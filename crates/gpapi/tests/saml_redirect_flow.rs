use std::{
  collections::HashMap,
  net::SocketAddr,
  sync::{Arc, Mutex},
};

use anyhow::Context;
use axum::{
  Router,
  extract::{Form, State},
  response::IntoResponse,
  routing::post,
};
use gpapi::{
  credential::{AuthCookieCredential, Credential, PreloginCredential},
  gateway::{GatewayLogin, gateway_login},
  gp_params::GpParams,
  portal::{Prelogin, prelogin, retrieve_config},
};
use tokio::net::TcpListener;

const PRELOGIN_SAML_XML: &str = include_str!("files/prelogin_saml.xml");
const PORTAL_CONFIG_XML: &str = include_str!("files/portal_config.xml");
const GATEWAY_LOGIN_XML: &str = include_str!("files/gateway_login.xml");

#[derive(Clone, Default)]
struct MockState {
  requests: Arc<Mutex<Vec<(String, HashMap<String, String>)>>>,
}

impl MockState {
  fn push(&self, endpoint: &str, params: &HashMap<String, String>) {
    self
      .requests
      .lock()
      .expect("requests lock poisoned")
      .push((endpoint.to_string(), params.clone()));
  }

  fn requests_for(&self, endpoint: &str) -> Vec<HashMap<String, String>> {
    self
      .requests
      .lock()
      .expect("requests lock poisoned")
      .iter()
      .filter(|(name, _)| name == endpoint)
      .map(|(_, params)| params.clone())
      .collect()
  }
}

#[tokio::test]
async fn saml_redirect_flow_uses_expected_endpoints_and_cookies() -> anyhow::Result<()> {
  let state = MockState::default();
  let server_url = start_mock_server(state.clone()).await?;
  let gp_params = GpParams::builder().user_agent("gpapi-test/1.0").build();

  let prelogin_res = prelogin(&server_url, &gp_params).await?;
  let saml_prelogin = match prelogin_res {
    Prelogin::Saml(saml) => saml,
    Prelogin::Standard(_) => anyhow::bail!("expected SAML prelogin response"),
  };
  assert_eq!(saml_prelogin.region(), "CN");
  assert_eq!(saml_prelogin.saml_request(), "SAMLRequest=xxx");
  assert!(saml_prelogin.support_default_browser());

  let prelogin_cred = Credential::Prelogin(PreloginCredential::new("alice", Some("prelogin-cookie-value"), None));
  let portal_config = retrieve_config(&server_url, &prelogin_cred, &gp_params).await?;
  assert_eq!(portal_config.auth_cookie().username(), "alice");
  assert_eq!(portal_config.auth_cookie().user_auth_cookie(), "xxxxxx");
  assert_eq!(portal_config.auth_cookie().prelogon_user_auth_cookie(), "xxxxxx");

  let auth_cookie_cred = Credential::from(portal_config.auth_cookie());
  let gateway_login_res = gateway_login(&server_url, &auth_cookie_cred, &gp_params).await?;
  let cookie = match gateway_login_res {
    GatewayLogin::Cookie(cookie) => cookie,
    GatewayLogin::Mfa(_, _) => anyhow::bail!("expected gateway cookie, got MFA challenge"),
  };
  assert!(cookie.contains("authcookie=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert!(cookie.contains("portal=XXX-GP-Gateway-N"));
  assert!(cookie.contains("user=user"));
  assert!(cookie.contains("domain=corp.example.com"));

  let prelogin_calls = state.requests_for("prelogin");
  assert_eq!(prelogin_calls.len(), 1);
  assert_eq!(prelogin_calls[0].get("default-browser").map(String::as_str), Some("1"));
  assert_eq!(prelogin_calls[0].get("cas-support").map(String::as_str), Some("yes"));

  let getconfig_calls = state.requests_for("getconfig");
  assert_eq!(getconfig_calls.len(), 1);
  assert_eq!(getconfig_calls[0].get("user").map(String::as_str), Some("alice"));
  assert_eq!(
    getconfig_calls[0].get("prelogin-cookie").map(String::as_str),
    Some("prelogin-cookie-value")
  );

  let login_calls = state.requests_for("gateway-login");
  assert_eq!(login_calls.len(), 1);
  assert_eq!(
    login_calls[0].get("portal-userauthcookie").map(String::as_str),
    Some("xxxxxx")
  );
  assert_eq!(
    login_calls[0].get("portal-prelogonuserauthcookie").map(String::as_str),
    Some("xxxxxx")
  );

  Ok(())
}

#[tokio::test]
async fn getconfig_rejects_until_hip_cookie_state_is_present() -> anyhow::Result<()> {
  let server_url = start_hip_policy_server().await?;
  let gp_params = GpParams::builder().user_agent("gpapi-test/1.0").build();

  let no_hip_cookie = Credential::AuthCookie(AuthCookieCredential::new(
    "alice",
    "no-hip-cookie",
    "prelogon-cookie",
  ));
  let err = retrieve_config(&server_url, &no_hip_cookie, &gp_params)
    .await
    .expect_err("expected getconfig to fail when HIP policy is not satisfied");
  let err_text = err.to_string();
  assert!(err_text.contains("Portal config error"));
  assert!(err_text.contains("HIP_REQUIRED"));

  let hip_ok_cookie = Credential::AuthCookie(AuthCookieCredential::new(
    "alice",
    "hip-ok-cookie",
    "prelogon-cookie",
  ));
  let portal_config = retrieve_config(&server_url, &hip_ok_cookie, &gp_params).await?;
  assert_eq!(portal_config.auth_cookie().user_auth_cookie(), "xxxxxx");

  Ok(())
}

async fn start_mock_server(state: MockState) -> anyhow::Result<String> {
  let app = Router::new()
    .route("/global-protect/prelogin.esp", post(handle_prelogin))
    .route("/global-protect/getconfig.esp", post(handle_getconfig))
    .route("/ssl-vpn/login.esp", post(handle_gateway_login))
    .with_state(state);

  let listener = TcpListener::bind("127.0.0.1:0").await?;
  let addr: SocketAddr = listener.local_addr()?;
  tokio::spawn(async move {
    if let Err(err) = axum::serve(listener, app).await {
      eprintln!("mock gpapi server failed: {err}");
    }
  });

  Ok(format!("http://{}", addr))
}

async fn start_hip_policy_server() -> anyhow::Result<String> {
  let app = Router::new().route("/global-protect/getconfig.esp", post(handle_hip_policy_getconfig));

  let listener = TcpListener::bind("127.0.0.1:0").await?;
  let addr: SocketAddr = listener.local_addr()?;
  tokio::spawn(async move {
    if let Err(err) = axum::serve(listener, app).await {
      eprintln!("mock hip policy server failed: {err}");
    }
  });

  Ok(format!("http://{}", addr))
}

async fn handle_prelogin(
  State(state): State<MockState>,
  Form(params): Form<HashMap<String, String>>,
) -> impl IntoResponse {
  state.push("prelogin", &params);
  PRELOGIN_SAML_XML
}

async fn handle_getconfig(
  State(state): State<MockState>,
  Form(params): Form<HashMap<String, String>>,
) -> impl IntoResponse {
  state.push("getconfig", &params);
  PORTAL_CONFIG_XML
}

async fn handle_gateway_login(
  State(state): State<MockState>,
  Form(params): Form<HashMap<String, String>>,
) -> impl IntoResponse {
  state.push("gateway-login", &params);
  GATEWAY_LOGIN_XML
}

async fn handle_hip_policy_getconfig(Form(params): Form<HashMap<String, String>>) -> impl IntoResponse {
  let cookie = params.get("portal-userauthcookie").map(String::as_str).unwrap_or_default();

  if cookie != "hip-ok-cookie" {
    return (
      axum::http::StatusCode::FORBIDDEN,
      [("x-private-pan-globalprotect", "HIP_REQUIRED")],
      "HIP report is required by policy",
    )
      .into_response();
  }

  (
    axum::http::StatusCode::OK,
    [("content-type", "application/xml")],
    PORTAL_CONFIG_XML,
  )
    .into_response()
}

#[test]
fn fixtures_are_present() {
  assert!(!PRELOGIN_SAML_XML.trim().is_empty());
  assert!(!PORTAL_CONFIG_XML.trim().is_empty());
  assert!(!GATEWAY_LOGIN_XML.trim().is_empty());

  assert!(
    std::str::from_utf8(PRELOGIN_SAML_XML.as_bytes())
      .context("invalid utf-8 in prelogin fixture")
      .is_ok()
  );
  assert!(
    std::str::from_utf8(PORTAL_CONFIG_XML.as_bytes())
      .context("invalid utf-8 in portal fixture")
      .is_ok()
  );
  assert!(
    std::str::from_utf8(GATEWAY_LOGIN_XML.as_bytes())
      .context("invalid utf-8 in gateway fixture")
      .is_ok()
  );
}
