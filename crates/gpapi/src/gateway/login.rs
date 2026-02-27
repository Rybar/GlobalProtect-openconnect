use std::borrow::Cow;

use anyhow::bail;
use log::{debug, info, warn};
use reqwest::Client;
use urlencoding::{decode, encode};
use xmltree::Element;

use crate::{
  credential::Credential,
  error::PortalError,
  gp_params::GpParams,
  utils::{normalize_server, parse_gp_response, remove_url_scheme, xml::ElementExt},
};

pub enum GatewayLogin {
  Cookie(String),
  Mfa(String, String),
}

pub async fn gateway_login(gateway: &str, cred: &Credential, gp_params: &GpParams) -> anyhow::Result<GatewayLogin> {
  let url = normalize_server(gateway)?;
  let gateway = remove_url_scheme(&url);

  let login_url = format!("{}/ssl-vpn/login.esp", url);
  let client = Client::try_from(gp_params)?;

  let mut params = cred.to_params();
  let extra_params = gp_params.to_params();

  params.extend(extra_params);
  params.insert("server", &gateway);

  info!("Perform gateway login, user_agent: {}", gp_params.user_agent());

  let res = client.post(&login_url).form(&params).send().await.map_err(|e| {
    warn!("Network error: {:?}", e);
    anyhow::anyhow!(PortalError::NetworkError(e))
  })?;

  let res = parse_gp_response(res).await.map_err(|err| {
    warn!("{err}");
    anyhow::anyhow!("Gateway login error: {}", err.reason)
  })?;

  // MFA detected
  if res.contains("Challenge") {
    let Some((message, input_str)) = parse_mfa(&res) else {
      bail!("Failed to parse MFA challenge: {res}");
    };

    return Ok(GatewayLogin::Mfa(message, input_str));
  }

  debug!("Gateway login response: {}", res);

  let root = Element::parse(res.as_bytes())?;

  let cookie = build_gateway_token(&root, gp_params.computer())?;

  Ok(GatewayLogin::Cookie(cookie))
}

fn build_gateway_token(element: &Element, computer: &str) -> anyhow::Result<String> {
  let args = element
    .descendants("argument")
    .iter()
    .map(|e| e.get_text().unwrap_or_default())
    .collect::<Vec<_>>();

  let mut params = vec![
    read_args(&args, 1, "authcookie")?,
    read_args(&args, 3, "portal")?,
    read_args(&args, 4, "user")?,
    read_args(&args, 7, "domain")?,
    read_args(&args, 15, "preferred-ip")?,
    ("computer", computer),
  ];

  if let Some(persistent_cookie) = read_optional_arg(&args, 2) {
    params.push(("persistent-cookie", persistent_cookie));
  }

  if let Some(portal_userauthcookie) = read_optional_arg(&args, 16) {
    params.push(("portal-userauthcookie", portal_userauthcookie));
  }

  if let Some(portal_prelogonuserauthcookie) = read_optional_arg(&args, 17) {
    params.push(("portal-prelogonuserauthcookie", portal_prelogonuserauthcookie));
  }

  let token = params
    .iter()
    .map(|(k, v)| {
      let value = normalize_token_value(v);
      format!("{}={}", k, encode(value.as_ref()))
    })
    .collect::<Vec<_>>()
    .join("&");

  Ok(token)
}

fn read_optional_arg<'a>(args: &'a [Cow<'_, str>], index: usize) -> Option<&'a str> {
  let value = args.get(index)?.as_ref();
  if value.is_empty() || value == "(null)" || value == "-1" || value == "empty" {
    None
  } else {
    Some(value)
  }
}

fn normalize_token_value<'a>(value: &'a str) -> Cow<'a, str> {
  if value.contains('%') {
    return decode(value).unwrap_or_else(|_| Cow::Borrowed(value));
  }

  Cow::Borrowed(value)
}

fn read_args<'a>(args: &'a [Cow<'_, str>], index: usize, key: &'a str) -> anyhow::Result<(&'a str, &'a str)> {
  args
    .get(index)
    .ok_or_else(|| anyhow::anyhow!("Failed to read {key} from args"))
    .map(|s| (key, s.as_ref()))
}

fn parse_mfa(res: &str) -> Option<(String, String)> {
  let message = res
    .lines()
    .find(|l| l.contains("respMsg"))
    .and_then(|l| l.split('"').nth(1).map(|s| s.to_string()))?;

  let input_str = res
    .lines()
    .find(|l| l.contains("inputStr"))
    .and_then(|l| l.split('"').nth(1).map(|s| s.to_string()))?;

  Some((message, input_str))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn mfa() {
    let res = r#"var respStatus = "Challenge";
var respMsg = "MFA message";
thisForm.inputStr.value = "5ef64e83000119ed";"#;

    let (message, input_str) = parse_mfa(res).unwrap();
    assert_eq!(message, "MFA message");
    assert_eq!(input_str, "5ef64e83000119ed");
  }

  #[test]
  fn normalize_token_value_handles_percent_encoded_domain() {
    let value = normalize_token_value("%28empty_domain%29");
    assert_eq!(value, "(empty_domain)");
  }

  #[test]
  fn gateway_token_avoids_double_encoding_for_encoded_domain() {
    let res = r#"<?xml version="1.0" encoding="utf-8"?>
<jnlp>
    <application-desc>
        <argument>(null)</argument>
        <argument>cookie-value</argument>
        <argument>x</argument>
        <argument>GP-Gateway-N</argument>
        <argument>user@example.com</argument>
        <argument>x</argument>
        <argument>x</argument>
        <argument>%28empty_domain%29</argument>
        <argument>x</argument>
        <argument>x</argument>
        <argument>x</argument>
        <argument>x</argument>
        <argument>x</argument>
        <argument>x</argument>
        <argument>x</argument>
        <argument>198.51.100.12</argument>
    </application-desc>
</jnlp>"#;

    let root = Element::parse(res.as_bytes()).unwrap();
    let token = build_gateway_token(&root, "test-host").unwrap();
    assert!(token.contains("domain=%28empty_domain%29"));
    assert!(!token.contains("domain=%2528empty_domain%2529"));
  }

  #[test]
  fn gateway_token_includes_optional_portal_cookie_fields() {
    let res = r#"<?xml version="1.0" encoding="utf-8"?>
<jnlp>
    <application-desc>
        <argument>(null)</argument>
        <argument>cookie-value</argument>
        <argument>persistent-cookie-value</argument>
        <argument>GP-Gateway-N</argument>
        <argument>user@example.com</argument>
        <argument>x</argument>
        <argument>x</argument>
        <argument>%28empty_domain%29</argument>
        <argument>x</argument>
        <argument>x</argument>
        <argument>x</argument>
        <argument>x</argument>
        <argument>x</argument>
        <argument>x</argument>
        <argument>x</argument>
        <argument>198.51.100.12</argument>
        <argument>portal-user-cookie-value</argument>
        <argument>portal-prelogon-cookie-value</argument>
    </application-desc>
</jnlp>"#;

    let root = Element::parse(res.as_bytes()).unwrap();
    let token = build_gateway_token(&root, "test-host").unwrap();
    assert!(token.contains("persistent-cookie=persistent-cookie-value"));
    assert!(token.contains("portal-userauthcookie=portal-user-cookie-value"));
    assert!(token.contains("portal-prelogonuserauthcookie=portal-prelogon-cookie-value"));
  }
}
