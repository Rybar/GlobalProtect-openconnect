use crate::Vpn;
use log::{debug, info, trace, warn};
use std::borrow::Cow;
use std::ffi::{c_char, c_int, c_void};

/// ConnectOptions struct for FFI, the field names and order must match the C definition.
#[repr(C)]
#[derive(Debug)]
pub(crate) struct ConnectOptions {
  pub user_data: *mut c_void,

  pub server: *const c_char,
  pub cookie: *const c_char,

  pub user_agent: *const c_char,
  pub os: *const c_char,
  pub os_version: *const c_char,
  pub client_version: *const c_char,

  pub script: *const c_char,
  pub interface: *const c_char,
  pub script_tun: u32,

  pub certificate: *const c_char,
  pub sslkey: *const c_char,
  pub key_password: *const c_char,
  pub servercert: *const c_char,

  pub csd_uid: u32,
  pub csd_wrapper: *const c_char,

  pub reconnect_timeout: u32,
  pub mtu: u32,
  pub disable_ipv6: u32,
  pub no_dtls: u32,

  pub dpd_interval: u32,
}

#[link(name = "vpn")]
unsafe extern "C" {
  #[link_name = "vpn_connect"]
  fn vpn_connect(options: *const ConnectOptions, callback: extern "C" fn(i32, *mut c_void)) -> c_int;

  #[link_name = "vpn_disconnect"]
  fn vpn_disconnect();
}

pub(crate) fn connect(options: &ConnectOptions) -> i32 {
  unsafe { vpn_connect(options, on_vpn_connected) }
}

pub(crate) fn disconnect() {
  unsafe { vpn_disconnect() }
}

#[unsafe(no_mangle)]
extern "C" fn on_vpn_connected(pipe_fd: i32, vpn: *mut c_void) {
  let vpn = unsafe { &*(vpn as *const Vpn) };
  vpn.on_connected(pipe_fd);
}

// Logger used in the C code.
// level: 0 = error, 1 = info, 2 = debug, 3 = trace
// map the error level log in openconnect to the warning level
#[unsafe(no_mangle)]
extern "C" fn vpn_log(level: i32, message: *const c_char) {
  let message = unsafe { std::ffi::CStr::from_ptr(message) };
  let message = message.to_str().unwrap_or("Invalid log message");
  // Strip the trailing newline
  let message = redact_pkcs11_pin(message.trim_end_matches('\n'));

  if level == 0 {
    warn!("{}", message);
  } else if level == 1 {
    info!("{}", message);
  } else if level == 2 {
    debug!("{}", message);
  } else if level == 3 {
    trace!("{}", message);
  } else {
    warn!(
      "Unknown log level: {}, enable DEBUG log level to see more details",
      level
    );
    debug!("{}", message);
  }
}

fn redact_pkcs11_pin(message: &str) -> Cow<'_, str> {
  let marker = "pin-value=";
  let Some(start) = message.find(marker) else {
    return Cow::Borrowed(message);
  };

  let value_start = start + marker.len();
  let tail = &message[value_start..];
  let value_end_rel = tail
    .find(|ch: char| ch == '&' || ch == ';' || ch == ' ' || ch == '\'' || ch == '"' || ch == ')')
    .unwrap_or(tail.len());

  let value_end = value_start + value_end_rel;
  let mut redacted = String::with_capacity(message.len());
  redacted.push_str(&message[..value_start]);
  redacted.push_str("<redacted>");
  redacted.push_str(&message[value_end..]);
  Cow::Owned(redacted)
}
