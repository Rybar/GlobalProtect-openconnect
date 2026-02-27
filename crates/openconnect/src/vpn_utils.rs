use std::{env, io, path::Path};

use is_executable::IsExecutable;

const VPNC_SCRIPT_LOCATIONS: &[&str] = &[
  "/usr/local/share/vpnc-scripts/vpnc-script",
  "/usr/local/sbin/vpnc-script",
  "/usr/share/vpnc-scripts/vpnc-script",
  "/usr/sbin/vpnc-script",
  "/etc/vpnc/vpnc-script",
  "/etc/openconnect/vpnc-script",
  "/usr/libexec/vpnc-scripts/vpnc-script",
  #[cfg(target_os = "macos")]
  "/opt/homebrew/etc/vpnc/vpnc-script",
];

const CSD_WRAPPER_LOCATIONS: &[&str] = &[
  "/usr/libexec/gpclient/hipreport.sh",
  #[cfg(target_arch = "x86_64")]
  "/usr/lib/x86_64-linux-gnu/openconnect/hipreport.sh",
  #[cfg(target_arch = "aarch64")]
  "/usr/lib/aarch64-linux-gnu/openconnect/hipreport.sh",
  "/usr/lib/openconnect/hipreport.sh",
  "/usr/libexec/openconnect/hipreport.sh",
  #[cfg(target_os = "macos")]
  "/opt/homebrew/opt/openconnect/libexec/openconnect/hipreport.sh",
];

fn find_executable(locations: &[&'static str]) -> Option<&'static str> {
  for location in locations.iter() {
    let path = Path::new(location);
    if path.is_executable() {
      return Some(*location);
    }
  }

  None
}

pub fn find_vpnc_script() -> Option<&'static str> {
  find_executable(&VPNC_SCRIPT_LOCATIONS)
}

fn is_executable_file(path: &str) -> bool {
  Path::new(path).is_executable()
}

fn resolve_csd_wrapper(override_path: Option<&str>, locations: &[&str]) -> Option<String> {
  if let Some(path) = override_path.filter(|p| !p.is_empty()) {
    if is_executable_file(path) {
      return Some(path.to_string());
    }
  }

  locations
    .iter()
    .find(|path| is_executable_file(path))
    .map(|path| (*path).to_string())
}

pub fn find_csd_wrapper() -> Option<String> {
  let override_path = env::var("GPCLIENT_HIP_WRAPPER").ok();
  resolve_csd_wrapper(override_path.as_deref(), CSD_WRAPPER_LOCATIONS)
}

/// If file exists, check if it is executable
pub fn check_executable(file: &str) -> Result<(), io::Error> {
  let path = Path::new(file);

  if path.exists() && !path.is_executable() {
    return Err(io::Error::new(
      io::ErrorKind::PermissionDenied,
      format!("{} is not executable", file),
    ));
  }

  Ok(())
}

#[cfg(test)]
mod tests {
  use std::{
    fs::{self, OpenOptions},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
  };

  use super::*;

  fn create_executable(path: &Path) {
    OpenOptions::new()
      .create(true)
      .write(true)
      .truncate(true)
      .open(path)
      .unwrap();
    let mut perms = fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).unwrap();
  }

  fn create_non_executable(path: &Path) {
    OpenOptions::new()
      .create(true)
      .write(true)
      .truncate(true)
      .open(path)
      .unwrap();
    let mut perms = fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o644);
    fs::set_permissions(path, perms).unwrap();
  }

  fn unique_path(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nanos}-{}", std::process::id()))
  }

  #[test]
  fn resolve_csd_wrapper_prefers_override_when_executable() {
    let override_path = unique_path("hip-override");
    let fallback_path = unique_path("hip-fallback");
    create_executable(&override_path);
    create_executable(&fallback_path);

    let resolved = resolve_csd_wrapper(override_path.to_str(), &[fallback_path.to_str().unwrap()]);
    assert_eq!(resolved.as_deref(), override_path.to_str());

    let _ = fs::remove_file(override_path);
    let _ = fs::remove_file(fallback_path);
  }

  #[test]
  fn resolve_csd_wrapper_uses_fallback_when_override_not_executable() {
    let override_path = unique_path("hip-override-noexec");
    let fallback_path = unique_path("hip-fallback-exec");
    create_non_executable(&override_path);
    create_executable(&fallback_path);

    let resolved = resolve_csd_wrapper(override_path.to_str(), &[fallback_path.to_str().unwrap()]);
    assert_eq!(resolved.as_deref(), fallback_path.to_str());

    let _ = fs::remove_file(override_path);
    let _ = fs::remove_file(fallback_path);
  }

  #[test]
  fn check_executable_rejects_non_executable_file() {
    let file = unique_path("hip-not-exec");
    create_non_executable(&file);

    let err = check_executable(file.to_str().unwrap()).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

    let _ = fs::remove_file(file);
  }
}
