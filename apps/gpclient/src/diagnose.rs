use clap::Args;
use gpapi::utils::{host_utils, request::is_pkcs11_uri};
use openconnect::{find_csd_wrapper, find_vpnc_script};
use std::process::Command;

#[derive(Args)]
pub(crate) struct DiagnoseArgs {
  #[arg(long, help = "Optional certificate input to classify (file path or PKCS#11 URI)")]
  certificate: Option<String>,
}

pub(crate) struct DiagnoseHandler<'a> {
  args: &'a DiagnoseArgs,
}

impl<'a> DiagnoseHandler<'a> {
  pub(crate) fn new(args: &'a DiagnoseArgs) -> Self {
    Self { args }
  }

  pub(crate) async fn handle(&self) -> anyhow::Result<()> {
    println!("== gpclient diagnose ==");
    println!("host.os_version={}", host_utils::get_linux_os_string());
    println!("host.device={}", whoami::devicename());

    match self.args.certificate.as_deref() {
      Some(cert) if is_pkcs11_uri(cert) => println!("certificate.mode=pkcs11-uri"),
      Some(cert) => {
        let exists = std::path::Path::new(cert).exists();
        println!("certificate.mode=file-path");
        println!("certificate.path={cert}");
        println!("certificate.exists={exists}");
      }
      None => println!("certificate.mode=not-specified"),
    }

    println!("runtime.vpnc_script={}", find_vpnc_script().unwrap_or("<not-found>"));
    println!(
      "runtime.hip_wrapper={}",
      find_csd_wrapper().unwrap_or_else(|| "<not-found>".to_string())
    );

    match detect_openconnect_version() {
      Some(version) => println!("runtime.openconnect={version}"),
      None => println!("runtime.openconnect=<not-detected>"),
    }

    Ok(())
  }
}

fn detect_openconnect_version() -> Option<String> {
  let output = Command::new("openconnect").arg("--version").output().ok()?;
  if !output.status.success() {
    return None;
  }

  let stdout = String::from_utf8(output.stdout).ok()?;
  stdout.lines().next().map(|line| line.to_string())
}
