mod cli;
mod connect;
mod diagnose;
mod disconnect;
mod hip;
mod launch_gui;

pub(crate) const GP_CLIENT_LOCK_FILE: &str = "/var/run/gpclient.lock";

#[tokio::main]
async fn main() {
  cli::run().await;
}
