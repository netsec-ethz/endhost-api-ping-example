use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use chrono::Utc;
use clap::Parser;
use scion_proto::{
    packet::{ByEndpoint, ScionPacketScmp},
    scmp::{ScmpEchoRequest, ScmpMessage},
};
use scion_stack::path::manager::traits::PathManager;
use scion_stack::scionstack::ScionStackBuilder;
use tracing::{debug, info};
use url::Url;

#[derive(Parser, Debug)]
#[clap(
    name = "scionping",
    about = "SCIONPings sender",
    arg_required_else_help = true
)]
struct Opt {
    /// Local address to bind to
    #[clap(long = "bind")]
    bind: Option<scion_proto::address::SocketAddr>,

    /// Address of the endhost API to connect to for scion path resolution.
    #[clap(long = "endhost-api")]
    endhost_api_address: Url,

    /// Path to the Snap token file for authentication with the endhost API
    #[clap(long = "snap-token", value_name = "FILE")]
    snap_token_path: Option<PathBuf>,

    /// Tracing level (trace, debug, info, warn, error)
    #[clap(long = "log", default_value = "info")]
    log_level: tracing::Level,
}

fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    let result = run_client(opt);
    if let Err(ref err) = result {
        tracing::error!(error = %err, "command failed");
    }
    result
}

#[tokio::main]
async fn run_client(opt: Opt) -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt()
        .with_max_level(opt.log_level)
        .try_init()
        .map_err(|err| anyhow!("failed to init tracing: {err}"))?;

    let mut builder = ScionStackBuilder::new(opt.endhost_api_address.clone());
    if let Some(token_path) = &opt.snap_token_path {
        let snap_token = fs::read_to_string(token_path)
            .with_context(|| format!("failed to read token file {:?}", token_path))?
            .trim()
            .to_string();
        if snap_token.is_empty() {
            anyhow::bail!("token file {:?} is empty", token_path);
        }
        builder = builder.with_auth_token(snap_token);
    }
    let client_network_stack = builder
        .build()
        .await
        .context("failed to build SCION network stack")?;

    let sender = client_network_stack
        .bind_raw(opt.bind)
        .await
        .context("failed to bind raw sender")?;
    let path_manager = client_network_stack.create_path_manager();

    let isd_as = "64-2:0:9c"
        .parse()
        .context("invalid destination ISD-AS literal: 64-2:0:9c")?;

    let path = path_manager
        .path_wait(sender.local_addr().isd_asn(), isd_as, Utc::now())
        .await
        .context("failed to resolve SCION path")?;


    info!("local address: {}", sender.local_addr());
    // A red block in x=53, y=20
    let addrs = [
        "64-2:0:9c,fd00::0034:0014:ffff:0000",
        "64-2:0:9c,fd00::0034:0015:ffff:0000",
        "64-2:0:9c,fd00::0035:0014:ffff:0000",
        "64-2:0:9c,fd00::0035:0015:ffff:0000",
    ];
    for x in addrs {
        let addr = match scion_proto::address::ScionAddr::from_str(x) {
            Ok(addr) => addr,
            Err(err) => {
                debug!("Invalid SCION address {x}: {err}");
                continue;
            }
        };

        let echo_request = match ScionPacketScmp::new(
            ByEndpoint {
                source: sender.local_addr().scion_address(),
                destination: addr,
            },
            path.data_plane_path.clone(),
            ScmpMessage::EchoRequest(ScmpEchoRequest::new(1234, 1, Bytes::from_static(b""))),
        ) {
            Ok(packet) => packet,
            Err(err) => {
                debug!("Failed to build SCMP packet for address {x}: {err}");
                continue;
            }
        };

        match sender.send(echo_request.into()).await {
            Ok(()) => {
                debug!("Sent ping to address {x}");
            }
            Err(err) => {
                debug!("Failed to send ping to address {x}: {err}");
            }
        }
    }
    Ok(())
}
