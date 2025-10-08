use std::{
    collections::HashMap,
    env::current_exe,
    net::{SocketAddr, UdpSocket},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    str::FromStr,
    sync::Arc,
};

use anyhow::{Context, anyhow};
use clap::{Parser, Subcommand};
use hickory_server::{
    authority::{Catalog, ZoneType},
    proto::rr::{
        LowerName, Name, RData, Record,
        rdata::{SOA, TXT},
    },
    store::in_memory::InMemoryAuthority,
};
use nix::{
    sys::signal::Signal,
    unistd::{ForkResult, Pid, fork},
};
use serde::Deserialize;
use syslog_tracing::{Facility, Options, Syslog};
use tokio::{
    sync::mpsc::{Receiver, channel},
    try_join,
};
use tracing_subscriber::filter::LevelFilter;

#[derive(Subcommand)]
enum DaemonArguments {
    /// Used internally, NEVER set manually
    // Dont touch field layout, see below
    #[command(name = "_daemon")]
    Daemon {
        txt_secret: String,
        mapped_domain: String,
        soa: String,
        socket_fd: i32,
    },
}

/// Manual Pre/Post hook for the dns challenge with certbot.
#[derive(clap::Parser)]
struct Arguments {
    #[command(subcommand)]
    daemon: Option<DaemonArguments>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Arguments = Arguments::parse();

    // Write to syslog as logs and never have stdout
    let syslog = Syslog::new(c"certbot-dns01-hook", Options::LOG_PID, Facility::Daemon).unwrap();
    tracing_subscriber::fmt()
        .compact()
        .with_ansi(false)
        .with_max_level(LevelFilter::DEBUG)
        .with_writer(syslog)
        .init();
    std::panic::set_hook(Box::new(tracing_panic::panic_hook));

    let cerbot_parameters = detect_certbot_environment().unwrap();

    if let Some(DaemonArguments::Daemon {
        txt_secret,
        socket_fd,
        mapped_domain,
        soa,
    }) = args.daemon
    {
        // SAFETY Cannot really guarantee how this executable is called but we left a
        // warning to not invoke this application with this argument
        unsafe { daemon_logic(txt_secret, socket_fd, mapped_domain, soa).await }.unwrap();
    } else if let Some(the_pid) = cerbot_parameters.pre_hook_daemon_id {
        assert!(the_pid > 0); // lets not kill the system
        sigint_process(Pid::from_raw(the_pid)).expect("Cannot signal daemon to stop")
    } else {
        let config = read_hook_options(
            PathBuf::from_str("/etc/letsencrypt/acme-map.toml")
                .unwrap()
                .as_path(),
        )
        .expect("cannot read hook options");
        let daemon = dispatch_daemon(cerbot_parameters, config).expect("failed to setup daemon");
        println!("{}", daemon.as_raw())
    }
}

/// Configuration how the CNAME referencing is set up
#[derive(Deserialize)]
struct HookConfig {
    /// The main domain, entry served of SOA type
    /// typically 'acme.mydomain.org'
    soa: String,
    /// Domain mapping, from challenged domain to CNAME-referenced domain.
    /// typically 'mysubdomain.mydomain.org' -> 'mysubdomain.acme.mydomain.org'
    /// then there is a CNAME entry for '_acme_challenge.mysubdomain.mydomain.org'
    /// referencing 'mysubdomain.acme.mydomain.org'
    domains: HashMap<String, String>,
}

struct CertbotParameters {
    /// Only set when run as post hook
    pre_hook_daemon_id: Option<i32>,
    domain_to_be_validated: String,
    dns01_txt_validation_secret: String,
}

fn detect_certbot_environment() -> anyhow::Result<CertbotParameters> {
    Ok(CertbotParameters {
        pre_hook_daemon_id: std::env::var("CERTBOT_AUTH_OUTPUT")
            .ok()
            .map(|process_output| process_output.parse())
            .transpose()
            .context("Invalid prehook output")?,
        domain_to_be_validated: std::env::var("CERTBOT_DOMAIN")?,
        dns01_txt_validation_secret: std::env::var("CERTBOT_VALIDATION")?,
    })
}

fn sigint_process(process_to_be_signaled: Pid) -> anyhow::Result<()> {
    tracing::info!("Sending shutdowm to pid {process_to_be_signaled}");
    nix::sys::signal::kill(process_to_be_signaled, Signal::SIGINT).map_err(Into::into)
}

fn read_hook_options(hook_options: &Path) -> anyhow::Result<HookConfig> {
    let config = std::fs::read_to_string(hook_options)
        .with_context(|| format!("cannot read parameters from {hook_options:?}"))?;
    let toml: HookConfig = toml::from_str(&config)
        .with_context(|| format!("cannot parse config from {hook_options:?}"))?;

    return Ok(toml);
}

fn dispatch_daemon(
    CertbotParameters {
        domain_to_be_validated,
        dns01_txt_validation_secret,
        ..
    }: CertbotParameters,
    toml: HookConfig,
) -> anyhow::Result<Pid> {
    let cname_referenced_domain = toml
        .domains
        .get(&domain_to_be_validated)
        .with_context(|| format!("Domain '{domain_to_be_validated}' not mapped"))?;
    let dns_socket = UdpSocket::bind(SocketAddr::from_str("0.0.0.0:53").unwrap())
        .context("Can not bind socket")?;

    let no_close_on_exec_fd = nix::unistd::dup(dns_socket)
        .context("failed to duplicate socket fd with no CLOEXEC flag")?;
    tracing::info!(
        "Playing challenge for '{domain_to_be_validated}', record name is '{cname_referenced_domain}', secret '{dns01_txt_validation_secret}'"
    );
    let mut daemon_command = Command::new(
        current_exe()
            .context("cannot detect path to this executable")?
            .to_str()
            .context("Incompatible path to executable")?,
    );

    // TODO how do we keep this in sync for when the layout changes? maybe json serialize argumemts
    daemon_command
        .arg("_daemon")
        .arg(dns01_txt_validation_secret)
        .arg(cname_referenced_domain)
        .arg(toml.soa)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .arg(&format!("{}", no_close_on_exec_fd.as_raw_fd()));

    // SAFETY well, we do our best and only call exec directly after fork
    // but Command::exec should not be used for that according to a note _within_
    // its function body
    // We rather pray for no problem here and keep the implementation simple
    match unsafe { fork() }.unwrap() {
        ForkResult::Child => {
            panic!("{:?}", daemon_command.exec());
        }
        ForkResult::Parent { child } => Ok(child),
    }
}

/// Executes the daemon logic in this thread. The process can be
/// stopped with a SIGINT signal.
///
/// SAFETY The socket fd must be not owned or used by another thread
/// See from_rw_fd
async unsafe fn daemon_logic(
    txt_secret: String,
    socket_fd: i32,
    mapped_domain: String,
    soa: String,
) -> anyhow::Result<()> {
    nix::unistd::setsid().expect("Cannot detach process");
    let (send_to_cancel, receiver) = channel(1);
    ctrlc::set_handler(move || {
        send_to_cancel
            .blocking_send(())
            .expect("Daemon appears to have exited/crashed");
    })
    .context("Cannot setup SIGINT handler to make the daemon canceable in a graceful manner")?;

    // SAFETY delegated to caller
    let socket = unsafe { UdpSocket::from_raw_fd(socket_fd) };
    tracing::info!("Hosting server, soa={soa}, record={mapped_domain}, secret={txt_secret:.4}...");

    run_simple_dns(&soa, &mapped_domain, &txt_secret, socket, receiver)
        .await
        .context("dns logic failed")
}

async fn run_simple_dns(
    cname_referenced_domain: &str,
    fqdn_subdomain: &str,
    dns01_txt_validation_secret: &str,
    dns_socket: UdpSocket,
    mut terminate: Receiver<()>,
) -> anyhow::Result<()> {
    let name = Name::from_utf8(cname_referenced_domain)?;
    let subname = Name::from_utf8(fqdn_subdomain)?;
    let mut catalog = Catalog::new();
    let mut authority = InMemoryAuthority::empty(name.clone(), ZoneType::Primary, false);
    const DEFAULT_TTL: u32 = 60;

    // are the timing options correct here? I dont know
    authority.upsert_mut(
        Record::from_rdata(
            name.clone(),
            DEFAULT_TTL,
            RData::SOA(SOA::new(
                name.clone(),
                name.clone(),
                0,
                1,
                1,
                120,
                DEFAULT_TTL,
            )),
        ),
        0,
    );
    authority.upsert_mut(
        Record::from_rdata(
            subname,
            DEFAULT_TTL,
            RData::TXT(TXT::new(vec![dns01_txt_validation_secret.into()])),
        ),
        0,
    );
    catalog.upsert(LowerName::new(&name), vec![Arc::new(authority)]);
    let mut server = hickory_server::ServerFuture::new(catalog);
    server.register_socket_std(dns_socket)?;
    let cancellation = server.shutdown_token().clone();
    try_join!(
        async {
            server
                .block_until_done()
                .await
                .context("Failed to properly execute the dns server")?;
            Ok(()) as anyhow::Result<()>
        },
        async {
            terminate
                .recv()
                .await
                .ok_or(anyhow!("Ctrl+C handler set up correctly"))?;
            cancellation.cancel();
            tracing::info!("DNS server logic stopped");
            Ok(()) as anyhow::Result<()>
        }
    )?;
    Ok(())
}
