#![allow(clippy::field_reassign_with_default)]

use apicon::*;
use apicon::error::ProxErr;
use clap::Parser;
use nix::unistd::{setgid, setuid};
use pingora_core::server::configuration::ServerConf;
use tracing::info;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let log_level = cli.log.first().map(|s| s.to_owned()).unwrap_or_else(|| "info".into());
    let log_file = cli.log.get(1).map(PathBuf::from);
    let _guard = init_tracing(&log_level, cli.json, log_file.as_deref());

    let cfg = load_config(&cli.config)?;

    let cert = cfg.cert.unwrap_or_else(|| cli.cert.to_owned());
    let key = cfg.key.unwrap_or_else(|| cli.key.to_owned());
    let ca_root = cfg.ca_root.or(cli.ca_root.clone());
    let client_ca = cfg.client_ca.or(cli.client_ca.clone());
    let require_client_cert = cfg.require_client_cert || cli.require_client_cert;
    let origins = if !cfg.allow_origin.is_empty() { cfg.allow_origin.clone() } else { cli.allow_origin.clone() };
    let listener = cfg
        .listener
        .unwrap_or_else(|| "[::]:443".to_owned());
    let endpoints = cfg.endpoint.clone();
    let lb_backends = if !cfg.lb_backends.is_empty() {
        cfg.lb_backends.clone()
    } else {
        vec![LBBackend { addr: "127.0.0.1:443".into(), sni: Some("localhost".into()) }]
    };

    if let Some(Commands::Service { start, restart, stop, status, names, workingdir }) = &cli.command {
        if *start { return systemctl_action("start", names).map_err(|e| Box::new(e) as Box<dyn std::error::Error>); }
        if *restart { return systemctl_action("restart", names).map_err(|e| Box::new(e) as Box<dyn std::error::Error>); }
        if *stop { return systemctl_action("stop", names).map_err(|e| Box::new(e) as Box<dyn std::error::Error>); }
        if *status { return systemctl_action("status", names).map_err(|e| Box::new(e) as Box<dyn std::error::Error>); }
        create_service(&cli, names, workingdir)?;
        return Ok(());
    }

    if let Some(Commands::Mtls { out }) = &cli.command {
        generate_mtls(out)?;
        return Ok(());
    }

    let mut pid_handle = match open_pid(&cli.pid) {
        Ok(f) => f,
        Err(e) => { eprintln!("pid-file: {e}"); std::process::exit(1); }
    };

    let mut sc = ServerConf::default();
    sc.daemon    = cli.daemon;
    sc.threads   = cli.threads;
    sc.pid_file  = cli.pid.display().to_string();
    sc.ca_file   = ca_root.as_ref().map(|p| p.display().to_string());
    sc.max_retries               = 10;
    sc.upstream_debug_ssl_keylog = true;

    let gw = Gateway::new(
        sc,
        &listener,
        &cert,
        &key,
        client_ca,
        require_client_cert,
        origins,
        endpoints,
        lb_backends,
    )?;

    if let Err(e) = write_pid(&mut pid_handle) {
        eprintln!("pid-file write: {e}");
    }

    if cli.user.is_some() || cli.group.is_some() {
        match resolve_ids(cli.user.as_ref(), cli.group.as_ref()).and_then(|(u, g)| {
            if let Some(gid) = g { setgid(gid).map_err(|e| ProxErr::Other(e.to_string()))?; }
            if let Some(uid) = u { setuid(uid).map_err(|e| ProxErr::Other(e.to_string()))?; }
            Ok(())
        }) {
            Ok(()) => info!(target="startup", "dropped to uid={:?} gid={:?}", cli.user, cli.group),
            Err(e) => eprintln!("priv-drop: {e}"),
        }
    }

    info!(target="startup", "Pingora bootstrapped");
    gw.run();
    #[allow(unreachable_code)]
    Ok(())
}
