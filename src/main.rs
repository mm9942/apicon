#![allow(clippy::field_reassign_with_default)]

use apicon::{error::ProxErr, reload, *};
use clap::Parser;
use nix::unistd::{setgid, setuid};
use pingora_core::server::configuration::ServerConf;
use std::path::PathBuf;
use tracing::info;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let log_level = match cli.log.first() {
        Some(s) => s.to_owned(),
        None => "info".into(),
    };
    let log_file = cli.log.get(1).map(PathBuf::from);
    let cfg = load_config(&cli.config)?;
    let _guard = init_tracing(&log_level, cli.json, log_file.as_deref());

    let cert = match cfg.cert {
        Some(p) => p,
        None => cli.cert.to_owned(),
    };
    let key = match cfg.key {
        Some(p) => p,
        None => cli.key.to_owned(),
    };
    let ca_root = cfg
        .ca_root
        .or_else(|| cli.ca_root.as_ref().map(PathBuf::to_owned));
    let client_ca = cfg
        .client_ca
        .or_else(|| cli.client_ca.as_ref().map(PathBuf::to_owned));
    let require_client_cert = cfg.require_client_cert || cli.require_client_cert;
    let origins = if !cfg.allow_origin.is_empty() {
        cfg.allow_origin.to_vec()
    } else {
        cli.allow_origin.to_vec()
    };
    let listener = match cfg.listener {
        Some(l) => l,
        None => "[::]:443".to_owned(),
    };
    let endpoints = cfg.endpoint.to_vec();
    let lb_backends = if !cfg.lb_backends.is_empty() {
        cfg.lb_backends.to_vec()
    } else {
        vec![LBBackend {
            addr: "127.0.0.1:443".into(),
            tls: true,
            sni: Some("localhost".into()),
        }]
    };
    let queue_cap = cfg.queue_cap.unwrap_or(cli.queue_cap);
    let preconnect = cfg.preconnect.unwrap_or(cli.preconnect);
    let session_ticket = cfg.session_ticket && !cli.no_session_tickets;
    let ocsp_stapling = cfg.ocsp_stapling && !cli.no_ocsp;
    let ticket_rotate = cfg.ticket_rotate.unwrap_or(cli.ticket_rotate);
    let default_header_timeout_ms = cfg.default_header_timeout_ms;
    let default_body_timeout_ms = cfg.default_body_timeout_ms;
    let base_prefix = cfg.base_prefix.clone();
    let prepend_base_prefix = cfg.prepend_base_prefix;

    if let Some(Commands::Service {
        start,
        restart,
        stop,
        status,
        names,
        workingdir,
    }) = &cli.command
    {
        if *start {
            return systemctl_action("start", names)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>);
        }
        if *restart {
            return systemctl_action("restart", names)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>);
        }
        if *stop {
            return systemctl_action("stop", names)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>);
        }
        if *status {
            return systemctl_action("status", names)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>);
        }
        create_service(&cli, names, workingdir)?;
        return Ok(());
    }

    if let Some(Commands::Mtls { out }) = &cli.command {
        generate_mtls(out)?;
        return Ok(());
    }

    let mut pid_handle = match open_pid(&cli.pid) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("pid-file: {e}");
            std::process::exit(1);
        }
    };

    let mut sc = ServerConf::default();
    sc.daemon = cli.daemon;
    sc.threads = cli.threads;
    sc.pid_file = cli.pid.display().to_string();
    sc.ca_file = ca_root.as_ref().map(|p| p.display().to_string());
    sc.max_retries = 10;
    sc.client_bind_to_ipv4 = cfg.client_bind_to_ipv4.clone();
    sc.client_bind_to_ipv6 = cfg.client_bind_to_ipv6.clone();
    configure_keylog(&mut sc);

    let gw = Gateway::new(
        sc,
        &listener,
        &cert,
        &key,
        client_ca,
        require_client_cert,
        origins,
        endpoints,
        base_prefix,
        prepend_base_prefix,
        lb_backends,
        queue_cap,
        preconnect,
        default_header_timeout_ms,
        default_body_timeout_ms,
        session_ticket,
        ticket_rotate,
        ocsp_stapling,
    )?;
    let metrics_cfg = cfg.metrics;
    reload::load_state();
    reload::setup_reload_handler(
        gw.queue_handle(),
        gw.hash_handle(),
        cli.config
            .as_ref()
            .map(PathBuf::to_owned)
            .unwrap_or_default(),
    );

    if let Err(e) = write_pid(&mut pid_handle) {
        eprintln!("pid-file write: {e}");
    }

    if cli.user.is_some() || cli.group.is_some() {
        match resolve_ids(cli.user.as_ref(), cli.group.as_ref()).and_then(|(u, g)| {
            if let Some(gid) = g {
                setgid(gid).map_err(|e| ProxErr::Other(e.to_string()))?;
            }
            if let Some(uid) = u {
                setuid(uid).map_err(|e| ProxErr::Other(e.to_string()))?;
            }
            Ok(())
        }) {
            Ok(()) => info!(
                target = "startup",
                "dropped to uid={:?} gid={:?}", cli.user, cli.group
            ),
            Err(e) => eprintln!("priv-drop: {e}"),
        }
    }

    if let Some(m) = metrics_cfg {
        if let Ok(addr) = m.addr.parse::<std::net::SocketAddr>() {
            let path = m.path;
            std::thread::spawn(move || {
                if let Ok(rt) = tokio::runtime::Runtime::new() {
                    let _ = rt.block_on(serve_metrics(addr, path));
                }
            });
        }
    }

    info!(target = "startup", "Pingora bootstrapped");
    gw.run();
    #[allow(unreachable_code)]
    Ok(())
}
