#![allow(clippy::field_reassign_with_default)]

use apicon::error::ProxErr;
use apicon::webserver::WebServer;
use apicon::*;
use clap::Parser;
use nix::unistd::{setgid, setuid};
use pingora_core::server::configuration::ServerConf;
use std::path::PathBuf;
use tracing::info;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let log_level = cli
        .log
        .first()
        .map(|s| s.to_owned())
        .unwrap_or_else(|| "info".into());
    let log_file = cli.log.get(1).map(PathBuf::from);
    let _guard = init_tracing(&log_level, cli.json, log_file.as_deref());

    let cfg = load_config(&cli.config)?;

    let gateways_cfg = if cfg.gateways.is_empty() {
        vec![GatewayConfig {
            listener: cfg.listener.clone(),
            cert: cfg.cert.clone(),
            key: cfg.key.clone(),
            ca_root: cfg.ca_root.clone(),
            client_ca: cfg.client_ca.clone(),
            require_client_cert: cfg.require_client_cert,
            allow_origin: cfg.allow_origin.clone(),
            lb_backends: cfg.lb_backends.clone(),
            endpoint: cfg.endpoint.clone(),
            round_robin: cfg.round_robin,
            client_bind_to_ipv4: cfg.client_bind_to_ipv4.clone(),
            client_bind_to_ipv6: cfg.client_bind_to_ipv6.clone(),
            web: cfg.web.clone(),
        }]
    } else {
        cfg.gateways.clone()
    };

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

    let mut gateways = Vec::new();
    let mut webs = Vec::new();
    for g in gateways_cfg {
        let cert = g.cert.clone().unwrap_or_else(|| cli.cert.to_owned());
        let key = g.key.clone().unwrap_or_else(|| cli.key.to_owned());
        let ca_root = g.ca_root.clone().or(cli.ca_root.clone());
        let client_ca = g.client_ca.clone().or(cli.client_ca.clone());
        let require_client_cert = g.require_client_cert || cli.require_client_cert;
        let origins = if !g.allow_origin.is_empty() {
            g.allow_origin.clone()
        } else {
            cli.allow_origin.clone()
        };
        let listener = g.listener.clone().unwrap_or_else(|| "[::]:443".to_owned());
        let endpoints = g.endpoint.clone();
        let lb_backends = if !g.lb_backends.is_empty() {
            g.lb_backends.clone()
        } else {
            vec![LBBackend {
                addr: "127.0.0.1:443".into(),
                sni: Some("localhost".into()),
            }]
        };

        let mut sc = ServerConf::default();
        sc.daemon = cli.daemon;
        sc.threads = cli.threads;
        sc.pid_file = cli.pid.display().to_string();
        sc.ca_file = ca_root.as_ref().map(|p| p.display().to_string());
        sc.client_bind_to_ipv4 = g.client_bind_to_ipv4.clone();
        sc.client_bind_to_ipv6 = g.client_bind_to_ipv6.clone();
        sc.max_retries = 10;
        sc.upstream_debug_ssl_keylog = true;

        let gw = Gateway::new(
            sc,
            &listener,
            &cert,
            &key,
            client_ca.clone(),
            require_client_cert,
            origins,
            endpoints,
            lb_backends,
        )?;
        gateways.push(gw);

        if let Some(web_cfg) = g.web {
            let ws = WebServer::new(&web_cfg)?;
            webs.push(ws);
        }
    }

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

    info!(target = "startup", "Pingora bootstrapped");
    let mut handles: Vec<std::thread::JoinHandle<()>> = gateways
        .into_iter()
        .map(|gw| std::thread::spawn(move || gw.run()))
        .collect();
    handles.extend(
        webs.into_iter()
            .map(|ws| std::thread::spawn(move || ws.run())),
    );
    for h in handles {
        let _ = h.join();
    }
    #[allow(unreachable_code)]
    Ok(())
}
