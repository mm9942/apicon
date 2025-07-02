// Library for apicon proxy

pub mod error;
pub mod webserver;

use crate::error::{ProxErr, ProxResult};
use async_trait::async_trait;
use boring::ssl::SslVerifyMode;
use bytes::Bytes;
use clap::{ArgAction, Parser, Subcommand};
use futures_util::FutureExt;
use pingora::lb::discovery;
use pingora::lb::selection::RoundRobin;
use pingora::lb::{Backend, Backends, LoadBalancer};
use pingora::prelude::*;
use pingora_core::listeners::tls::TlsSettings;
use pingora_core::server::configuration::ServerConf;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session, http_proxy_service};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::info;

/* ---------------------------------------------------------------------- */
/* CLI flags                                                              */
/* ---------------------------------------------------------------------- */
#[derive(Parser, Debug)]
#[command(author, version)]
pub struct Cli {
    /// Run as background daemon
    #[arg(short = 'd', long, action = ArgAction::SetTrue)]
    pub daemon: bool,

    /// PID-file
    #[arg(long, default_value = "/run/pingora-gw.pid")]
    pub pid: PathBuf,

    /// User / group to drop to after bind
    #[arg(short = 'u', long)]
    pub user: Option<String>,
    #[arg(short = 'g', long)]
    pub group: Option<String>,

    /// Worker threads
    #[arg(short = 't', long, default_value_t = 4)]
    pub threads: usize,

    /// TLS cert / key / CA
    #[arg(
        short = 'c',
        long = "cert",
        default_value = "/home/mm29942/projects/keys/live/api.mm29942.com/fullchain.pem"
    )]
    pub cert: PathBuf,
    #[arg(
        short = 'k',
        long = "key",
        default_value = "/home/mm29942/projects/keys/live/api.mm29942.com/privkey.pem"
    )]
    pub key: PathBuf,
    #[arg(long = "ca-root")]
    pub ca_root: Option<PathBuf>,

    /// CA for verifying client certificates (mTLS)
    #[arg(long = "client-ca")]
    pub client_ca: Option<PathBuf>,

    /// Require clients to present valid certificates
    #[arg(long, action = ArgAction::SetTrue)]
    pub require_client_cert: bool,

    /// Logging: tracing level and optional log file
    #[arg(short = 'l', long, value_names=["LEVEL","FILE"], num_args=1..=2, default_values=["info"])]
    pub log: Vec<String>,

    /// JSON logs instead of plain
    #[arg(long, action = ArgAction::SetTrue)]
    pub json: bool,

    /// Config file with endpoints
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Allowed CORS origins (repeatable)
    #[arg(long = "allow-origin", action = ArgAction::Append)]
    pub allow_origin: Vec<String>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Manage systemd service
    Service {
        #[arg(long, action = ArgAction::SetTrue)]
        start: bool,
        #[arg(long, action = ArgAction::SetTrue)]
        restart: bool,
        #[arg(long, action = ArgAction::SetTrue)]
        stop: bool,
        #[arg(long, action = ArgAction::SetTrue)]
        status: bool,
        /// Install/manage these service unit names
        #[arg(long = "name", default_values=["apicon"], action = ArgAction::Append)]
        names: Vec<String>,

        /// Working directory for installed unit
        #[arg(long)]
        workingdir: Option<PathBuf>,
    },

    /// Generate sample certificates for mTLS
    Mtls {
        /// Output directory for generated certs
        #[arg(long, default_value = "./certs")]
        out: PathBuf,
    },
}

#[derive(Deserialize, Clone)]
pub struct Endpoint {
    pub prefix: String,
    pub addr: String,
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub sni: Option<String>,
}

#[derive(Deserialize, Clone)]
pub struct LBBackend {
    pub addr: String,
    #[serde(default)]
    pub sni: Option<String>,
}

#[derive(Deserialize, Clone, Default)]
pub struct GatewayConfig {
    #[serde(default)]
    pub listener: Option<String>,
    #[serde(default)]
    pub cert: Option<PathBuf>,
    #[serde(default)]
    pub key: Option<PathBuf>,
    #[serde(default, rename = "ca_root")]
    pub ca_root: Option<PathBuf>,
    #[serde(default, rename = "client_ca")]
    pub client_ca: Option<PathBuf>,
    #[serde(default)]
    pub require_client_cert: bool,
    #[serde(default, rename = "allow_origin")]
    pub allow_origin: Vec<String>,
    #[serde(default, rename = "lb_backends")]
    pub lb_backends: Vec<LBBackend>,
    #[serde(default)]
    pub endpoint: Vec<Endpoint>,
    #[serde(default)]
    pub round_robin: bool,
    #[serde(default)]
    pub client_bind_to_ipv4: Vec<String>,
    #[serde(default)]
    pub client_bind_to_ipv6: Vec<String>,

    #[serde(default)]
    pub web: Option<crate::webserver::WebServerConfig>,
}

#[derive(Deserialize, Default)]
pub struct FileConfig {
    #[serde(default)]
    pub gateways: Vec<GatewayConfig>,

    #[serde(default)]
    pub listener: Option<String>,
    #[serde(default)]
    pub cert: Option<PathBuf>,
    #[serde(default)]
    pub key: Option<PathBuf>,
    #[serde(default, rename = "ca_root")]
    pub ca_root: Option<PathBuf>,
    #[serde(default, rename = "client_ca")]
    pub client_ca: Option<PathBuf>,
    #[serde(default)]
    pub require_client_cert: bool,
    #[serde(default, rename = "allow_origin")]
    pub allow_origin: Vec<String>,
    #[serde(default, rename = "lb_backends")]
    pub lb_backends: Vec<LBBackend>,
    #[serde(default)]
    pub endpoint: Vec<Endpoint>,
    #[serde(default)]
    pub round_robin: bool,
    #[serde(default)]
    pub client_bind_to_ipv4: Vec<String>,
    #[serde(default)]
    pub client_bind_to_ipv6: Vec<String>,

    #[serde(default)]
    pub web: Option<crate::webserver::WebServerConfig>,
}

pub fn load_config(path: &Option<PathBuf>) -> ProxResult<FileConfig> {
    if let Some(p) = path {
        let data = std::fs::read_to_string(p).map_err(ProxErr::from)?;
        let cfg: FileConfig = toml::from_str(&data).map_err(|e| ProxErr::Other(e.to_string()))?;
        Ok(cfg)
    } else {
        Ok(FileConfig::default())
    }
}

#[derive(Default)]
#[allow(dead_code)]
struct Ctx {
    backend: &'static str,
    x_api_key: &'static str,
}

#[allow(dead_code)]
struct LB {
    lb: std::sync::Arc<LoadBalancer<RoundRobin>>,
    origins: Vec<String>,
    endpoints: Vec<Endpoint>,
}

#[async_trait]
impl ProxyHttp for LB {
    type CTX = Ctx;
    fn new_ctx(&self) -> Self::CTX {
        Ctx::default()
    }
    async fn upstream_peer(
        &self,
        sess: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>, Box<pingora::Error>> {
        let path = sess.req_header().uri.path();
        for ep in &self.endpoints {
            if path.starts_with(&ep.prefix) {
                let sni = ep.sni.as_deref().unwrap_or("localhost").to_owned();
                let peer = HttpPeer::new(ep.addr.to_owned(), ep.tls, sni);
                info!(target="proxy", addr=%ep.addr, path, "picked upstream from config");
                return Ok(Box::new(peer));
            }
        }
        let key = path.as_bytes();
        if let Some(backend) = self.lb.select(key, 3) {
            let addr = backend.addr;
            let sni = backend
                .ext
                .get::<String>()
                .map(|s| s.to_owned())
                .unwrap_or_else(|| "localhost".to_owned());
            info!(target = "proxy", addr = %addr, "picked upstream via LoadBalancer");
            let peer = HttpPeer::new(addr.to_string(), true, sni);
            Ok(Box::new(peer))
        } else {
            Err(ProxErr::Other("upstream_peer: no healthy backend available".into()).into_pg())
        }
    }

    async fn upstream_request_filter(
        &self,
        _sess: &mut Session,
        req: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<(), Box<pingora::Error>> {
        req.remove_header("Host");
        req.insert_header("Host", "m.mm29942.com").unwrap();
        Ok(())
    }

    async fn request_filter(
        &self,
        sess: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<bool, Box<pingora::Error>> {
        if sess.req_header().method == "OPTIONS" {
            let mut hdr = ResponseHeader::build(204, None).unwrap();
            if let Some(origin) = sess.req_header().headers.get("Origin").and_then(|o| {
                let o = o.to_str().ok()?;
                if self.origins.is_empty() || self.origins.iter().any(|a| a == o) {
                    Some(o)
                } else {
                    None
                }
            }) {
                hdr.insert_header("Access-Control-Allow-Origin", origin)
                    .unwrap();
            }
            hdr.insert_header(
                "Access-Control-Allow-Methods",
                "GET, POST, PUT, PATCH, DELETE, OPTIONS",
            )
            .unwrap();
            hdr.insert_header(
                "Access-Control-Allow-Headers",
                "Content-Type, Authorization, X-Requested-With",
            )
            .unwrap();
            hdr.insert_header("Access-Control-Max-Age", "86400")
                .unwrap();
            sess.write_response_header(Box::new(hdr), false).await?;
            sess.write_response_body(Some(Bytes::new()), true).await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn response_filter(
        &self,
        _sess: &mut Session,
        resp: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<(), Box<pingora::Error>> {
        if let Some(origin) = _sess.req_header().headers.get("Origin").and_then(|o| {
            let o = o.to_str().ok()?;
            if self.origins.is_empty() || self.origins.iter().any(|a| a == o) {
                Some(o)
            } else {
                None
            }
        }) {
            resp.insert_header("Access-Control-Allow-Origin", origin)
                .unwrap();
        }
        resp.insert_header(
            "Access-Control-Expose-Headers",
            "Content-Length, Content-Type",
        )
        .unwrap();
        Ok(())
    }
}

pub struct Gateway {
    pub server: Server,
    pub lb: std::sync::Arc<LoadBalancer<RoundRobin>>,
    pub client_bind_to_ipv4: Vec<String>,
    pub client_bind_to_ipv6: Vec<String>,
}

impl Gateway {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sc: ServerConf,
        listener: &str,
        cert: &Path,
        key: &Path,
        client_ca: Option<PathBuf>,
        require_client_cert: bool,
        origins: Vec<String>,
        endpoints: Vec<Endpoint>,
        lb_backends: Vec<LBBackend>,
    ) -> ProxResult<Self> {
        let listener_sock: std::net::SocketAddr = listener
            .parse()
            .map_err(|e| ProxErr::Other(format!("invalid listener {listener}: {e}")))?;
        let bind_ip = listener_sock.ip().to_string();
        let mut sc = sc;
        match listener_sock.ip() {
            std::net::IpAddr::V4(_) => sc.client_bind_to_ipv4 = vec![bind_ip.to_owned()],
            std::net::IpAddr::V6(_) => sc.client_bind_to_ipv6 = vec![bind_ip.to_owned()],
        }

        let ipv4 = sc.client_bind_to_ipv4.clone();
        let ipv6 = sc.client_bind_to_ipv6.clone();
        let mut server = Server::new_with_opt_and_conf(None, sc);
        server.bootstrap();

        let mut lb_set = BTreeSet::new();
        for b in &lb_backends {
            let mut be = Backend::new(&b.addr).map_err(|e| ProxErr::Other(e.to_string()))?;
            if let Some(sni) = &b.sni {
                be.ext.insert(sni.to_owned());
            }
            lb_set.insert(be);
        }
        let discovery = discovery::Static::new(lb_set);
        let mut lb = LoadBalancer::<RoundRobin>::from_backends(Backends::new(discovery));
        lb.update()
            .now_or_never()
            .expect("static should not block")
            .expect("static should not error");
        lb.update_frequency = Some(Duration::from_secs(30));
        lb.health_check_frequency = Some(Duration::from_secs(10));

        let lb = std::sync::Arc::new(lb);

        let mut tls = TlsSettings::intermediate(cert.to_str().unwrap(), key.to_str().unwrap())
            .expect("tls init");
        tls.enable_h2();
        if client_ca.is_some() || require_client_cert {
            if let Some(ca) = &client_ca {
                tls.set_ca_file(ca.to_str().unwrap())
                    .map_err(|e| ProxErr::Other(e.to_string()))?;
            } else {
                tls.set_default_verify_paths()
                    .map_err(|e| ProxErr::Other(e.to_string()))?;
            }
            let mut mode = SslVerifyMode::PEER;
            if require_client_cert {
                mode |= SslVerifyMode::FAIL_IF_NO_PEER_CERT;
            }
            tls.set_verify(mode);
        }

        let lb_service = LB {
            lb: lb.clone(),
            origins,
            endpoints,
        };
        let mut service = http_proxy_service(&server.configuration, lb_service);
        service.add_tls_with_settings(listener, None, tls);
        server.add_service(service);

        Ok(Self {
            server,
            lb,
            client_bind_to_ipv4: ipv4,
            client_bind_to_ipv6: ipv6,
        })
    }

    pub fn run(self) {
        self.server.run_forever();
    }
}

pub fn resolve_ids(
    u: Option<&String>,
    g: Option<&String>,
) -> ProxResult<(Option<nix::unistd::Uid>, Option<nix::unistd::Gid>)> {
    use nix::unistd::{Gid, Uid};
    use users::{get_group_by_name, get_user_by_name};
    let uid = u
        .map(|name| {
            get_user_by_name(name)
                .ok_or_else(|| ProxErr::Other(format!("user '{name}' not found")))
                .map(|u| Uid::from_raw(u.uid()))
        })
        .transpose()?;

    let gid = g
        .map(|name| {
            get_group_by_name(name)
                .ok_or_else(|| ProxErr::Other(format!("group '{name}' not found")))
                .map(|g| Gid::from_raw(g.gid()))
        })
        .transpose()?;

    Ok((uid, gid))
}

pub fn init_tracing(
    level: &str,
    json: bool,
    file: Option<&Path>,
) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));
    if let Some(path) = file {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let name = path.file_name().unwrap_or_default();
        let appender = tracing_appender::rolling::never(parent, name);
        let (writer, guard) = tracing_appender::non_blocking(appender);
        if json {
            fmt::Subscriber::builder()
                .with_env_filter(filter)
                .with_writer(writer)
                .json()
                .init();
        } else {
            fmt::Subscriber::builder()
                .with_env_filter(filter)
                .with_writer(writer)
                .init();
        }
        Some(guard)
    } else {
        if json {
            fmt::Subscriber::builder()
                .with_env_filter(filter)
                .json()
                .init();
        } else {
            fmt::Subscriber::builder().with_env_filter(filter).init();
        }
        None
    }
}

pub fn open_pid(path: &Path) -> ProxResult<std::fs::File> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(path)
        .map_err(ProxErr::from)
}

pub fn write_pid(f: &mut std::fs::File) -> ProxResult<()> {
    use std::io::Write;
    writeln!(f, "{}", std::process::id()).map_err(ProxErr::from)
}

pub fn systemctl_action(action: &str, names: &[String]) -> ProxResult<()> {
    use std::process::Command;
    for name in names {
        let out = Command::new("systemctl")
            .arg(action)
            .arg(name)
            .output()
            .map_err(ProxErr::from)?;
        print!("{}", String::from_utf8_lossy(&out.stdout));
        if !out.status.success() {
            eprintln!("{}", String::from_utf8_lossy(&out.stderr));
            return Err(ProxErr::Other(format!(
                "systemctl {} failed for {}",
                action, name
            )));
        }
    }
    Ok(())
}

pub fn create_service(
    cli: &crate::Cli,
    names: &[String],
    workingdir: &Option<PathBuf>,
) -> ProxResult<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::process::Command;
    let exe = std::env::current_exe().map_err(ProxErr::from)?;
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    args.retain(|a| a != "service");
    args.retain(|a| a != "--start" && a != "--restart" && a != "--stop" && a != "--status");
    if !args.iter().any(|a| a == "-d" || a == "--daemon") {
        args.push("-d".into());
    }
    let base = format!(
        "[Unit]\nDescription=apicon proxy\nAfter=network.target\n\n[Service]\nExecStart={} {}\n",
        exe.display(),
        args.join(" ")
    );
    let base = if let Some(wd) = workingdir {
        format!("{}WorkingDirectory={}\n", base, wd.display())
    } else {
        base
    };
    for name in names {
        let mut service = base.to_owned();
        if let Some(u) = &cli.user {
            service.push_str(&format!("User={}\n", u));
        }
        if let Some(g) = &cli.group {
            service.push_str(&format!("Group={}\n", g));
        }
        service.push_str("Restart=always\n\n[Install]\nWantedBy=multi-user.target\n");
        let service_path = format!("/etc/systemd/system/{}.service", name);
        let path = Path::new(&service_path);
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .map_err(ProxErr::from)?;
        f.write_all(service.as_bytes()).map_err(ProxErr::from)?;
        Command::new("systemctl")
            .arg("daemon-reload")
            .status()
            .map_err(ProxErr::from)?;
        Command::new("systemctl")
            .args(["enable", "--now", name])
            .status()
            .map_err(ProxErr::from)?;
    }
    Ok(())
}

pub fn generate_mtls(out: &Path) -> ProxResult<()> {
    use std::process::Command;
    std::fs::create_dir_all(out).map_err(ProxErr::from)?;
    let ca_key = out.join("ca.key");
    let ca_cert = out.join("ca.pem");
    Command::new("openssl")
        .args([
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-x509",
            "-subj",
            "/CN=apicon-test-ca",
            "-days",
            "1",
            "-keyout",
            ca_key.to_str().unwrap(),
            "-out",
            ca_cert.to_str().unwrap(),
        ])
        .status()
        .map_err(ProxErr::from)?;
    let srv_key = out.join("server.key");
    let srv_csr = out.join("server.csr");
    Command::new("openssl")
        .args([
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-keyout",
            srv_key.to_str().unwrap(),
            "-out",
            srv_csr.to_str().unwrap(),
        ])
        .status()
        .map_err(ProxErr::from)?;
    let srv_cert = out.join("server.pem");
    Command::new("openssl")
        .args([
            "x509",
            "-req",
            "-days",
            "1",
            "-in",
            srv_csr.to_str().unwrap(),
            "-CA",
            ca_cert.to_str().unwrap(),
            "-CAkey",
            ca_key.to_str().unwrap(),
            "-CAcreateserial",
            "-out",
            srv_cert.to_str().unwrap(),
        ])
        .status()
        .map_err(ProxErr::from)?;
    let cli_key = out.join("client.key");
    let cli_csr = out.join("client.csr");
    Command::new("openssl")
        .args([
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=client",
            "-keyout",
            cli_key.to_str().unwrap(),
            "-out",
            cli_csr.to_str().unwrap(),
        ])
        .status()
        .map_err(ProxErr::from)?;
    let cli_cert = out.join("client.pem");
    Command::new("openssl")
        .args([
            "x509",
            "-req",
            "-days",
            "1",
            "-in",
            cli_csr.to_str().unwrap(),
            "-CA",
            ca_cert.to_str().unwrap(),
            "-CAkey",
            ca_key.to_str().unwrap(),
            "-CAcreateserial",
            "-out",
            cli_cert.to_str().unwrap(),
        ])
        .status()
        .map_err(ProxErr::from)?;
    println!("Generated mTLS materials under {}", out.display());
    Ok(())
}
