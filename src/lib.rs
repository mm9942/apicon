// Library for apicon proxy

pub mod error;
mod ewma;
pub mod ocsp;
pub mod pool;
pub mod reload;
pub mod trace;
pub use ewma::DualEwma;

#[cfg(all(feature = "jemalloc", feature = "mimalloc"))]
compile_error!("features 'jemalloc' and 'mimalloc' cannot be enabled together");

#[cfg(feature = "jemalloc")]
use jemallocator::Jemalloc;

#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[cfg(feature = "mimalloc")]
use mimalloc::MiMalloc;

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use crate::{
    error::{ProxErr, ProxResult},
    ocsp::OcspCache,
};
use async_trait::async_trait;
use boring::ssl::{NameType, SslInfoCallbackMode, SslOptions, SslVerifyMode};
use bytes::Bytes;
use clap::{ArgAction, Parser, Subcommand};
use futures_util::FutureExt;
use hyper::{
    Body, Request, Response, Server as HyperServer,
    service::{make_service_fn, service_fn},
};
use once_cell::sync::Lazy;
use pingora::{
    lb::{
        Backend, Backends, LoadBalancer, discovery, health_check::TcpHealthCheck,
        selection::RoundRobin,
    },
    prelude::*,
};
use pingora_core::{
    connectors::http::Connector, listeners::tls::TlsSettings, server::configuration::ServerConf,
};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session, http_proxy_service};
use prometheus::{
    self, Encoder, Gauge, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, TextEncoder,
    register_gauge, register_histogram_vec, register_int_counter_vec, register_int_gauge,
    register_int_gauge_vec,
};
use rand::{Rng, RngCore};
use serde::Deserialize;
use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::info;

static REQUEST_DURATION_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "request_duration_seconds",
        "Request duration in seconds",
        &["backend"]
    )
    .expect("histogram")
});

static UPSTREAM_INFLIGHT: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!(
        "upstream_inflight",
        "In-flight requests to upstream",
        &["backend"]
    )
    .expect("gauge")
});

static RETRY_BUDGET: Lazy<Gauge> =
    Lazy::new(|| register_gauge!("retry_budget", "Remaining retry budget tokens").expect("gauge"));

static HEDGE_INFLIGHT: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!("hedge_inflight", "Number of in-flight hedged requests").expect("gauge")
});

static EJECTIONS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "ejections_total",
        "Total number of backend ejections",
        &["backend", "reason"]
    )
    .expect("counter")
});

async fn handle_metrics(
    req: Request<Body>,
    path: Arc<str>,
) -> Result<Response<Body>, hyper::Error> {
    if req.uri().path() != path.as_ref() {
        return Ok(Response::builder()
            .status(404)
            .body(Body::empty())
            .expect("response"));
    }
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder
        .encode(&metric_families, &mut buffer)
        .expect("encode");
    let resp = Response::builder()
        .header(hyper::header::CONTENT_TYPE, encoder.format_type())
        .body(Body::from(buffer))
        .expect("response");
    Ok(resp)
}

pub async fn serve_metrics(addr: std::net::SocketAddr, path: String) -> Result<(), hyper::Error> {
    let p = Arc::<str>::from(path);
    let make_svc = make_service_fn(move |_| {
        let path = Arc::clone(&p);
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                handle_metrics(req, Arc::clone(&path))
            }))
        }
    });
    HyperServer::bind(&addr).serve(make_svc).await
}

pub fn configure_keylog(sc: &mut ServerConf) {
    if let Ok(p) = std::env::var("PINGORA_KEYLOG") {
        unsafe {
            std::env::set_var("SSLKEYLOGFILE", &p);
        }
        sc.upstream_debug_ssl_keylog = true;
    } else {
        sc.upstream_debug_ssl_keylog = false;
    }
}

struct PendingPermit {
    _permit: OwnedSemaphorePermit,
    depth: Arc<AtomicUsize>,
}

impl Drop for PendingPermit {
    fn drop(&mut self) {
        self.depth.fetch_sub(1, Ordering::SeqCst);
    }
}

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

    /// Maximum number of pending requests
    #[arg(long = "queue-cap", default_value_t = 100)]
    pub queue_cap: usize,

    /// Warm-up connections per backend
    #[arg(short = 'w', long = "preconnect", default_value_t = 0)]
    pub preconnect: usize,

    /// Disable TLS session tickets
    #[arg(long = "no-session-tickets", action = ArgAction::SetTrue)]
    pub no_session_tickets: bool,

    /// Disable OCSP stapling
    #[arg(long = "no-ocsp", action = ArgAction::SetTrue)]
    pub no_ocsp: bool,

    /// Session ticket rotation interval in seconds
    #[arg(long = "ticket-rotate", default_value_t = 86400)]
    pub ticket_rotate: u64,

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
    #[serde(default, rename = "connect_timeout_ms")]
    pub connect_timeout_ms: Option<u64>,
    #[serde(default, rename = "read_timeout_ms")]
    pub read_timeout_ms: Option<u64>,
    #[serde(default, rename = "header_timeout_ms")]
    pub header_timeout_ms: Option<u64>,
    #[serde(default, rename = "body_timeout_ms")]
    pub body_timeout_ms: Option<u64>,
}

#[derive(Deserialize, Clone)]
pub struct LBBackend {
    pub addr: String,
    #[serde(default = "default_true")]
    pub tls: bool,
    #[serde(default)]
    pub sni: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
pub struct MetricsConfig {
    pub addr: String,
    #[serde(default = "default_metrics_path")]
    pub path: String,
}

fn default_metrics_path() -> String {
    "/metrics".to_string()
}

#[derive(Deserialize, Default)]
pub struct FileConfig {
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
    pub base_prefix: Option<String>,
    #[serde(default)]
    pub prepend_base_prefix: bool,
    #[serde(default)]
    pub round_robin: bool,
    #[serde(default)]
    pub client_bind_to_ipv4: Vec<String>,
    #[serde(default)]
    pub client_bind_to_ipv6: Vec<String>,
    #[serde(default)]
    pub queue_cap: Option<usize>,
    #[serde(default)]
    pub preconnect: Option<usize>,
    #[serde(default)]
    pub default_header_timeout_ms: Option<u64>,
    #[serde(default)]
    pub default_body_timeout_ms: Option<u64>,

    #[serde(default)]
    pub metrics: Option<MetricsConfig>,

    #[serde(default = "default_true")]
    pub session_ticket: bool,
    #[serde(default = "default_true")]
    pub ocsp_stapling: bool,
    #[serde(default)]
    pub ticket_rotate: Option<u64>,
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

struct LatencyWindow {
    samples: VecDeque<Duration>,
    cap: usize,
}

impl LatencyWindow {
    fn new(cap: usize) -> Self {
        Self {
            samples: VecDeque::with_capacity(cap),
            cap,
        }
    }

    fn record(&mut self, d: Duration) {
        if self.samples.len() >= self.cap {
            self.samples.pop_front();
        }
        self.samples.push_back(d);
    }

    fn p95(&self) -> Option<Duration> {
        if self.samples.is_empty() {
            return None;
        }
        let mut v: Vec<_> = self.samples.iter().copied().collect();
        v.sort_unstable();
        let idx = ((v.len() as f64) * 0.95).ceil() as usize - 1;
        v.get(idx).copied()
    }

    fn stats(&self) -> Option<(usize, f64, f64)> {
        if self.samples.is_empty() {
            return None;
        }
        let n = self.samples.len();
        let mut sum = 0.0;
        for d in &self.samples {
            sum += d.as_secs_f64() * 1000.0;
        }
        let mean = sum / n as f64;
        let mut var_sum = 0.0;
        for d in &self.samples {
            let ms = d.as_secs_f64() * 1000.0;
            let diff = ms - mean;
            var_sum += diff * diff;
        }
        let variance = var_sum / n as f64;
        Some((n, mean, variance))
    }
}

struct RouteMetrics {
    windows: HashMap<String, LatencyWindow>,
    cap: usize,
}

impl RouteMetrics {
    fn new(cap: usize) -> Self {
        Self {
            windows: HashMap::new(),
            cap,
        }
    }

    fn record(&mut self, route: &str, d: Duration) {
        let w = self
            .windows
            .entry(route.to_owned())
            .or_insert_with(|| LatencyWindow::new(self.cap));
        w.record(d);
    }

    fn p95(&self, route: &str) -> Option<Duration> {
        self.windows.get(route).and_then(|w| w.p95())
    }

    fn stats(&self, route: &str) -> Option<(usize, f64, f64)> {
        self.windows.get(route).and_then(|w| w.stats())
    }
}

struct RetryBudget {
    max: f64,
    tokens: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl RetryBudget {
    fn new(max: usize, refill_per_sec: f64) -> Self {
        let max_f = max as f64;
        Self {
            max: max_f,
            tokens: max_f,
            refill_per_sec,
            last: Instant::now(),
        }
    }

    fn try_acquire(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.max);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn tokens(&self) -> f64 {
        self.tokens
    }
}

struct BackendStats {
    latency: DualEwma,
    error_ewma: f64,
    ejected_until: Option<Instant>,
    latency_ejections: usize,
    error_ejections: usize,
    inflight: usize,
    limit: usize,
    cap: usize,
}

impl Default for BackendStats {
    fn default() -> Self {
        Self {
            latency: DualEwma::default(),
            error_ewma: 0.0,
            ejected_until: None,
            latency_ejections: 0,
            error_ejections: 0,
            inflight: 0,
            limit: 1,
            cap: 32,
        }
    }
}

impl BackendStats {
    #[allow(clippy::too_many_arguments)]
    fn update(
        &mut self,
        latency: Duration,
        err: bool,
        lat_limit: f64,
        err_limit: f64,
        cooldown: Duration,
        volume: usize,
        mean: f64,
        variance: f64,
    ) -> Option<&'static str> {
        const ALPHA: f64 = 0.2;
        let ms = latency.as_secs_f64() * 1000.0;
        self.latency.record(ms, volume, mean, variance);
        let lat_short = self.latency.short();
        let sample = if err { 1.0 } else { 0.0 };
        if self.error_ewma == 0.0 {
            self.error_ewma = sample;
        } else {
            self.error_ewma = ALPHA * sample + (1.0 - ALPHA) * self.error_ewma;
        }
        if err {
            self.limit = (self.limit / 2).max(1);
        } else if self.limit < self.cap {
            self.limit += 1;
        }
        if self.ejected_until.is_none() {
            let now = Instant::now();
            if lat_short > lat_limit {
                self.ejected_until = Some(now + cooldown);
                self.latency_ejections += 1;
                return Some("latency");
            } else if self.error_ewma > err_limit {
                self.ejected_until = Some(now + cooldown);
                self.error_ejections += 1;
                return Some("error");
            }
        }
        None
    }

    fn is_ejected(&mut self) -> bool {
        if let Some(t) = self.ejected_until {
            if Instant::now() >= t {
                self.ejected_until = None;
            }
        }
        self.ejected_until.is_some()
    }
}

struct Ctx {
    authority: String,
    start: Instant,
    route: String,
    path_kind: String,
    backend: String,
    peer_ip: String,
    sni: String,
    tls_proto: String,
    tls_cipher: String,
    pending: Option<PendingPermit>,
    hedged: bool,
    trace: trace::TraceContext,
    trace_kind: trace::TraceHeader,
}

#[allow(dead_code)]
struct LB {
    lb: Arc<LoadBalancer<RoundRobin>>,
    origins: Vec<String>,
    endpoints: Vec<Endpoint>,
    base_prefix: Option<String>,
    prepend_base_prefix: bool,
    metrics: Arc<Mutex<RouteMetrics>>,
    hedge_threshold: Duration,
    retry_budget: Arc<Mutex<RetryBudget>>,
    backend_addrs: Vec<String>,
    backend_stats: Arc<Mutex<HashMap<String, BackendStats>>>,
    latency_limit: Duration,
    error_limit: f64,
    cooldown: Duration,
    pending: Arc<Semaphore>,
    queue_depth: Arc<AtomicUsize>,
    hash_dos_max_headers: usize,
    hash_dos_avg_len: usize,
    hash_dos_counter: Arc<AtomicUsize>,
    preconnect: usize,
    warmed: Arc<Mutex<HashMap<String, Instant>>>,
    warm_success: Arc<AtomicUsize>,
    warm_failure: Arc<AtomicUsize>,
    default_header_timeout_ms: Option<u64>,
    default_body_timeout_ms: Option<u64>,
}

/// Check if the request path targets a sensitive file that should not reveal
/// its presence. Such paths should return 404 rather than 401 to avoid
/// hinting at protected resources.
pub fn is_sensitive_path(path: &str) -> bool {
    matches!(
        path.to_ascii_lowercase().as_str(),
        "/public/aws_credentials.php"
            | "/public/awscredentials.php"
            | "/public/credentials.php"
            | "/public/secrets.php"
            | "/public/config/aws_credentials.php"
            | "/public/config/awscredentials.php"
            | "/public/config/credentials.php"
            | "/public/config/secrets.php"
    )
}

fn log_access(ctx: &Ctx, req: &RequestHeader, status: u16) {
    let host = req.headers.get("Host").and_then(|h| h.to_str().ok());
    let user_agent = req.headers.get("User-Agent").and_then(|h| h.to_str().ok());
    info!(
        target = "access",
        trace_id = %ctx.trace.trace_id,
        route = %ctx.route,
        path_kind = %ctx.path_kind,
        backend = %ctx.backend,
        peer_ip = %ctx.peer_ip,
        sni = %ctx.sni,
        tls_proto = %ctx.tls_proto,
        tls_cipher = %ctx.tls_cipher,
        method = %req.method,
        uri = %req.uri,
        host,
        user_agent,
        status
    );
}

fn build_prefix(base: Option<&str>, prepend: bool, prefix: &str) -> String {
    if prepend {
        if let Some(b) = base {
            if prefix.starts_with('/') {
                prefix.to_owned()
            } else {
                format!(
                    "{}/{}",
                    b.trim_end_matches('/'),
                    prefix.trim_start_matches('/')
                )
            }
        } else {
            prefix.to_owned()
        }
    } else {
        prefix.to_owned()
    }
}

#[async_trait]
impl ProxyHttp for LB {
    type CTX = Ctx;
    fn new_ctx(&self) -> Self::CTX {
        Ctx {
            authority: String::new(),
            start: Instant::now(),
            route: String::new(),
            path_kind: String::new(),
            backend: String::new(),
            peer_ip: String::new(),
            sni: String::new(),
            tls_proto: String::new(),
            tls_cipher: String::new(),
            pending: None,
            hedged: false,
            trace: trace::generate_context(),
            trace_kind: trace::TraceHeader::Both,
        }
    }
    async fn upstream_peer(
        &self,
        sess: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>, Box<pingora::Error>> {
        let path = sess.req_header().uri.path();
        for ep in &self.endpoints {
            let prefix = build_prefix(
                self.base_prefix.as_deref(),
                self.prepend_base_prefix,
                &ep.prefix,
            );
            if path.starts_with(&prefix) {
                let authority = ep.sni.as_deref().unwrap_or("localhost").to_owned();
                ctx.authority = authority.to_owned();
                ctx.route = prefix;
                ctx.path_kind = "endpoint".to_owned();
                ctx.backend = ep.addr.to_owned();
                if !self.acquire_backend(&ctx.backend) {
                    return Err(
                        ProxErr::Other("upstream concurrency limit reached".to_string()).into_pg(),
                    );
                }
                let mut peer = HttpPeer::new(ctx.backend.to_owned(), ep.tls, authority);
                if let Some(ms) = ep.connect_timeout_ms {
                    peer.options.connection_timeout = Some(Duration::from_millis(ms));
                }
                let header_timeout_ms = ep.header_timeout_ms.or(self.default_header_timeout_ms);
                if let Some(ms) = header_timeout_ms {
                    peer.options.read_timeout = Some(Duration::from_millis(ms));
                }
                let body_timeout_ms = ep.body_timeout_ms.or(self.default_body_timeout_ms);
                if let Some(ms) = body_timeout_ms {
                    peer.options.idle_timeout = Some(Duration::from_millis(ms));
                }
                info!(target="proxy", trace_id=%ctx.trace.trace_id, addr=%ep.addr, path, "picked upstream from config");
                self.maybe_preconnect(&ctx.backend, ep.tls, &ctx.authority);
                return Ok(Box::new(peer));
            }
        }
        let key = path.as_bytes();
        for _ in 0..self.backend_addrs.len() {
            if let Some(backend) = self.lb.select(key, 3) {
                let addr = backend.addr;
                let addr_str = addr.to_string();
                let weight = if let Ok(map) = self.backend_stats.lock() {
                    map.get(&addr_str)
                        .map(|s| (1.0 / s.latency.ratio()).clamp(0.0, 1.0))
                        .unwrap_or(1.0)
                } else {
                    1.0
                };
                if rand::thread_rng().r#gen::<f64>() > weight {
                    continue;
                }
                if self.backend_ejected(&addr_str) || !self.acquire_backend(&addr_str) {
                    continue;
                }
                let sni = backend
                    .ext
                    .get::<String>()
                    .map_or_else(|| "localhost".to_owned(), |s| s.to_owned());
                let tls = backend.ext.get::<bool>().copied().unwrap_or(true);
                ctx.authority = sni.to_owned();
                ctx.route = "/lb".to_owned();
                ctx.path_kind = "lb".to_owned();
                ctx.backend = addr_str.to_owned();
                info!(target = "proxy", trace_id=%ctx.trace.trace_id, addr = %addr, "picked upstream via LoadBalancer");
                self.maybe_preconnect(&ctx.backend, tls, &ctx.authority);
                let peer = HttpPeer::new(addr.to_string(), tls, sni);
                return Ok(Box::new(peer));
            }
        }
        Err(ProxErr::Other("upstream_peer: no healthy backend available".into()).into_pg())
    }

    async fn upstream_request_filter(
        &self,
        sess: &mut Session,
        req: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<pingora::Error>> {
        ctx.hedged = self.should_hedge(&ctx.route);
        if ctx.hedged {
            HEDGE_INFLIGHT.inc();
        }
        if let Some(host) = sess
            .req_header()
            .headers
            .get("Host")
            .and_then(|h| h.to_str().ok())
        {
            req.insert_header("X-Forwarded-Host", host)
                .map_err(|e| ProxErr::Http(e.to_string()).into_pg())?;
        }
        req.insert_header("X-Forwarded-Proto", "https")
            .map_err(|e| ProxErr::Http(e.to_string()).into_pg())?;
        if let Some(addr) = sess.client_addr() {
            let mut ip = addr.to_string();
            if let Some(pos) = ip.rfind(':') {
                ip.truncate(pos);
            }
            let existing = req
                .headers
                .get("X-Forwarded-For")
                .and_then(|v| v.to_str().ok())
                .map(|s| format!("{s}, {ip}"))
                .unwrap_or(ip);
            req.insert_header("X-Forwarded-For", existing)
                .map_err(|e| ProxErr::Http(e.to_string()).into_pg())?;
        }
        req.remove_header("Host");
        req.insert_header("Host", &ctx.authority)
            .map_err(|e| ProxErr::Http(e.to_string()).into_pg())?;
        match ctx.trace_kind {
            trace::TraceHeader::TraceParent => {
                let tp = trace::format_traceparent(&ctx.trace);
                req.insert_header("traceparent", &tp)
                    .map_err(|e| ProxErr::Http(e.to_string()).into_pg())?;
            }
            trace::TraceHeader::B3 => {
                let b3 = trace::format_b3(&ctx.trace);
                req.insert_header("b3", &b3)
                    .map_err(|e| ProxErr::Http(e.to_string()).into_pg())?;
            }
            trace::TraceHeader::Both => {
                let tp = trace::format_traceparent(&ctx.trace);
                req.insert_header("traceparent", &tp)
                    .map_err(|e| ProxErr::Http(e.to_string()).into_pg())?;
                let b3 = trace::format_b3(&ctx.trace);
                req.insert_header("b3", &b3)
                    .map_err(|e| ProxErr::Http(e.to_string()).into_pg())?;
            }
        }
        info!(target="trace", trace_id=%ctx.trace.trace_id, "propagated trace context");
        Ok(())
    }

    async fn request_filter(
        &self,
        sess: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool, Box<pingora::Error>> {
        let tp = sess
            .req_header()
            .headers
            .get("traceparent")
            .and_then(|h| h.to_str().ok());
        let b3 = sess
            .req_header()
            .headers
            .get("b3")
            .and_then(|h| h.to_str().ok());
        let (tc, kind) = trace::extract_context(tp, b3);
        ctx.trace = tc;
        ctx.trace_kind = kind;
        if let Some(addr) = sess.client_addr() {
            let mut ip = addr.to_string();
            if let Some(pos) = ip.rfind(':') {
                ip.truncate(pos);
            }
            ctx.peer_ip = ip;
        }
        if let Some(ssl) = sess.as_downstream().stream().and_then(|s| s.get_ssl()) {
            if let Some(name) = ssl.servername(NameType::HOST_NAME) {
                ctx.sni = name.to_owned();
            }
            ctx.tls_proto = ssl.version_str().to_owned();
            ctx.tls_cipher = ssl
                .current_cipher()
                .map(|c| c.name().to_owned())
                .unwrap_or_else(|| String::from("unknown"));
        }
        info!(target="trace", trace_id=%ctx.trace.trace_id, span_id=%ctx.trace.span_id, "received request");
        if self.detect_header_dos(sess.req_header()) {
            let hdr = ResponseHeader::build(400, None)
                .map_err(|e| ProxErr::Http(e.to_string()).into_pg())?;
            sess.write_response_header(Box::new(hdr), false).await?;
            sess.write_response_body(Some(Bytes::new()), true).await?;
            return Ok(true);
        }
        let path = sess.req_header().uri.path();
        if is_sensitive_path(path) {
            let hdr = ResponseHeader::build(404, None)
                .map_err(|e| ProxErr::Http(e.to_string()).into_pg())?;
            sess.write_response_header(Box::new(hdr), false).await?;
            sess.write_response_body(Some(Bytes::new()), true).await?;
            return Ok(true);
        }
        match self.enqueue() {
            Ok(p) => ctx.pending = Some(p),
            Err(hdr) => {
                sess.write_response_header(Box::new(hdr), false).await?;
                sess.write_response_body(Some(Bytes::new()), true).await?;
                return Ok(true);
            }
        }
        if sess.req_header().method == "OPTIONS" {
            let mut hdr = ResponseHeader::build(204, None)
                .map_err(|e| ProxErr::Http(e.to_string()).into_pg())?;
            if let Some(origin) = sess.req_header().headers.get("Origin").and_then(|o| {
                let o = o.to_str().ok()?;
                if self.origins.is_empty() || self.origins.iter().any(|a| a == o) {
                    Some(o)
                } else {
                    None
                }
            }) {
                hdr.insert_header("Access-Control-Allow-Origin", origin)
                    .map_err(|e| ProxErr::Http(e.to_string()).into_pg())?;
            }
            if let Some(m) = sess
                .req_header()
                .headers
                .get("Access-Control-Request-Method")
                .and_then(|m| m.to_str().ok())
            {
                hdr.insert_header("Access-Control-Allow-Methods", m)
                    .map_err(|e| ProxErr::Http(e.to_string()).into_pg())?;
            } else {
                hdr.insert_header(
                    "Access-Control-Allow-Methods",
                    "GET, POST, PUT, PATCH, DELETE, OPTIONS",
                )
                .map_err(|e| ProxErr::Http(e.to_string()).into_pg())?;
            }
            if let Some(h) = sess
                .req_header()
                .headers
                .get("Access-Control-Request-Headers")
                .and_then(|h| h.to_str().ok())
            {
                hdr.insert_header("Access-Control-Allow-Headers", h)
                    .map_err(|e| ProxErr::Http(e.to_string()).into_pg())?;
            } else {
                hdr.insert_header(
                    "Access-Control-Allow-Headers",
                    "Content-Type, Authorization, X-Requested-With",
                )
                .map_err(|e| ProxErr::Http(e.to_string()).into_pg())?;
            }
            hdr.insert_header("Access-Control-Max-Age", "86400")
                .map_err(|e| ProxErr::Http(e.to_string()).into_pg())?;
            hdr.insert_header(
                "Vary",
                "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
            )
            .map_err(|e| ProxErr::Http(e.to_string()).into_pg())?;
            sess.write_response_header(Box::new(hdr), false).await?;
            sess.write_response_body(Some(Bytes::new()), true).await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn response_filter(
        &self,
        sess: &mut Session,
        resp: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<pingora::Error>> {
        if let Some(origin) = sess.req_header().headers.get("Origin").and_then(|o| {
            let o = o.to_str().ok()?;
            if self.origins.is_empty() || self.origins.iter().any(|a| a == o) {
                Some(o)
            } else {
                None
            }
        }) {
            resp.insert_header("Access-Control-Allow-Origin", origin)
                .map_err(|e| ProxErr::Http(e.to_string()).into_pg())?;
        }
        resp.append_header("Vary", "Origin")
            .map_err(|e| ProxErr::Http(e.to_string()).into_pg())?;
        resp.insert_header(
            "Access-Control-Expose-Headers",
            "Content-Length, Content-Type",
        )
        .map_err(|e| ProxErr::Http(e.to_string()).into_pg())?;
        let err = resp.status.as_u16() >= 500;
        self.record_backend_result(&ctx.backend, &ctx.route, ctx.start.elapsed(), err);
        if ctx.hedged {
            HEDGE_INFLIGHT.dec();
        }
        self.record_latency(&ctx.route, ctx.start.elapsed());
        log_access(ctx, sess.req_header(), resp.status.as_u16());
        Ok(())
    }
}

impl LB {
    fn record_latency(&self, route: &str, d: Duration) {
        if let Ok(mut m) = self.metrics.lock() {
            m.record(route, d);
        }
    }

    fn should_hedge(&self, route: &str) -> bool {
        let p95_exceeded = if let Ok(m) = self.metrics.lock() {
            m.p95(route).is_some_and(|p| p > self.hedge_threshold)
        } else {
            false
        };
        if p95_exceeded {
            if let Ok(mut b) = self.retry_budget.lock() {
                let ok = b.try_acquire();
                RETRY_BUDGET.set(b.tokens());
                ok
            } else {
                false
            }
        } else {
            false
        }
    }

    fn record_backend_result(&self, addr: &str, route: &str, d: Duration, err: bool) {
        let (volume, mean, variance) = if let Ok(m) = self.metrics.lock() {
            m.stats(route).unwrap_or((0, d.as_secs_f64() * 1000.0, 0.0))
        } else {
            (0, d.as_secs_f64() * 1000.0, 0.0)
        };
        if let Ok(mut map) = self.backend_stats.lock() {
            let stat = map
                .entry(addr.to_owned())
                .or_insert_with(BackendStats::default);
            if stat.inflight > 0 {
                stat.inflight -= 1;
            }
            UPSTREAM_INFLIGHT.with_label_values(&[addr]).dec();
            REQUEST_DURATION_SECONDS
                .with_label_values(&[addr])
                .observe(d.as_secs_f64());
            if let Some(reason) = stat.update(
                d,
                err,
                self.latency_limit.as_secs_f64() * 1000.0,
                self.error_limit,
                self.cooldown,
                volume,
                mean,
                variance,
            ) {
                EJECTIONS_TOTAL.with_label_values(&[addr, reason]).inc();
            }
        }
    }

    fn backend_ejected(&self, addr: &str) -> bool {
        if let Ok(mut map) = self.backend_stats.lock() {
            if let Some(s) = map.get_mut(addr) {
                return s.is_ejected();
            }
        }
        false
    }

    fn acquire_backend(&self, addr: &str) -> bool {
        if let Ok(mut map) = self.backend_stats.lock() {
            let stat = map
                .entry(addr.to_owned())
                .or_insert_with(BackendStats::default);
            if stat.inflight >= stat.limit || stat.inflight >= stat.cap {
                return false;
            }
            stat.inflight += 1;
            UPSTREAM_INFLIGHT.with_label_values(&[addr]).inc();
            return true;
        }
        false
    }

    fn maybe_preconnect(&self, addr: &str, tls: bool, sni: &str) {
        if self.preconnect == 0 {
            return;
        }
        if let Ok(mut map) = self.warmed.lock() {
            let now = Instant::now();
            let needs = match map.get(addr) {
                Some(t) => now.duration_since(*t) > Duration::from_secs(300),
                None => true,
            };
            if needs {
                map.insert(addr.to_owned(), now);
                let addr_s = addr.to_owned();
                let sni_s = sni.to_owned();
                let count = self.preconnect;
                let success = Arc::clone(&self.warm_success);
                let failure = Arc::clone(&self.warm_failure);
                tokio::spawn(async move {
                    preconnect_backend(addr_s, tls, sni_s, 0, count, success, failure).await;
                });
            }
        }
    }

    fn detect_header_dos(&self, req: &RequestHeader) -> bool {
        let mut total = 0usize;
        let mut count = 0usize;
        for (name, value) in req.headers.iter() {
            count += 1;
            total += name.as_str().len() + value.as_bytes().len();
        }
        if count > self.hash_dos_max_headers {
            let avg = if count > 0 { total / count } else { 0 };
            if avg < self.hash_dos_avg_len {
                let c = self.hash_dos_counter.fetch_add(1, Ordering::SeqCst) + 1;
                info!(target = "proxy", hash_dos_count = c, "hash dos detected");
                info!(target = "metrics", hash_dos = c);
                return true;
            }
        }
        false
    }

    #[allow(clippy::result_large_err)]
    fn enqueue(&self) -> Result<PendingPermit, ResponseHeader> {
        match Arc::clone(&self.pending).try_acquire_owned() {
            Ok(permit) => {
                let depth = self.queue_depth.fetch_add(1, Ordering::SeqCst) + 1;
                info!(target = "metrics", queue_depth = depth);
                Ok(PendingPermit {
                    _permit: permit,
                    depth: Arc::clone(&self.queue_depth),
                })
            }
            Err(_) => {
                let mut hdr = ResponseHeader::build(503, None).expect("status");
                hdr.insert_header("Retry-After", "1").expect("header");
                Err(hdr)
            }
        }
    }
}

pub struct Gateway {
    pub server: Server,
    pub lb: std::sync::Arc<LoadBalancer<RoundRobin>>,
    pub client_bind_to_ipv4: Vec<String>,
    pub client_bind_to_ipv6: Vec<String>,
    _pending: Arc<Semaphore>,
    queue_depth: Arc<AtomicUsize>,
    hash_dos_counter: Arc<AtomicUsize>,
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
        base_prefix: Option<String>,
        prepend_base_prefix: bool,
        lb_backends: Vec<LBBackend>,
        queue_cap: usize,
        preconnect: usize,
        default_header_timeout_ms: Option<u64>,
        default_body_timeout_ms: Option<u64>,
        session_ticket: bool,
        ticket_rotate: u64,
        ocsp_stapling: bool,
    ) -> ProxResult<Self> {
        let listener_sock: std::net::SocketAddr = listener
            .parse()
            .map_err(|e| ProxErr::Other(format!("invalid listener {listener}: {e}")))?;
        let bind_ip = listener_sock.ip().to_string();
        let mut sc = sc;
        if sc.client_bind_to_ipv4.is_empty() && sc.client_bind_to_ipv6.is_empty() {
            match listener_sock.ip() {
                std::net::IpAddr::V4(_) => sc.client_bind_to_ipv4 = vec![bind_ip.to_owned()],
                std::net::IpAddr::V6(_) => sc.client_bind_to_ipv6 = vec![bind_ip.to_owned()],
            }
        }

        let ipv4 = sc.client_bind_to_ipv4.to_vec();
        let ipv6 = sc.client_bind_to_ipv6.to_vec();
        let mut server = Server::new_with_opt_and_conf(None, sc);
        server.bootstrap();

        let mut lb_set = BTreeSet::new();
        for b in &lb_backends {
            let mut be = Backend::new(&b.addr).map_err(|e| ProxErr::Other(e.to_string()))?;
            if let Some(sni) = &b.sni {
                be.ext.insert(sni.to_owned());
            }
            be.ext.insert(b.tls);
            lb_set.insert(be);
        }
        let discovery = discovery::Static::new(lb_set);
        let mut backends = Backends::new(discovery);
        backends.set_health_check(TcpHealthCheck::new());
        let mut lb = LoadBalancer::<RoundRobin>::from_backends(backends);
        lb.update()
            .now_or_never()
            .expect("static should not block")
            .expect("static should not error");
        lb.update_frequency = Some(Duration::from_secs(30));
        lb.health_check_frequency = Some(Duration::from_secs(10));

        let lb = std::sync::Arc::new(lb);
        let metrics = Arc::new(Mutex::new(RouteMetrics::new(100)));
        let retry_budget = Arc::new(Mutex::new(RetryBudget::new(10, 1.0)));
        RETRY_BUDGET.set(10.0);
        let hedge_threshold = Duration::from_millis(500);
        let pending = Arc::new(Semaphore::new(queue_cap));
        let queue_depth = Arc::new(AtomicUsize::new(0));
        let hash_dos_counter = Arc::new(AtomicUsize::new(0));

        let cert_str = cert
            .to_str()
            .ok_or_else(|| ProxErr::Other("invalid cert path".into()))?;
        let key_str = key
            .to_str()
            .ok_or_else(|| ProxErr::Other("invalid key path".into()))?;
        let mut tls = TlsSettings::intermediate(cert_str, key_str)
            .map_err(|e| ProxErr::Other(e.to_string()))?;
        tls.enable_h2();
        if client_ca.is_some() || require_client_cert {
            if let Some(ca) = &client_ca {
                let ca_str = ca
                    .to_str()
                    .ok_or_else(|| ProxErr::Other("invalid ca path".into()))?;
                tls.set_ca_file(ca_str)
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

        let ctx_ptr = tls.as_ptr();
        if session_ticket {
            tls.clear_options(SslOptions::NO_TICKET);
            rotate_ticket_key(ctx_ptr);
            let ctx_arc = Arc::new(std::sync::atomic::AtomicPtr::new(ctx_ptr));
            let ctx_clone = Arc::clone(&ctx_arc);
            let rotate = Duration::from_secs(ticket_rotate);
            std::thread::spawn(move || {
                loop {
                    std::thread::sleep(rotate);
                    let p = ctx_clone.load(Ordering::Relaxed);
                    rotate_ticket_key(p);
                }
            });
        }

        let ocsp_cache = if ocsp_stapling {
            OcspCache::new(ctx_ptr, cert.to_owned())
        } else {
            None
        };
        let ocsp_info = ocsp_cache.as_ref().map(Arc::clone);

        let ocsp_log = ocsp_stapling;
        tls.set_new_session_callback(move |ssl, _| {
            let stapled = ssl.ocsp_status().is_some();
            info!(
                target = "handshake",
                stapled = stapled && ocsp_log,
                ticket_issued = true,
                ticket_resumed = false
            );
        });
        tls.set_info_callback(move |ssl, mode, _| {
            if mode == SslInfoCallbackMode::HANDSHAKE_START {
                if let Some(ref cache) = ocsp_info {
                    if ssl.ocsp_status().is_none() || cache.is_stale() {
                        cache.spawn_refresh();
                    }
                }
            }
            if mode == SslInfoCallbackMode::HANDSHAKE_DONE && ssl.session_reused() {
                let stapled = ssl.ocsp_status().is_some();
                info!(
                    target = "handshake",
                    stapled = stapled,
                    ticket_issued = false,
                    ticket_resumed = true
                );
            }
        });

        let mut endpoints = endpoints;
        endpoints.sort_by(|a, b| b.prefix.len().cmp(&a.prefix.len()));
        let backend_addrs = lb_backends.iter().map(|b| b.addr.to_owned()).collect();
        let backend_stats = Arc::new(Mutex::new(HashMap::new()));
        let latency_limit = Duration::from_millis(1000);
        let error_limit = 0.5;
        let cooldown = Duration::from_secs(30);
        let warm_success = Arc::new(AtomicUsize::new(0));
        let warm_failure = Arc::new(AtomicUsize::new(0));
        let warmed = Arc::new(Mutex::new(HashMap::new()));
        let lb_service = LB {
            lb: std::sync::Arc::clone(&lb),
            origins,
            endpoints,
            base_prefix,
            prepend_base_prefix,
            metrics: Arc::clone(&metrics),
            hedge_threshold,
            retry_budget: Arc::clone(&retry_budget),
            backend_addrs,
            backend_stats,
            latency_limit,
            error_limit,
            cooldown,
            pending: Arc::clone(&pending),
            queue_depth: Arc::clone(&queue_depth),
            hash_dos_max_headers: 100,
            hash_dos_avg_len: 8,
            hash_dos_counter: Arc::clone(&hash_dos_counter),
            preconnect,
            warmed: Arc::clone(&warmed),
            warm_success: Arc::clone(&warm_success),
            warm_failure: Arc::clone(&warm_failure),
            default_header_timeout_ms,
            default_body_timeout_ms,
        };
        let mut service = http_proxy_service(&server.configuration, lb_service);
        service.add_tls_with_settings(listener, None, tls);
        server.add_service(service);

        if preconnect > 0 {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| ProxErr::Other(e.to_string()))?;
            for b in &lb_backends {
                let addr = b.addr.to_owned();
                let tls_b = b.tls;
                let sni_b = b
                    .sni
                    .as_ref()
                    .map_or_else(|| "localhost".to_owned(), |s| s.to_owned());
                let succ = Arc::clone(&warm_success);
                let fail = Arc::clone(&warm_failure);
                let warmed_map = Arc::clone(&warmed);
                runtime.block_on(preconnect_backend(
                    addr.to_owned(),
                    tls_b,
                    sni_b,
                    0,
                    preconnect,
                    succ,
                    fail,
                ));
                if let Ok(mut m) = warmed_map.lock() {
                    m.insert(b.addr.to_owned(), Instant::now());
                }
            }
        }

        Ok(Self {
            server,
            lb,
            client_bind_to_ipv4: ipv4,
            client_bind_to_ipv6: ipv6,
            _pending: pending,
            queue_depth,
            hash_dos_counter,
        })
    }

    pub fn run(self) {
        self.server.run_forever();
    }

    pub fn queue_depth(&self) -> usize {
        self.queue_depth.load(Ordering::SeqCst)
    }

    pub fn hash_dos_count(&self) -> usize {
        self.hash_dos_counter.load(Ordering::SeqCst)
    }

    pub fn queue_handle(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.queue_depth)
    }

    pub fn hash_handle(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.hash_dos_counter)
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn rotate_ticket_key(ctx: *mut boring_sys::SSL_CTX) {
    let mut key = [0u8; 48];
    rand::thread_rng().fill_bytes(&mut key);
    unsafe {
        boring_sys::SSL_CTX_set_tlsext_ticket_keys(ctx, key.as_ptr().cast(), key.len());
    }
}

#[allow(clippy::too_many_arguments)]
async fn preconnect_backend_with_connector(
    connector: &Connector,
    addr: String,
    tls: bool,
    sni: String,
    group_key: u64,
    count: usize,
    success: Arc<AtomicUsize>,
    failure: Arc<AtomicUsize>,
) {
    let mut peer = HttpPeer::new(addr, tls, sni);
    peer.group_key = group_key;
    for _ in 0..count {
        match connector.get_http_session(&peer).await {
            Ok((sess, _)) => {
                success.fetch_add(1, Ordering::SeqCst);
                connector
                    .release_http_session(sess, &peer, Some(Duration::from_secs(30)))
                    .await;
            }
            Err(_) => {
                failure.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
    info!(
        target = "metrics",
        warmup_success = success.load(Ordering::SeqCst),
        warmup_failure = failure.load(Ordering::SeqCst)
    );
}

async fn preconnect_backend(
    addr: String,
    tls: bool,
    sni: String,
    group_key: u64,
    count: usize,
    success: Arc<AtomicUsize>,
    failure: Arc<AtomicUsize>,
) {
    let connector = Connector::new(None);
    preconnect_backend_with_connector(
        &connector, addr, tls, sni, group_key, count, success, failure,
    )
    .await;
}

pub async fn warm_up(
    addr: String,
    tls: bool,
    sni: String,
    group_key: u64,
    count: usize,
) -> (usize, usize) {
    let connector = Connector::new(None);
    warm_with_connector(&connector, addr, tls, sni, group_key, count).await
}

pub async fn warm_with_connector(
    connector: &Connector,
    addr: String,
    tls: bool,
    sni: String,
    group_key: u64,
    count: usize,
) -> (usize, usize) {
    let success = Arc::new(AtomicUsize::new(0));
    let failure = Arc::new(AtomicUsize::new(0));
    preconnect_backend_with_connector(
        connector,
        addr,
        tls,
        sni,
        group_key,
        count,
        Arc::clone(&success),
        Arc::clone(&failure),
    )
    .await;
    (
        success.load(Ordering::SeqCst),
        failure.load(Ordering::SeqCst),
    )
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
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};
    let filter = match EnvFilter::try_new(level) {
        Ok(f) => f,
        Err(_) => EnvFilter::new("info"),
    };

    if let Some(path) = file {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let name = path.file_name().unwrap_or_else(|| std::ffi::OsStr::new(""));
        let appender = tracing_appender::rolling::never(parent, name);
        let (writer, guard) = tracing_appender::non_blocking(appender);
        if json {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().with_writer(writer).json())
                .init();
        } else {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().with_writer(writer))
                .init();
        }
        Some(guard)
    } else {
        if json {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().json())
                .init();
        } else {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer())
                .init();
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
                "systemctl {action} failed for {name}"
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
            service.push_str(&format!("User={u}\n"));
        }
        if let Some(g) = &cli.group {
            service.push_str(&format!("Group={g}\n"));
        }
        service.push_str("Restart=always\n\n[Install]\nWantedBy=multi-user.target\n");
        let service_path = format!("/etc/systemd/system/{name}.service");
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
    let ca_key_str = ca_key
        .to_str()
        .ok_or_else(|| ProxErr::Other("invalid path".into()))?;
    let ca_cert_str = ca_cert
        .to_str()
        .ok_or_else(|| ProxErr::Other("invalid path".into()))?;
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
            ca_key_str,
            "-out",
            ca_cert_str,
        ])
        .status()
        .map_err(ProxErr::from)?;
    let srv_key = out.join("server.key");
    let srv_csr = out.join("server.csr");
    let srv_key_str = srv_key
        .to_str()
        .ok_or_else(|| ProxErr::Other("invalid path".into()))?;
    let srv_csr_str = srv_csr
        .to_str()
        .ok_or_else(|| ProxErr::Other("invalid path".into()))?;
    Command::new("openssl")
        .args([
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1",
            "-keyout",
            srv_key_str,
            "-out",
            srv_csr_str,
        ])
        .status()
        .map_err(ProxErr::from)?;
    let srv_cert = out.join("server.pem");
    let srv_cert_str = srv_cert
        .to_str()
        .ok_or_else(|| ProxErr::Other("invalid path".into()))?;
    Command::new("openssl")
        .args([
            "x509",
            "-req",
            "-days",
            "1",
            "-in",
            srv_csr_str,
            "-CA",
            ca_cert_str,
            "-CAkey",
            ca_key_str,
            "-CAcreateserial",
            "-copy_extensions",
            "copy",
            "-out",
            srv_cert_str,
        ])
        .status()
        .map_err(ProxErr::from)?;
    let cli_key = out.join("client.key");
    let cli_csr = out.join("client.csr");
    let cli_key_str = cli_key
        .to_str()
        .ok_or_else(|| ProxErr::Other("invalid path".into()))?;
    let cli_csr_str = cli_csr
        .to_str()
        .ok_or_else(|| ProxErr::Other("invalid path".into()))?;
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
            cli_key_str,
            "-out",
            cli_csr_str,
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
            cli_csr_str,
            "-CA",
            ca_cert_str,
            "-CAkey",
            ca_key_str,
            "-CAcreateserial",
            "-out",
            cli_cert
                .to_str()
                .ok_or_else(|| ProxErr::Other("invalid path".into()))?,
        ])
        .status()
        .map_err(ProxErr::from)?;
    println!("Generated mTLS materials under {}", out.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora::lb::discovery;
    use pingora::lb::selection::RoundRobin;
    use pingora::lb::{Backends, LoadBalancer};

    fn dummy_lb() -> Arc<LoadBalancer<RoundRobin>> {
        let set = BTreeSet::new();
        let discovery = discovery::Static::new(set);
        let backends = Backends::new(discovery);
        Arc::new(LoadBalancer::<RoundRobin>::from_backends(backends))
    }

    #[test]
    fn prefix_applied_when_enabled() {
        let p = build_prefix(Some("/api"), true, "v1");
        assert_eq!(p, "/api/v1");
    }

    #[test]
    fn prefix_unchanged_when_disabled() {
        let p = build_prefix(Some("/api"), false, "v1");
        assert_eq!(p, "v1");
    }

    #[test]
    fn hedging_respects_budget() {
        let metrics = Arc::new(Mutex::new(RouteMetrics::new(5)));
        let budget = Arc::new(Mutex::new(RetryBudget::new(2, 0.0)));
        let lb = LB {
            lb: dummy_lb(),
            origins: Vec::new(),
            endpoints: Vec::new(),
            base_prefix: None,
            prepend_base_prefix: false,
            metrics: Arc::clone(&metrics),
            hedge_threshold: Duration::from_millis(50),
            retry_budget: Arc::clone(&budget),
            backend_addrs: Vec::new(),
            backend_stats: Arc::new(Mutex::new(HashMap::new())),
            latency_limit: Duration::from_secs(1),
            error_limit: 1.0,
            cooldown: Duration::from_secs(0),
            pending: Arc::new(Semaphore::new(10)),
            queue_depth: Arc::new(AtomicUsize::new(0)),
            hash_dos_max_headers: 100,
            hash_dos_avg_len: 8,
            hash_dos_counter: Arc::new(AtomicUsize::new(0)),
            preconnect: 0,
            warmed: Arc::new(Mutex::new(HashMap::new())),
            warm_success: Arc::new(AtomicUsize::new(0)),
            warm_failure: Arc::new(AtomicUsize::new(0)),
            default_header_timeout_ms: None,
            default_body_timeout_ms: None,
        };
        {
            let mut m = metrics.lock().unwrap();
            for _ in 0..5 {
                m.record("/a", Duration::from_millis(100));
            }
        }
        assert!(lb.should_hedge("/a"));
        assert!(lb.should_hedge("/a"));
        assert!(!lb.should_hedge("/a"));
    }

    #[test]
    fn below_threshold_no_hedge() {
        let metrics = Arc::new(Mutex::new(RouteMetrics::new(5)));
        let budget = Arc::new(Mutex::new(RetryBudget::new(1, 0.0)));
        let lb = LB {
            lb: dummy_lb(),
            origins: Vec::new(),
            endpoints: Vec::new(),
            base_prefix: None,
            prepend_base_prefix: false,
            metrics: Arc::clone(&metrics),
            hedge_threshold: Duration::from_millis(200),
            retry_budget: budget,
            backend_addrs: Vec::new(),
            backend_stats: Arc::new(Mutex::new(HashMap::new())),
            latency_limit: Duration::from_secs(1),
            error_limit: 1.0,
            cooldown: Duration::from_secs(0),
            pending: Arc::new(Semaphore::new(10)),
            queue_depth: Arc::new(AtomicUsize::new(0)),
            hash_dos_max_headers: 100,
            hash_dos_avg_len: 8,
            hash_dos_counter: Arc::new(AtomicUsize::new(0)),
            preconnect: 0,
            warmed: Arc::new(Mutex::new(HashMap::new())),
            warm_success: Arc::new(AtomicUsize::new(0)),
            warm_failure: Arc::new(AtomicUsize::new(0)),
            default_header_timeout_ms: None,
            default_body_timeout_ms: None,
        };
        {
            let mut m = metrics.lock().unwrap();
            for _ in 0..5 {
                m.record("/b", Duration::from_millis(10));
            }
        }
        assert!(!lb.should_hedge("/b"));
    }

    #[test]
    fn slow_backend_ejected_and_recovers() {
        let lb = LB {
            lb: dummy_lb(),
            origins: Vec::new(),
            endpoints: Vec::new(),
            base_prefix: None,
            prepend_base_prefix: false,
            metrics: Arc::new(Mutex::new(RouteMetrics::new(1))),
            hedge_threshold: Duration::from_millis(10),
            retry_budget: Arc::new(Mutex::new(RetryBudget::new(1, 0.0))),
            backend_addrs: vec!["b1".to_owned()],
            backend_stats: Arc::new(Mutex::new(HashMap::new())),
            latency_limit: Duration::from_millis(50),
            error_limit: 1.0,
            cooldown: Duration::from_millis(10),
            pending: Arc::new(Semaphore::new(10)),
            queue_depth: Arc::new(AtomicUsize::new(0)),
            hash_dos_max_headers: 100,
            hash_dos_avg_len: 8,
            hash_dos_counter: Arc::new(AtomicUsize::new(0)),
            preconnect: 0,
            warmed: Arc::new(Mutex::new(HashMap::new())),
            warm_success: Arc::new(AtomicUsize::new(0)),
            warm_failure: Arc::new(AtomicUsize::new(0)),
            default_header_timeout_ms: None,
            default_body_timeout_ms: None,
        };
        lb.record_backend_result("b1", "/", Duration::from_millis(100), false);
        assert!(lb.backend_ejected("b1"));
        std::thread::sleep(Duration::from_millis(20));
        assert!(!lb.backend_ejected("b1"));
        let map = lb.backend_stats.lock().unwrap();
        let stats = map.get("b1").unwrap();
        assert_eq!(stats.latency_ejections, 1);
    }

    #[test]
    fn error_backend_ejected_and_recovers() {
        let lb = LB {
            lb: dummy_lb(),
            origins: Vec::new(),
            endpoints: Vec::new(),
            base_prefix: None,
            prepend_base_prefix: false,
            metrics: Arc::new(Mutex::new(RouteMetrics::new(1))),
            hedge_threshold: Duration::from_millis(10),
            retry_budget: Arc::new(Mutex::new(RetryBudget::new(1, 0.0))),
            backend_addrs: vec!["b1".to_owned()],
            backend_stats: Arc::new(Mutex::new(HashMap::new())),
            latency_limit: Duration::from_secs(1),
            error_limit: 0.5,
            cooldown: Duration::from_millis(10),
            pending: Arc::new(Semaphore::new(10)),
            queue_depth: Arc::new(AtomicUsize::new(0)),
            hash_dos_max_headers: 100,
            hash_dos_avg_len: 8,
            hash_dos_counter: Arc::new(AtomicUsize::new(0)),
            preconnect: 0,
            warmed: Arc::new(Mutex::new(HashMap::new())),
            warm_success: Arc::new(AtomicUsize::new(0)),
            warm_failure: Arc::new(AtomicUsize::new(0)),
            default_header_timeout_ms: None,
            default_body_timeout_ms: None,
        };
        lb.record_backend_result("b1", "/", Duration::from_millis(10), true);
        assert!(lb.backend_ejected("b1"));
        std::thread::sleep(Duration::from_millis(20));
        assert!(!lb.backend_ejected("b1"));
        let map = lb.backend_stats.lock().unwrap();
        let stats = map.get("b1").unwrap();
        assert_eq!(stats.error_ejections, 1);
    }

    #[test]
    fn aimd_concurrency_tracking() {
        let lb = LB {
            lb: dummy_lb(),
            origins: Vec::new(),
            endpoints: Vec::new(),
            base_prefix: None,
            prepend_base_prefix: false,
            metrics: Arc::new(Mutex::new(RouteMetrics::new(1))),
            hedge_threshold: Duration::from_millis(10),
            retry_budget: Arc::new(Mutex::new(RetryBudget::new(1, 0.0))),
            backend_addrs: vec!["b1".to_owned()],
            backend_stats: Arc::new(Mutex::new(HashMap::new())),
            latency_limit: Duration::from_secs(1),
            error_limit: 1.0,
            cooldown: Duration::from_millis(10),
            pending: Arc::new(Semaphore::new(10)),
            queue_depth: Arc::new(AtomicUsize::new(0)),
            hash_dos_max_headers: 100,
            hash_dos_avg_len: 8,
            hash_dos_counter: Arc::new(AtomicUsize::new(0)),
            preconnect: 0,
            warmed: Arc::new(Mutex::new(HashMap::new())),
            warm_success: Arc::new(AtomicUsize::new(0)),
            warm_failure: Arc::new(AtomicUsize::new(0)),
            default_header_timeout_ms: None,
            default_body_timeout_ms: None,
        };
        assert!(lb.acquire_backend("b1"));
        lb.record_backend_result("b1", "/", Duration::from_millis(5), false);
        {
            let map = lb.backend_stats.lock().unwrap();
            let stats = map.get("b1").unwrap();
            assert_eq!(stats.limit, 2);
            assert!(stats.latency.short() > 0.0);
        }
        assert!(lb.acquire_backend("b1"));
        assert!(lb.acquire_backend("b1"));
        assert!(!lb.acquire_backend("b1"));
        lb.record_backend_result("b1", "/", Duration::from_millis(5), false);
        lb.record_backend_result("b1", "/", Duration::from_millis(5), true);
        {
            let map = lb.backend_stats.lock().unwrap();
            let stats = map.get("b1").unwrap();
            assert_eq!(stats.limit, 1);
            assert_eq!(stats.inflight, 0);
        }
        assert!(lb.acquire_backend("b1"));
        assert!(!lb.acquire_backend("b1"));
    }

    #[test]
    fn queue_overflow_returns_503() {
        let lb = LB {
            lb: dummy_lb(),
            origins: Vec::new(),
            endpoints: Vec::new(),
            base_prefix: None,
            prepend_base_prefix: false,
            metrics: Arc::new(Mutex::new(RouteMetrics::new(1))),
            hedge_threshold: Duration::from_millis(10),
            retry_budget: Arc::new(Mutex::new(RetryBudget::new(1, 0.0))),
            backend_addrs: Vec::new(),
            backend_stats: Arc::new(Mutex::new(HashMap::new())),
            latency_limit: Duration::from_secs(1),
            error_limit: 1.0,
            cooldown: Duration::from_secs(0),
            pending: Arc::new(Semaphore::new(1)),
            queue_depth: Arc::new(AtomicUsize::new(0)),
            hash_dos_max_headers: 100,
            hash_dos_avg_len: 8,
            hash_dos_counter: Arc::new(AtomicUsize::new(0)),
            preconnect: 0,
            warmed: Arc::new(Mutex::new(HashMap::new())),
            warm_success: Arc::new(AtomicUsize::new(0)),
            warm_failure: Arc::new(AtomicUsize::new(0)),
            default_header_timeout_ms: None,
            default_body_timeout_ms: None,
        };
        let permit = lb.enqueue().unwrap();
        assert_eq!(lb.queue_depth.load(Ordering::SeqCst), 1);
        let resp = lb.enqueue().err().unwrap();
        assert_eq!(resp.status.as_u16(), 503);
        assert_eq!(
            resp.headers.get("Retry-After").unwrap().to_str().unwrap(),
            "1"
        );
        drop(permit);
        assert_eq!(lb.queue_depth.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn detects_header_hash_dos() {
        let lb = LB {
            lb: dummy_lb(),
            origins: Vec::new(),
            endpoints: Vec::new(),
            base_prefix: None,
            prepend_base_prefix: false,
            metrics: Arc::new(Mutex::new(RouteMetrics::new(1))),
            hedge_threshold: Duration::from_millis(10),
            retry_budget: Arc::new(Mutex::new(RetryBudget::new(1, 0.0))),
            backend_addrs: Vec::new(),
            backend_stats: Arc::new(Mutex::new(HashMap::new())),
            latency_limit: Duration::from_secs(1),
            error_limit: 1.0,
            cooldown: Duration::from_secs(0),
            pending: Arc::new(Semaphore::new(1)),
            queue_depth: Arc::new(AtomicUsize::new(0)),
            hash_dos_max_headers: 10,
            hash_dos_avg_len: 8,
            hash_dos_counter: Arc::new(AtomicUsize::new(0)),
            preconnect: 0,
            warmed: Arc::new(Mutex::new(HashMap::new())),
            warm_success: Arc::new(AtomicUsize::new(0)),
            warm_failure: Arc::new(AtomicUsize::new(0)),
            default_header_timeout_ms: None,
            default_body_timeout_ms: None,
        };
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        for i in 0..20 {
            let name = format!("x{i}");
            req.insert_header(name, "v").unwrap();
        }
        assert!(lb.detect_header_dos(&req));
        assert_eq!(lb.hash_dos_counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn normal_headers_pass() {
        let lb = LB {
            lb: dummy_lb(),
            origins: Vec::new(),
            endpoints: Vec::new(),
            base_prefix: None,
            prepend_base_prefix: false,
            metrics: Arc::new(Mutex::new(RouteMetrics::new(1))),
            hedge_threshold: Duration::from_millis(10),
            retry_budget: Arc::new(Mutex::new(RetryBudget::new(1, 0.0))),
            backend_addrs: Vec::new(),
            backend_stats: Arc::new(Mutex::new(HashMap::new())),
            latency_limit: Duration::from_secs(1),
            error_limit: 1.0,
            cooldown: Duration::from_secs(0),
            pending: Arc::new(Semaphore::new(1)),
            queue_depth: Arc::new(AtomicUsize::new(0)),
            hash_dos_max_headers: 10,
            hash_dos_avg_len: 8,
            hash_dos_counter: Arc::new(AtomicUsize::new(0)),
            preconnect: 0,
            warmed: Arc::new(Mutex::new(HashMap::new())),
            warm_success: Arc::new(AtomicUsize::new(0)),
            warm_failure: Arc::new(AtomicUsize::new(0)),
            default_header_timeout_ms: None,
            default_body_timeout_ms: None,
        };
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("X-Test", "ok").unwrap();
        assert!(!lb.detect_header_dos(&req));
        assert_eq!(lb.hash_dos_counter.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn records_metrics_and_ejections() {
        REQUEST_DURATION_SECONDS.reset();
        UPSTREAM_INFLIGHT.reset();
        EJECTIONS_TOTAL.reset();
        let lb = LB {
            lb: dummy_lb(),
            origins: Vec::new(),
            endpoints: Vec::new(),
            base_prefix: None,
            prepend_base_prefix: false,
            metrics: Arc::new(Mutex::new(RouteMetrics::new(1))),
            hedge_threshold: Duration::from_millis(10),
            retry_budget: Arc::new(Mutex::new(RetryBudget::new(1, 0.0))),
            backend_addrs: Vec::new(),
            backend_stats: Arc::new(Mutex::new(HashMap::new())),
            latency_limit: Duration::from_millis(5),
            error_limit: 1.0,
            cooldown: Duration::from_secs(0),
            pending: Arc::new(Semaphore::new(10)),
            queue_depth: Arc::new(AtomicUsize::new(0)),
            hash_dos_max_headers: 10,
            hash_dos_avg_len: 8,
            hash_dos_counter: Arc::new(AtomicUsize::new(0)),
            preconnect: 0,
            warmed: Arc::new(Mutex::new(HashMap::new())),
            warm_success: Arc::new(AtomicUsize::new(0)),
            warm_failure: Arc::new(AtomicUsize::new(0)),
            default_header_timeout_ms: None,
            default_body_timeout_ms: None,
        };
        assert!(lb.acquire_backend("b1"));
        lb.record_backend_result("b1", "/", Duration::from_millis(1), false);
        assert!(lb.acquire_backend("b1"));
        lb.record_backend_result("b1", "/", Duration::from_millis(100), false);
        assert!(
            REQUEST_DURATION_SECONDS
                .with_label_values(&["b1"])
                .get_sample_count()
                >= 2
        );
        assert_eq!(UPSTREAM_INFLIGHT.with_label_values(&["b1"]).get(), 0);
        assert_eq!(
            EJECTIONS_TOTAL.with_label_values(&["b1", "latency"]).get(),
            1
        );
    }

    #[test]
    fn hedging_updates_gauges() {
        RETRY_BUDGET.set(2.0);
        HEDGE_INFLIGHT.set(0);
        let metrics = Arc::new(Mutex::new(RouteMetrics::new(5)));
        {
            let mut m = metrics.lock().unwrap();
            m.record("/a", Duration::from_millis(100));
            m.record("/a", Duration::from_millis(100));
            m.record("/a", Duration::from_millis(100));
        }
        let lb = LB {
            lb: dummy_lb(),
            origins: Vec::new(),
            endpoints: Vec::new(),
            base_prefix: None,
            prepend_base_prefix: false,
            metrics: Arc::clone(&metrics),
            hedge_threshold: Duration::from_millis(50),
            retry_budget: Arc::new(Mutex::new(RetryBudget::new(2, 0.0))),
            backend_addrs: Vec::new(),
            backend_stats: Arc::new(Mutex::new(HashMap::new())),
            latency_limit: Duration::from_secs(1),
            error_limit: 1.0,
            cooldown: Duration::from_secs(0),
            pending: Arc::new(Semaphore::new(10)),
            queue_depth: Arc::new(AtomicUsize::new(0)),
            hash_dos_max_headers: 10,
            hash_dos_avg_len: 8,
            hash_dos_counter: Arc::new(AtomicUsize::new(0)),
            preconnect: 0,
            warmed: Arc::new(Mutex::new(HashMap::new())),
            warm_success: Arc::new(AtomicUsize::new(0)),
            warm_failure: Arc::new(AtomicUsize::new(0)),
            default_header_timeout_ms: None,
            default_body_timeout_ms: None,
        };
        let hedged = lb.should_hedge("/a");
        if hedged {
            HEDGE_INFLIGHT.inc();
        }
        assert!(hedged);
        assert_eq!(RETRY_BUDGET.get(), 1.0);
        assert_eq!(HEDGE_INFLIGHT.get(), 1);
        HEDGE_INFLIGHT.dec();
    }

    #[tokio::test]
    async fn logs_access_fields() {
        use tracing_subscriber::fmt::MakeWriter;
        use tracing_subscriber::{Registry, fmt, prelude::*};
        struct TestWriter {
            buf: Arc<Mutex<Vec<u8>>>,
        }
        impl<'a> MakeWriter<'a> for TestWriter {
            type Writer = TestGuard;
            fn make_writer(&'a self) -> Self::Writer {
                TestGuard {
                    buf: Arc::clone(&self.buf),
                }
            }
        }
        struct TestGuard {
            buf: Arc<Mutex<Vec<u8>>>,
        }
        impl std::io::Write for TestGuard {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                self.buf.lock().unwrap().write(data)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buf = Arc::new(Mutex::new(Vec::new()));
        let make = TestWriter {
            buf: Arc::clone(&buf),
        };
        let subscriber = Registry::default().with(fmt::layer().json().with_writer(make));
        let _guard = tracing::subscriber::set_default(subscriber);
        let trace = trace::generate_context();
        let ctx = Ctx {
            authority: String::new(),
            start: Instant::now(),
            route: "/test".to_owned(),
            path_kind: "endpoint".to_owned(),
            backend: "127.0.0.1:80".to_owned(),
            peer_ip: "1.2.3.4".to_owned(),
            sni: "example.com".to_owned(),
            tls_proto: "TLSv1.3".to_owned(),
            tls_cipher: "TLS_AES_128_GCM_SHA256".to_owned(),
            pending: None,
            hedged: false,
            trace,
            trace_kind: trace::TraceHeader::Both,
        };
        let mut req = RequestHeader::build("GET", b"/path", None).unwrap();
        req.insert_header("Host", "example.com").unwrap();
        req.insert_header("User-Agent", "test-agent").unwrap();
        log_access(&ctx, &req, 200);
        drop(_guard);
        let mut data = Vec::new();
        std::mem::swap(&mut data, &mut *buf.lock().unwrap());
        let log = String::from_utf8(data).unwrap();
        let v: serde_json::Value = serde_json::from_str(log.trim()).unwrap();
        let f = &v["fields"];
        assert_eq!(f["route"], "/test");
        assert_eq!(f["path_kind"], "endpoint");
        assert_eq!(f["backend"], "127.0.0.1:80");
        assert_eq!(f["peer_ip"], "1.2.3.4");
        assert_eq!(f["sni"], "example.com");
        assert_eq!(f["tls_proto"], "TLSv1.3");
        assert_eq!(f["tls_cipher"], "TLS_AES_128_GCM_SHA256");
        assert_eq!(f["method"], "GET");
        assert_eq!(f["uri"], "/path");
        assert_eq!(f["host"], "example.com");
        assert_eq!(f["user_agent"], "test-agent");
    }
}
