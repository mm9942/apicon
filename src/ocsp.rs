use chrono::{NaiveDateTime, Utc};
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tempfile::NamedTempFile;
use tracing::info;

const SOFT_EXPIRY: Duration = Duration::from_secs(3600);

struct Entry {
    resp: Vec<u8>,
    next: Instant,
}

pub struct OcspCache {
    ctx: *mut boring_sys::SSL_CTX,
    cert: PathBuf,
    issuer: PathBuf,
    responders: Vec<String>,
    state: Mutex<Option<Entry>>,
}

unsafe impl Send for OcspCache {}
unsafe impl Sync for OcspCache {}

impl OcspCache {
    pub fn new(ctx: *mut boring_sys::SSL_CTX, cert: PathBuf) -> Option<Arc<Self>> {
        let responders = responders_from_cert(&cert)?;
        let pem = std::fs::read(&cert).ok()?;
        let stack = boring::x509::X509::stack_from_pem(&pem).ok()?;
        if stack.len() < 2 {
            return None;
        }
        let mut iter = stack.into_iter();
        let _server = iter.next()?;
        let issuer = iter.next()?;
        let pem_issuer = issuer.to_pem().ok()?;
        let mut tmp = NamedTempFile::new().ok()?;
        tmp.write_all(&pem_issuer).ok()?;
        let issuer_path = tmp.into_temp_path().to_path_buf();
        let cache = Arc::new(OcspCache {
            ctx,
            cert,
            issuer: issuer_path,
            responders,
            state: Mutex::new(None),
        });
        let background = Arc::clone(&cache);
        std::thread::spawn(move || {
            background.refresh();
            background.refresh_loop();
        });
        Some(cache)
    }

    fn refresh_loop(self: Arc<Self>) {
        loop {
            let wait = {
                let guard = self.state.lock().unwrap();
                if let Some(entry) = guard.as_ref() {
                    let now = Instant::now();
                    if entry.next > now {
                        let total = entry.next - now;
                        total - total / 10
                    } else {
                        Duration::from_secs(300)
                    }
                } else {
                    Duration::from_secs(300)
                }
            };
            std::thread::sleep(wait);
            self.refresh();
        }
    }

    fn refresh(&self) {
        if let Some((resp, next)) = fetch_any(&self.cert, &self.issuer, &self.responders) {
            unsafe {
                boring_sys::SSL_CTX_set_ocsp_response(self.ctx, resp.as_ptr(), resp.len());
            }
            let mut guard = self.state.lock().unwrap();
            *guard = Some(Entry { resp, next });
            info!(target = "metrics", ocsp_refresh_success = true);
        } else {
            info!(target = "metrics", ocsp_refresh_fail = true);
        }
    }

    pub fn is_stale(&self) -> bool {
        let guard = self.state.lock().unwrap();
        guard
            .as_ref()
            .map(|e| Instant::now() > e.next)
            .unwrap_or(true)
    }

    pub fn spawn_refresh(self: &Arc<Self>) {
        let arc = Arc::clone(self);
        std::thread::spawn(move || arc.refresh());
    }

    pub fn soft_response(&self) -> Option<Vec<u8>> {
        let guard = self.state.lock().unwrap();
        guard.as_ref().and_then(|e| {
            let now = Instant::now();
            if now <= e.next + SOFT_EXPIRY {
                Some(e.resp.to_vec())
            } else {
                None
            }
        })
    }
}

fn responders_from_cert(cert: &Path) -> Option<Vec<String>> {
    let output = Command::new("openssl")
        .arg("x509")
        .arg("-in")
        .arg(cert)
        .arg("-noout")
        .arg("-ocsp_uri")
        .output()
        .ok()?;
    let text = String::from_utf8(output.stdout).ok()?;
    let list: Vec<String> = text
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    if list.is_empty() { None } else { Some(list) }
}

fn fetch_any(cert: &Path, issuer: &Path, responders: &[String]) -> Option<(Vec<u8>, Instant)> {
    for uri in responders {
        if let Some(v) = fetch_single(cert, issuer, uri) {
            return Some(v);
        }
    }
    None
}

fn fetch_single(cert: &Path, issuer: &Path, uri: &str) -> Option<(Vec<u8>, Instant)> {
    let der_out = Command::new("openssl")
        .arg("ocsp")
        .arg("-issuer")
        .arg(issuer)
        .arg("-cert")
        .arg(cert)
        .arg("-url")
        .arg(uri)
        .arg("-no_nonce")
        .arg("-resp_der")
        .output()
        .ok()?;
    if !der_out.status.success() {
        return None;
    }
    let text_out = Command::new("openssl")
        .arg("ocsp")
        .arg("-issuer")
        .arg(issuer)
        .arg("-cert")
        .arg(cert)
        .arg("-url")
        .arg(uri)
        .arg("-no_nonce")
        .arg("-resp_text")
        .output()
        .ok()?;
    if !text_out.status.success() {
        return None;
    }
    let text = String::from_utf8(text_out.stdout).ok()?;
    let line = text
        .lines()
        .find(|l| l.trim_start().starts_with("Next Update:"))?;
    let (_, ts) = line.split_once(':')?;
    let dt = NaiveDateTime::parse_from_str(ts.trim(), "%b %e %H:%M:%S %Y GMT").ok()?;
    let now = Utc::now().naive_utc();
    let dur = dt - now;
    let next = Instant::now() + dur.to_std().ok()?;
    Some((der_out.stdout, next))
}
