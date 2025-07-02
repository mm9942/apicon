use crate::error::{ProxErr, ProxResult};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tokio::runtime::Runtime;

#[derive(Clone, Debug, serde::Deserialize)]
pub struct WebServerConfig {
    pub listener: String,
    pub dir: PathBuf,
}

pub struct WebServer {
    addr: SocketAddr,
    root: PathBuf,
}

impl WebServer {
    pub fn new(cfg: &WebServerConfig) -> ProxResult<Self> {
        let addr: SocketAddr = cfg
            .listener
            .parse()
            .map_err(|e| ProxErr::Other(format!("invalid listen {}: {e}", cfg.listener)))?;
        Ok(Self {
            addr,
            root: cfg.dir.clone(),
        })
    }

    pub fn run(self) {
        let rt = Runtime::new().expect("tokio runtime");
        rt.block_on(async move {
            let make = make_service_fn(move |_| {
                let root = self.root.clone();
                async move {
                    Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                        let base = root.clone();
                        async move { serve_file(req, &base).await }
                    }))
                }
            });
            let _ = Server::bind(&self.addr).serve(make).await;
        });
    }
}

async fn serve_file(req: Request<Body>, root: &Path) -> Result<Response<Body>, Infallible> {
    let mut path = req.uri().path().trim_start_matches('/').to_string();
    if path.is_empty() {
        path = "index.html".into();
    }
    let full = root.join(path);
    match tokio::fs::read(&full).await {
        Ok(contents) => Ok(Response::new(Body::from(contents))),
        Err(_) => Ok(Response::builder()
            .status(404)
            .body(Body::from("Not Found"))
            .unwrap()),
    }
}
