use hyper::{
    service::{make_service_fn, service_fn},
    Body, Response, Server,
};
use nix::{
    libc,
    sys::signal::{kill, Signal},
    unistd::Pid,
};
use rcgen::generate_simple_self_signed;
use std::{
    io::Write,
    net::SocketAddr,
    os::unix::process::CommandExt,
    process::{Command, Stdio},
};
use tempfile::NamedTempFile;
use tokio::time::{Duration, sleep};

async fn run_backend(port: u16) {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let make_svc = make_service_fn(|_| async {
        Ok::<_, hyper::Error>(service_fn(|_| async {
            Ok::<_, hyper::Error>(Response::new(Body::from("ok")))
        }))
    });
    Server::bind(&addr).serve(make_svc).await.unwrap();
}

#[tokio::test]
async fn reload_serves_requests_during_upgrade() {
    let backend_port = 18080;
    tokio::spawn(run_backend(backend_port));

    let cert = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let mut cert_file = NamedTempFile::new().unwrap();
    cert_file.write_all(cert.cert.pem().as_bytes()).unwrap();
    let mut key_file = NamedTempFile::new().unwrap();
    key_file
        .write_all(cert.key_pair.serialize_pem().as_bytes())
        .unwrap();
    let mut cfg_file = NamedTempFile::new().unwrap();
    writeln!(
        cfg_file,
        "listener = \"127.0.0.1:8443\"\ncert = \"{}\"\nkey = \"{}\"\n[[lb_backends]]\naddr = \"127.0.0.1:{}\"\ntls=false\n",
        cert_file.path().display(),
        key_file.path().display(),
        backend_port
    )
    .unwrap();
    let config_path = cfg_file.path();

    let bin = match std::env::var("CARGO_BIN_EXE_apicon") {
        Ok(p) => p,
        Err(_) => return,
    };
    let mut cmd = Command::new(bin);
    cmd.arg("--config").arg(config_path);
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    unsafe {
        cmd.pre_exec(|| {
            libc::setpgid(0, 0);
            Ok(())
        });
    }
    let mut child = cmd.spawn().unwrap();

    sleep(Duration::from_secs(1)).await;

    let status = tokio::task::spawn_blocking(|| {
        Command::new("curl")
            .arg("-sk")
            .arg("https://127.0.0.1:8443/")
            .status()
    })
    .await
    .unwrap()
    .unwrap();
    assert!(status.success());

    kill(Pid::from_raw(child.id() as i32), Signal::SIGHUP).unwrap();
    sleep(Duration::from_secs(1)).await;

    let status2 = tokio::task::spawn_blocking(|| {
        Command::new("curl")
            .arg("-sk")
            .arg("https://127.0.0.1:8443/")
            .status()
    })
    .await
    .unwrap()
    .unwrap();
    assert!(status2.success());

    kill(Pid::from_raw(-(child.id() as i32)), Signal::SIGTERM).ok();
    let _ = child.wait();
}
