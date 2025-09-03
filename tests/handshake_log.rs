use boring::ssl::{
    SslAcceptor, SslFiletype, SslMethod, SslOptions, SslSessionCacheMode, SslVerifyMode,
};
use rcgen::generate_simple_self_signed;
use std::{
    io::Write,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tempfile::NamedTempFile;
use tracing::info;

#[tokio::test]
async fn handshake_logs_ticket_and_ocsp_status() {
    let cert = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    let mut cert_file = NamedTempFile::new().unwrap();
    cert_file.write_all(cert_pem.as_bytes()).unwrap();
    let mut key_file = NamedTempFile::new().unwrap();
    key_file.write_all(key_pem.as_bytes()).unwrap();
    let cert_path = cert_file.path().to_str().unwrap();
    let key_path = key_file.path().to_str().unwrap();

    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file(key_path, SslFiletype::PEM)
        .unwrap();
    builder.set_certificate_chain_file(cert_path).unwrap();
    builder.clear_options(SslOptions::NO_TICKET);
    builder.set_session_cache_mode(SslSessionCacheMode::SERVER | SslSessionCacheMode::NO_INTERNAL);
    let ctx_ptr = builder.as_ptr();
    apicon::rotate_ticket_key(ctx_ptr);

    let ocsp = Arc::new(AtomicBool::new(false));
    let o1 = Arc::clone(&ocsp);
    builder.set_new_session_callback(move |ssl, _| {
        o1.store(ssl.ocsp_status().is_some(), Ordering::SeqCst);
        info!(
            target = "handshake",
            session_ticket = true,
            ocsp_stapled = ssl.ocsp_status().is_some()
        );
    });
    let acceptor = builder.build();

    let (client, server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        let ctx = boring::ssl::SslContext::builder(SslMethod::tls())
            .unwrap()
            .build();
        let mut ssl = boring::ssl::Ssl::new(&ctx).unwrap();
        ssl.set_verify(SslVerifyMode::NONE);
        ssl.set_hostname("localhost").unwrap();
        let mut stream = pingora_core::protocols::tls::SslStream::new(ssl, client).unwrap();
        let _ = stream.connect().await;
    });

    let stream = pingora_core::protocols::tls::server::handshake(&acceptor, server)
        .await
        .unwrap();
    drop(stream);
    assert!(!ocsp.load(Ordering::SeqCst));
}
