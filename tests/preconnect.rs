use apicon::warm_with_connector;
use pingora_core::{
    connectors::http::Connector,
    upstreams::peer::HttpPeer,
};
use std::time::Instant;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[tokio::test]
async fn preconnect_reduces_first_request_latency() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await.unwrap();
            let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            let _ = sock.write_all(resp).await;
        }
    });

    let connector = Connector::new(None);

    let mut peer_base = HttpPeer::new(addr, false, String::new());
    peer_base.group_key = 1;
    let start = Instant::now();
    let (sess, _) = connector.get_http_session(&peer_base).await.unwrap();
    let base_dur = start.elapsed();
    connector.release_http_session(sess, &peer_base, None).await;

    let (_s, _f) =
        warm_with_connector(&connector, addr.to_string(), false, String::new(), 2, 1).await;

    let mut peer_pre = HttpPeer::new(addr, false, String::new());
    peer_pre.group_key = 2;
    let start2 = Instant::now();
    let (sess2, _reused) = connector.get_http_session(&peer_pre).await.unwrap();
    let pre_dur = start2.elapsed();
    connector.release_http_session(sess2, &peer_pre, None).await;

    assert!(pre_dur < base_dur);
}
