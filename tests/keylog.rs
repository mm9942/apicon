use pingora_core::server::configuration::ServerConf;
use tempfile::NamedTempFile;

#[test]
fn keylog_env_controls_config() {
    unsafe {
        std::env::remove_var("PINGORA_KEYLOG");
        std::env::remove_var("SSLKEYLOGFILE");
    }
    let mut sc = ServerConf::default();
    apicon::configure_keylog(&mut sc);
    assert!(!sc.upstream_debug_ssl_keylog);
    assert!(std::env::var("SSLKEYLOGFILE").is_err());

    let keylog = NamedTempFile::new().unwrap();
    let keylog_path = keylog.path().to_str().unwrap().to_string();
    unsafe {
        std::env::set_var("PINGORA_KEYLOG", &keylog_path);
    }
    let mut sc2 = ServerConf::default();
    apicon::configure_keylog(&mut sc2);
    assert!(sc2.upstream_debug_ssl_keylog);
    assert_eq!(std::env::var("SSLKEYLOGFILE").unwrap(), keylog_path);
    unsafe {
        std::env::remove_var("PINGORA_KEYLOG");
        std::env::remove_var("SSLKEYLOGFILE");
    }
}
