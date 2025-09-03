use apicon::FileConfig;

#[test]
fn endpoint_timeouts_none_by_default() {
    let toml = "[[endpoint]]\nprefix = \"/a\"\naddr = \"127.0.0.1:80\"\n";
    let cfg: FileConfig = toml::from_str(toml).unwrap();
    let ep = &cfg.endpoint[0];
    assert!(ep.header_timeout_ms.is_none());
    assert!(ep.body_timeout_ms.is_none());
}

#[test]
fn global_timeout_defaults() {
    let toml = "default_header_timeout_ms = 10\ndefault_body_timeout_ms = 20\n[[endpoint]]\nprefix = \"/b\"\naddr = \"127.0.0.1:80\"\n";
    let cfg: FileConfig = toml::from_str(toml).unwrap();
    assert_eq!(cfg.default_header_timeout_ms, Some(10));
    assert_eq!(cfg.default_body_timeout_ms, Some(20));
    let ep = &cfg.endpoint[0];
    assert!(ep.header_timeout_ms.is_none());
    assert!(ep.body_timeout_ms.is_none());
}

#[test]
fn endpoint_timeout_override() {
    let toml = "default_header_timeout_ms = 10\ndefault_body_timeout_ms = 20\n[[endpoint]]\nprefix = \"/c\"\naddr = \"127.0.0.1:80\"\nheader_timeout_ms = 30\nbody_timeout_ms = 40\n";
    let cfg: FileConfig = toml::from_str(toml).unwrap();
    assert_eq!(cfg.default_header_timeout_ms, Some(10));
    assert_eq!(cfg.default_body_timeout_ms, Some(20));
    let ep = &cfg.endpoint[0];
    assert_eq!(ep.header_timeout_ms, Some(30));
    assert_eq!(ep.body_timeout_ms, Some(40));
}
