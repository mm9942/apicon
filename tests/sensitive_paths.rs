use apicon::is_sensitive_path;

#[test]
fn detect_sensitive_paths() {
    let cases = [
        "/public/aws_credentials.php",
        "/public/awscredentials.php",
        "/public/credentials.php",
        "/public/secrets.php",
        "/public/config/aws_credentials.php",
        "/public/config/awscredentials.php",
        "/public/config/credentials.php",
        "/public/config/secrets.php",
        "/PUBLIC/CONFIG/SECRETS.PHP",
    ];
    for p in cases {
        assert!(is_sensitive_path(p));
    }
    assert!(!is_sensitive_path("/public/not.php"));
    assert!(!is_sensitive_path("/other/secrets.php"));
}
