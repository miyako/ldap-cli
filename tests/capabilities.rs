use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn capabilities_is_offline_and_does_not_consume_credentials() {
    let output = Command::new(env!("CARGO_BIN_EXE_ldap"))
        .env(
            "LDAP_CONFIG",
            "/nonexistent/ldap-cli-capabilities/config.toml",
        )
        .args([
            "--profile",
            "must-not-load",
            "--password-stdin",
            "--uri",
            "ldaps://invalid.invalid",
            "capabilities",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema"], 1);
    for feature in ["explicit-credentials-sasl", "channel-binding-require"] {
        assert!(
            value["features"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f == feature)
        );
    }
}

#[test]
fn strict_simple_bind_is_refused_before_network_or_password() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ldap"))
        .args([
            "--uri",
            "ldaps://invalid.invalid",
            "--mech",
            "simple",
            "--bind-dn",
            "cn=alice",
            "--password-stdin",
            "--channel-binding",
            "require",
            "whoami",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Not supplying a password must still produce an immediate policy error.
    child.stdin.take().unwrap().flush().unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("CBT-capable"));
}

#[test]
fn nul_password_cannot_authenticate_using_a_truncated_prefix() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ldap"))
        .args([
            "--uri",
            "ldaps://invalid.invalid",
            "--mech",
            "gssapi",
            "--user",
            "alice@EXAMPLE.TEST",
            "--password-stdin",
            "--channel-binding",
            "require",
            "whoami",
        ])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"prefix\0suffix\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("NUL"));
}
