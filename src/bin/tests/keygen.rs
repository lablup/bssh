use super::*;
use clap::CommandFactory;
use tempfile::tempdir;

#[test]
fn test_cli_parsing() {
    // Verify CLI structure is valid
    Cli::command().debug_assert();

    let help = Cli::command().render_long_help().to_string();
    for internal_reference in ["issue #", "PR #", "/issues/", "/pull/"] {
        assert!(
            !help.contains(internal_reference),
            "help contains internal tracking reference {internal_reference:?}"
        );
    }
}

#[test]
fn test_cli_defaults() {
    let cli = Cli::try_parse_from(["bssh-keygen"]).unwrap();
    assert_eq!(cli.key_type, "ed25519");
    assert_eq!(cli.bits, 4096);
    assert!(cli.output.is_none());
    assert!(cli.comment.is_none());
    assert!(!cli.yes);
    assert!(!cli.quiet);
}

#[test]
fn test_cli_ed25519() {
    let cli = Cli::try_parse_from(["bssh-keygen", "-t", "ed25519"]).unwrap();
    assert_eq!(cli.key_type, "ed25519");
}

#[test]
fn test_cli_rsa() {
    let cli = Cli::try_parse_from(["bssh-keygen", "-t", "rsa", "-b", "2048"]).unwrap();
    assert_eq!(cli.key_type, "rsa");
    assert_eq!(cli.bits, 2048);
}

#[test]
fn test_cli_output_file() {
    let cli = Cli::try_parse_from(["bssh-keygen", "-f", "/tmp/my_key"]).unwrap();
    assert_eq!(cli.output, Some(PathBuf::from("/tmp/my_key")));
}

#[test]
fn test_cli_comment() {
    let cli = Cli::try_parse_from(["bssh-keygen", "-C", "user@host"]).unwrap();
    assert_eq!(cli.comment, Some("user@host".to_string()));
}

#[test]
fn test_cli_flags() {
    let cli = Cli::try_parse_from(["bssh-keygen", "-y", "-q"]).unwrap();
    assert!(cli.yes);
    assert!(cli.quiet);
}

#[test]
fn test_cli_verbose() {
    let cli = Cli::try_parse_from(["bssh-keygen", "-vvv"]).unwrap();
    assert_eq!(cli.verbose, 3);
}

#[test]
fn test_cli_full_options() {
    let cli = Cli::try_parse_from([
        "bssh-keygen",
        "-t",
        "rsa",
        "-b",
        "4096",
        "-f",
        "/tmp/test_key",
        "-C",
        "test@example.com",
        "-y",
        "-v",
    ])
    .unwrap();

    assert_eq!(cli.key_type, "rsa");
    assert_eq!(cli.bits, 4096);
    assert_eq!(cli.output, Some(PathBuf::from("/tmp/test_key")));
    assert_eq!(cli.comment, Some("test@example.com".to_string()));
    assert!(cli.yes);
    assert!(!cli.quiet);
    assert_eq!(cli.verbose, 1);
}

#[test]
fn test_cli_long_options() {
    let cli = Cli::try_parse_from([
        "bssh-keygen",
        "--type",
        "ed25519",
        "--file",
        "/tmp/key",
        "--comment",
        "my key",
        "--yes",
        "--quiet",
    ])
    .unwrap();

    assert_eq!(cli.key_type, "ed25519");
    assert_eq!(cli.output, Some(PathBuf::from("/tmp/key")));
    assert_eq!(cli.comment, Some("my key".to_string()));
    assert!(cli.yes);
    assert!(cli.quiet);
}

#[test]
fn test_create_ssh_directory() {
    let temp_dir = tempdir().unwrap();
    let ssh_dir = temp_dir.path().join(".ssh");

    let result = create_ssh_directory(&ssh_dir);
    assert!(result.is_ok());
    assert!(ssh_dir.exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(&ssh_dir).unwrap();
        let permissions = metadata.permissions();
        assert_eq!(permissions.mode() & 0o777, 0o700);
    }
}

#[test]
fn cli_help_and_security_key_options() {
    Cli::command().debug_assert();
    let help = Cli::command().render_long_help().to_string();
    for option in [
        "ed25519-sk",
        "ecdsa-sk",
        "-K",
        "-w",
        "-O",
        "resident",
        "verify-required",
        "challenge=FILE",
        "write-attestation=FILE",
    ] {
        assert!(help.contains(option), "Missing help for {option}");
    }
    let cli = Cli::try_parse_from([
        "bssh-keygen",
        "-t",
        "ed25519-sk",
        "-w",
        "internal",
        "-O",
        "resident",
        "-O",
        "application=ssh:test",
    ])
    .unwrap();
    assert_eq!(cli.key_type, "ed25519-sk");
    assert_eq!(cli.sk_options, ["resident", "application=ssh:test"]);
    assert!(
        Cli::try_parse_from(["bssh-keygen", "-K"])
            .unwrap()
            .download_resident
    );
    assert!(Cli::try_parse_from(["bssh-keygen", "-K", "-f", "key"]).is_err());
}

#[test]
fn cli_software_key_defaults() {
    let cli = Cli::try_parse_from(["bssh-keygen"]).unwrap();
    assert_eq!(cli.key_type, "ed25519");
    assert_eq!(cli.bits, 4096);
    assert!(cli.output.is_none());
    assert!(!cli.download_resident);
    let cli = Cli::try_parse_from(["bssh-keygen", "-t", "rsa", "-b", "2048", "-y", "-q", "-vvv"])
        .unwrap();
    assert_eq!(cli.bits, 2048);
    assert!(cli.yes && cli.quiet);
    assert_eq!(cli.verbose, 3);
}

#[test]
fn ssh_directory_permissions() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join(".ssh");
    create_ssh_directory(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}

#[test]
fn new_key_confirmation_does_not_authorize_later_overwrite() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("key");
    assert_eq!(
        confirm_security_key_output(&path, false).unwrap(),
        Some(false)
    );
    assert_eq!(
        confirm_security_key_output(&path, true).unwrap(),
        Some(true)
    );
}
