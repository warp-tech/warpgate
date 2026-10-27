use std::process::Command;

#[test]
fn substitutes_environment_in_requested_order() {
    let source = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    std::fs::write(source.path().join("warpgate.yaml"), "url: $DATABASE_URL").unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_warpgate"))
        .args([
            "internal-install-files",
            "--substitute-env=DATABASE_URL DATABASE_PASSWORD",
        ])
        .arg(source.path())
        .arg(destination.path())
        .env(
            "DATABASE_URL",
            "postgres://user:$DATABASE_PASSWORD@db/warpgate",
        )
        .env("DATABASE_PASSWORD", "secret")
        .status()
        .unwrap();

    assert!(status.success());
    assert_eq!(
        std::fs::read_to_string(destination.path().join("warpgate.yaml")).unwrap(),
        "url: postgres://user:secret@db/warpgate"
    );
}
