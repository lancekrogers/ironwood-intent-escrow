//! The `verify` binary, offline, as a judge runs it with `--offline`. Run
//! with `cargo test --test verify`.
//!
//! `--offline` never opens a socket. The live path is run by hand and
//! recorded; it needs the light server and the archival NEAR RPC.
//!
//! `tests/fixtures/verify_bad` is a copy of the records with one bit of the
//! first Ironwood nullifier in `fill.spend.tx` flipped, which changes the
//! txid but still parses, and `fill_quote_refund_refused` set to
//! `not_expired`.

use std::process::{Command, Output};

fn verify(args: &[&str]) -> (Option<i32>, String) {
    let Output { status, stdout, .. } = Command::new(env!("CARGO_BIN_EXE_verify"))
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    (status.code(), String::from_utf8(stdout).unwrap())
}

#[test]
fn verify_offline_passes_on_the_recorded_runs() {
    let (code, out) = verify(&["--offline"]);
    assert_eq!(code, Some(0), "{out}");
    assert!(
        out.contains("13 passed, 0 failed, 5 skipped (offline)"),
        "{out}"
    );
    assert!(!out.contains("FAIL"), "{out}");
    assert!(!out.contains("fetching"), "an offline run fetched: {out}");
}

#[test]
fn verify_offline_fails_a_flipped_byte_and_a_wrong_policy_outcome() {
    let (code, out) = verify(&["--offline", "--runs", "tests/fixtures/verify_bad"]);
    assert_eq!(code, Some(1), "{out}");
    assert!(out.contains("FAIL fill.spend.tx txid"), "{out}");
    assert!(out.contains("FAIL policy outcomes recorded"), "{out}");
    assert!(
        out.contains("11 passed, 2 failed, 5 skipped (offline)"),
        "{out}"
    );
}

#[test]
fn verify_fails_a_missing_records_directory() {
    let (code, out) = verify(&["--offline", "--runs", "tests/fixtures/no-such-dir"]);
    assert_eq!(code, Some(1), "{out}");
    assert!(out.contains("FAIL records loaded"), "{out}");
}

#[test]
fn verify_refuses_an_unknown_argument() {
    let (code, _) = verify(&["--online"]);
    assert_eq!(code, Some(2));
}
