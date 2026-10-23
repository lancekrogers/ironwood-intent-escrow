//! The run's escrow key split. Run with `cargo test run_keys`.

use ironwood_intent_escrow::cosign::SignerId;
use ironwood_intent_escrow::frost::FVK_FILE;
use ironwood_intent_escrow::run::{ensure_escrow_keys, RunPaths};

fn paths(dir: &std::path::Path) -> RunPaths {
    RunPaths {
        base: dir.to_path_buf(),
        runs: dir.join("runs"),
    }
}

#[test]
fn run_keys_refuse_a_partial_split_or_leftover_staging() {
    let dir = tempfile::tempdir().unwrap();
    let p = paths(dir.path());
    ensure_escrow_keys(&p).unwrap();
    std::fs::remove_file(p.holder(SignerId::Deadline).join("deadline.key")).unwrap();
    assert!(ensure_escrow_keys(&p).is_err());

    let dir = tempfile::tempdir().unwrap();
    let p = paths(dir.path());
    std::fs::create_dir_all(dir.path().join("escrow/staging")).unwrap();
    assert!(ensure_escrow_keys(&p).is_err());
}

#[test]
fn run_keys_put_each_share_in_its_own_holder_directory() {
    let dir = tempfile::tempdir().unwrap();
    let p = paths(dir.path());
    let fvk = ensure_escrow_keys(&p).unwrap();
    for role in SignerId::ALL {
        let mut names: Vec<String> = std::fs::read_dir(p.holder(role))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        let mut expected = vec![role.key_file_name().to_string(), FVK_FILE.to_string()];
        expected.sort();
        assert_eq!(names, expected, "{role:?}");
    }
    assert!(!dir.path().join("escrow/staging").exists());
    assert_eq!(ensure_escrow_keys(&p).unwrap(), fvk);
}
