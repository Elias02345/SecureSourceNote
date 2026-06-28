//! End-to-end smoke test for the `ssn` CLI: drives the whole local-first,
//! encrypted stack through the public command surface.

use ssn_cli::run;

#[test]
fn end_to_end_notes_are_encrypted() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let cli = |args: &[&str]| {
        run(
            &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            home,
        )
    };

    cli(&["init"]).unwrap();
    let doc = cli(&["new", "My Note"]).unwrap();
    cli(&["add", &doc, "hello", "world"]).unwrap();
    let blk = cli(&["add", &doc, "second", "line"]).unwrap();

    let cat = cli(&["cat", &doc]).unwrap();
    assert!(cat.contains("# My Note"));
    assert!(cat.contains("hello world"));
    assert!(cat.contains("second line"));

    assert!(cli(&["ls"]).unwrap().contains("My Note"));

    // edits and tombstones replay correctly
    cli(&["edit", &blk, "edited", "line"]).unwrap();
    cli(&["rm", &blk]).unwrap();
    let cat2 = cli(&["cat", &doc]).unwrap();
    assert!(cat2.contains("hello world"));
    assert!(!cat2.contains("edited line"), "removed block stays hidden");

    // and none of it is plaintext on disk
    let raw = std::fs::read(home.join("data").join("ops.jsonl")).unwrap();
    assert!(
        !raw.windows(11).any(|w| w == b"hello world"),
        "plaintext at rest"
    );
}
