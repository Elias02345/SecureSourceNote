//! ROADMAP S2/S3 exit criteria, as runnable checks (the 03:00-pager-drill seeds).
//! Each test fails if a core trust invariant breaks.

use ssn_core::*;
use std::io::Write;

/// Fixed key so reopening the same store in a test uses the same key.
fn test_key() -> SymKey {
    SymKey::from_bytes([7u8; 32])
}

fn op(payload: Payload) -> OperationEnvelope {
    OperationEnvelope::seal(EnvelopeCore {
        v: ENVELOPE_VERSION,
        actor: DeviceId::new("dev-a"),
        parents: vec![],
        authored_ms: 0,
        payload,
    })
}

fn sample_ops() -> Vec<OperationEnvelope> {
    let ws = WorkspaceId::new("ws1");
    let doc = DocumentId::new("doc1");
    let b1 = BlockId::new("b1");
    let b2 = BlockId::new("b2");
    vec![
        op(Payload::CreateWorkspace {
            workspace: ws.clone(),
            name: "Home".into(),
        }),
        op(Payload::CreateDocument {
            workspace: ws,
            document: doc.clone(),
            title: "Note".into(),
        }),
        op(Payload::InsertBlock {
            document: doc.clone(),
            block: b1.clone(),
            after: None,
            text: "hello".into(),
        }),
        op(Payload::InsertBlock {
            document: doc.clone(),
            block: b2,
            after: Some(b1.clone()),
            text: "world".into(),
        }),
        op(Payload::EditBlock {
            document: doc,
            block: b1,
            text: "HELLO".into(),
        }),
    ]
}

/// Step 2: local work is durable across a process restart, and replays correctly.
#[test]
fn local_save_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let ops = sample_ops();
    {
        let mut s = LocalStore::open(dir.path(), test_key()).unwrap();
        for o in &ops {
            assert!(s.commit(o).unwrap());
        }
    } // drop = simulated process exit

    let s2 = LocalStore::open(dir.path(), test_key()).unwrap();
    assert_eq!(s2.ops().len(), ops.len());

    let state = replay(s2.ops());
    let doc = state.documents.get(&DocumentId::new("doc1")).unwrap();
    assert_eq!(doc.title, "Note");
    let visible: Vec<&str> = doc
        .blocks
        .iter()
        .filter(|b| !b.removed)
        .map(|b| b.text.as_str())
        .collect();
    assert_eq!(visible, vec!["HELLO", "world"]);
}

/// Replaying the same ops always yields the same state.
#[test]
fn replay_is_deterministic() {
    let ops = sample_ops();
    assert_eq!(replay(&ops), replay(&ops));
}

/// "Outbox empty" must not be conflatable with "durable": acking changes the
/// outbox but never the op log, and the ack survives a restart (master §0.5).
#[test]
fn outbox_is_distinct_from_durability() {
    let dir = tempfile::tempdir().unwrap();
    let ops = sample_ops();
    let mut s = LocalStore::open(dir.path(), test_key()).unwrap();
    for o in &ops {
        s.commit(o).unwrap();
    }
    assert_eq!(s.outbox_len(), ops.len());

    s.mark_acked(&ops[0].id).unwrap();
    assert_eq!(s.outbox_len(), ops.len() - 1);
    assert_eq!(
        s.ops().len(),
        ops.len(),
        "ack must not touch durable history"
    );

    drop(s);
    let s2 = LocalStore::open(dir.path(), test_key()).unwrap();
    assert_eq!(s2.outbox_len(), ops.len() - 1, "ack must persist");
}

/// Committing the same envelope twice is a no-op the second time (safe replay).
#[test]
fn commit_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let o = op(Payload::CreateWorkspace {
        workspace: WorkspaceId::new("w"),
        name: "x".into(),
    });
    let mut s = LocalStore::open(dir.path(), test_key()).unwrap();
    assert!(s.commit(&o).unwrap());
    assert!(!s.commit(&o).unwrap());
    assert_eq!(s.ops().len(), 1);
}

/// S3: the on-disk op log contains no plaintext.
#[test]
fn no_plaintext_at_rest() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = LocalStore::open(dir.path(), test_key()).unwrap();
    for o in &sample_ops() {
        s.commit(o).unwrap();
    }
    let raw = std::fs::read(dir.path().join("ops.jsonl")).unwrap();
    for needle in [&b"Home"[..], b"hello", b"HELLO", b"world", b"Note"] {
        assert!(
            !raw.windows(needle.len()).any(|w| w == needle),
            "plaintext leaked at rest"
        );
    }
}

/// S3: a store written under one key cannot be opened (decrypted) under another.
#[test]
fn wrong_key_cannot_open_store() {
    let dir = tempfile::tempdir().unwrap();
    {
        let mut s = LocalStore::open(dir.path(), SymKey::from_bytes([1u8; 32])).unwrap();
        for o in &sample_ops() {
            s.commit(o).unwrap();
        }
    }
    let err = LocalStore::open(dir.path(), SymKey::from_bytes([2u8; 32])).unwrap_err();
    assert!(matches!(err, StoreError::Corruption(_)));
}

/// A tampered ciphertext line is detected by the AEAD tag, not silently trusted.
#[test]
fn tamper_is_detected_on_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let ops = sample_ops();
    {
        let mut s = LocalStore::open(dir.path(), test_key()).unwrap();
        for o in &ops {
            s.commit(o).unwrap();
        }
    }
    // Flip one hex nibble in the first (non-final) ciphertext line.
    let log = dir.path().join("ops.jsonl");
    let content = std::fs::read_to_string(&log).unwrap();
    let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
    let mut chars: Vec<char> = lines[0].chars().collect();
    let pos = chars.len() / 2;
    chars[pos] = if chars[pos] == 'a' { 'b' } else { 'a' };
    lines[0] = chars.into_iter().collect();
    std::fs::write(&log, lines.join("\n") + "\n").unwrap();

    let err = LocalStore::open(dir.path(), test_key()).unwrap_err();
    assert!(matches!(err, StoreError::Corruption(_)));
}

/// A torn final write (crash mid-append) is tolerated; prior ops stay intact.
#[test]
fn torn_final_write_is_tolerated() {
    let dir = tempfile::tempdir().unwrap();
    let ops = sample_ops();
    {
        let mut s = LocalStore::open(dir.path(), test_key()).unwrap();
        for o in &ops {
            s.commit(o).unwrap();
        }
    }
    let log = dir.path().join("ops.jsonl");
    let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
    f.write_all(b"deadbeef").unwrap(); // truncated final line, no newline
    drop(f);

    let s2 = LocalStore::open(dir.path(), test_key()).unwrap();
    assert_eq!(s2.ops().len(), ops.len());
}

/// Removing a block hides it from the projection but keeps the op in history.
#[test]
fn tombstone_retains_history() {
    let doc = DocumentId::new("d");
    let b = BlockId::new("b");
    let ops = vec![
        op(Payload::CreateDocument {
            workspace: WorkspaceId::new("w"),
            document: doc.clone(),
            title: "t".into(),
        }),
        op(Payload::InsertBlock {
            document: doc.clone(),
            block: b.clone(),
            after: None,
            text: "keep-me".into(),
        }),
        op(Payload::RemoveBlock {
            document: doc.clone(),
            block: b,
        }),
    ];
    let state = replay(&ops);
    let d = state.documents.get(&doc).unwrap();
    assert_eq!(d.blocks.len(), 1, "history retained");
    assert!(d.blocks[0].removed, "but hidden from the live projection");
}
