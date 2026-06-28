//! ROADMAP S2/S3/S6 exit criteria, as runnable checks (the 03:00-pager-drill seeds).
//! Each test fails if a core trust invariant breaks.

use ssn_core::*;
use std::io::Write;

/// Fixed key so reopening the same store in a test uses the same key.
fn test_key() -> SymKey {
    SymKey::from_bytes([7u8; 32])
}

/// A single parentless op (for cases where causality is irrelevant).
fn op(payload: Payload) -> OperationEnvelope {
    OperationEnvelope::seal(EnvelopeCore {
        v: ENVELOPE_VERSION,
        actor: DeviceId::new("dev-a"),
        parents: vec![],
        authored_ms: 0,
        payload,
    })
}

/// Build a causal chain (each op's parent is the previous op) — what a single
/// device actually produces.
fn chain(payloads: Vec<Payload>) -> Vec<OperationEnvelope> {
    let mut out: Vec<OperationEnvelope> = Vec::new();
    let mut parents: Vec<OpId> = vec![];
    for (i, payload) in payloads.into_iter().enumerate() {
        let e = OperationEnvelope::seal(EnvelopeCore {
            v: ENVELOPE_VERSION,
            actor: DeviceId::new("dev-a"),
            parents: parents.clone(),
            authored_ms: i as i64,
            payload,
        });
        parents = vec![e.id.clone()];
        out.push(e);
    }
    out
}

fn sample_ops() -> Vec<OperationEnvelope> {
    let ws = WorkspaceId::new("ws1");
    let doc = DocumentId::new("doc1");
    let b1 = BlockId::new("b1");
    let b2 = BlockId::new("b2");
    chain(vec![
        Payload::CreateWorkspace {
            workspace: ws.clone(),
            name: "Home".into(),
        },
        Payload::CreateDocument {
            workspace: ws,
            document: doc.clone(),
            title: "Note".into(),
        },
        Payload::InsertBlock {
            document: doc.clone(),
            block: b1.clone(),
            after: None,
            text: "hello".into(),
        },
        Payload::InsertBlock {
            document: doc.clone(),
            block: b2,
            after: Some(b1.clone()),
            text: "world".into(),
        },
        Payload::EditBlock {
            document: doc,
            block: b1,
            text: "HELLO".into(),
        },
    ])
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

/// Replay is order-independent: a shuffled op log yields the same state, so two
/// devices that received ops in different orders still converge (master §0.5).
#[test]
fn replay_is_convergent_regardless_of_order() {
    let ops = sample_ops();
    let mut shuffled: Vec<&OperationEnvelope> = ops.iter().collect();
    shuffled.reverse();
    assert_eq!(replay(&ops), replay(shuffled));
}

/// Concurrent edits to the same block are preserved, never silently overwritten.
#[test]
fn concurrent_edits_preserved_as_conflict() {
    let doc = DocumentId::new("d");
    let b = BlockId::new("b");
    let base = chain(vec![
        Payload::CreateDocument {
            workspace: WorkspaceId::new("w"),
            document: doc.clone(),
            title: "t".into(),
        },
        Payload::InsertBlock {
            document: doc.clone(),
            block: b.clone(),
            after: None,
            text: "base".into(),
        },
    ]);
    let insert_id = base[1].id.clone();
    // Two edits that both name the insert as their only parent → concurrent.
    let edit = |actor: &str, ms: i64, text: &str| {
        OperationEnvelope::seal(EnvelopeCore {
            v: ENVELOPE_VERSION,
            actor: DeviceId::new(actor),
            parents: vec![insert_id.clone()],
            authored_ms: ms,
            payload: Payload::EditBlock {
                document: doc.clone(),
                block: b.clone(),
                text: text.into(),
            },
        })
    };
    let mut ops = base.clone();
    ops.push(edit("dev-a", 10, "from-A"));
    ops.push(edit("dev-b", 11, "from-B"));

    let state = replay(&ops);
    let blk = &state.documents.get(&doc).unwrap().blocks[0];
    let mut values = vec![blk.text.clone()];
    values.extend(blk.conflicts.clone());
    values.sort();
    assert_eq!(values, vec!["from-A".to_string(), "from-B".to_string()]);
    assert!(!blk.removed, "a surviving edit keeps the block visible");
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
    let ops = chain(vec![
        Payload::CreateDocument {
            workspace: WorkspaceId::new("w"),
            document: doc.clone(),
            title: "t".into(),
        },
        Payload::InsertBlock {
            document: doc.clone(),
            block: b.clone(),
            after: None,
            text: "keep-me".into(),
        },
        Payload::RemoveBlock {
            document: doc.clone(),
            block: b,
        },
    ]);
    let state = replay(&ops);
    let d = state.documents.get(&doc).unwrap();
    assert_eq!(d.blocks.len(), 1, "history retained");
    assert!(d.blocks[0].removed, "but hidden from the live projection");
}
