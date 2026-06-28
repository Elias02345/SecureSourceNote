//! Operation envelopes: every durable change travels as a content-addressed,
//! signature-ready envelope (master §5.4).
//!
//! S2 scope: integrity by content hash, causal-parent recording, and the
//! three-time model's authored time. Actor *signatures* and key epochs arrive
//! with the key hierarchy (ROADMAP S3); the envelope already carries the slots
//! so that layer is additive, never a reshape.

use crate::id::{BlockId, DeviceId, DocumentId, OpId, WorkspaceId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Current envelope schema version. Old clients use it to detect operation sets
/// they cannot apply safely (master §5.4, D007).
pub const ENVELOPE_VERSION: u32 = 1;

/// The mutations the MVP text slice understands. Deliberately narrow
/// (master D002: "narrow replayable operation subset").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Payload {
    CreateWorkspace {
        workspace: WorkspaceId,
        name: String,
    },
    CreateDocument {
        workspace: WorkspaceId,
        document: DocumentId,
        title: String,
    },
    /// Insert a block after `after` (None = at the document head).
    InsertBlock {
        document: DocumentId,
        block: BlockId,
        after: Option<BlockId>,
        text: String,
    },
    EditBlock {
        document: DocumentId,
        block: BlockId,
        text: String,
    },
    /// Tombstone a block. History is retained; the projection hides it
    /// (master invariant: no silent data loss).
    RemoveBlock {
        document: DocumentId,
        block: BlockId,
    },
}

/// The hashed portion of an envelope. serde emits struct fields in declaration
/// order and this type uses no maps, so its JSON form is a deterministic
/// canonical encoding — no separate canonicalizer is needed (master §5.2 / CC-6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeCore {
    pub v: u32,
    /// Device that authored the operation.
    pub actor: DeviceId,
    /// Causal parents: op ids this operation observed (master §5.4, §5.5).
    pub parents: Vec<OpId>,
    /// Authored wall-clock millis — provenance only, never ordering truth (master §5.5).
    pub authored_ms: i64,
    pub payload: Payload,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationEnvelope {
    pub id: OpId,
    pub core: EnvelopeCore,
}

fn to_hex(bytes: impl AsRef<[u8]>) -> String {
    use std::fmt::Write;
    let bytes = bytes.as_ref();
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

impl EnvelopeCore {
    /// Deterministic canonical bytes of the hashed portion.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("envelope core is always serializable")
    }

    /// Content id = hex SHA-256 over the canonical bytes.
    pub fn content_id(&self) -> OpId {
        let mut h = Sha256::new();
        h.update(self.canonical_bytes());
        OpId(to_hex(h.finalize()))
    }
}

impl OperationEnvelope {
    /// Seal a core into an envelope, deriving its content id.
    pub fn seal(core: EnvelopeCore) -> Self {
        let id = core.content_id();
        Self { id, core }
    }

    /// True iff the stored id matches a fresh hash of the core.
    ///
    /// Detects corruption and accidental modification (master §6.6). This is
    /// NOT authenticity: anyone who can rewrite the log can also re-seal a
    /// forged op so it passes. Rejecting forgeries needs actor signatures, added
    /// with the key hierarchy in ROADMAP S3.
    pub fn verify_integrity(&self) -> bool {
        self.core.content_id() == self.id
    }

    /// Canonical JSON bytes of the full envelope, for sync transport.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("envelope is always serializable")
    }

    /// Parse an envelope from JSON bytes; `None` if malformed.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::WorkspaceId;

    fn core() -> EnvelopeCore {
        EnvelopeCore {
            v: ENVELOPE_VERSION,
            actor: DeviceId::new("d"),
            parents: vec![],
            authored_ms: 7,
            payload: Payload::CreateWorkspace {
                workspace: WorkspaceId::new("w"),
                name: "n".into(),
            },
        }
    }

    #[test]
    fn content_id_is_stable() {
        assert_eq!(core().content_id(), core().content_id());
    }

    #[test]
    fn sealed_envelope_verifies() {
        assert!(OperationEnvelope::seal(core()).verify_integrity());
    }

    #[test]
    fn any_mutation_changes_the_id() {
        let id1 = core().content_id();
        let mut c = core();
        c.authored_ms = 8;
        assert_ne!(id1, c.content_id());
    }

    #[test]
    fn bytes_roundtrip() {
        let e = OperationEnvelope::seal(core());
        assert_eq!(OperationEnvelope::from_bytes(&e.to_bytes()), Some(e));
    }
}
