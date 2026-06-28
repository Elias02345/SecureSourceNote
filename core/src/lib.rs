//! SecureSourceNote shared core — ROADMAP S2 slice.
//!
//! Proves the north-star local-first durability loop (master §13.1, steps 1–3):
//! a local edit becomes a content-addressed [`OperationEnvelope`], is durably
//! committed to a [`LocalStore`] before any network exists, sits in an outbox
//! that is structurally distinct from convergence, and [`replay`]s deterministically.
//!
//! At-rest encryption and a symmetric key hierarchy are in scope (ROADMAP S3,
//! [`crypto`]): the on-disk op log holds no plaintext. Out of scope here:
//! device-key wrapping, passkey/OPAQUE auth, and recovery material (rest of S3);
//! transport encryption, sync, conflict branches, and blob evidence (S6);
//! desktop client (S4); self-host relay server (S5).

pub mod crypto;
pub mod document;
pub mod envelope;
pub mod id;
pub mod store;

pub use crypto::SymKey;
pub use document::{block_heads, replay, BlockView, DocumentState, WorkspaceState};
pub use envelope::{EnvelopeCore, OperationEnvelope, Payload, ENVELOPE_VERSION};
pub use id::{AccountId, BlockId, DeviceId, DocumentId, OpId, WorkspaceId};
pub use store::{LocalStore, StoreError};
