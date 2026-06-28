//! SecureSourceNote shared core — ROADMAP S2 slice.
//!
//! Proves the north-star local-first durability loop (master §13.1, steps 1–3):
//! a local edit becomes a content-addressed [`OperationEnvelope`], is durably
//! committed to a [`LocalStore`] before any network exists, sits in an outbox
//! that is structurally distinct from convergence, and [`replay`]s deterministically.
//!
//! Out of scope here (later ROADMAP stages): at-rest/transport encryption and
//! the key hierarchy (S3); sync, conflict branches, and blob evidence (S6);
//! desktop client (S4); self-host relay server (S5).

pub mod document;
pub mod envelope;
pub mod id;
pub mod store;

pub use document::{replay, BlockView, DocumentState, WorkspaceState};
pub use envelope::{EnvelopeCore, OperationEnvelope, Payload, ENVELOPE_VERSION};
pub use id::{AccountId, BlockId, DeviceId, DocumentId, OpId, WorkspaceId};
pub use store::{LocalStore, StoreError};
