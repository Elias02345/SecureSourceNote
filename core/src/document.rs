//! Deterministic replay of an operation log into projected document state.
//!
//! The op log is canonical; this projection is rebuildable from it (master §5.1,
//! §6.6). Replaying the same ordered ops always yields the same state.
//!
//! ponytail: insert-after ordering with a deterministic append fallback for a
//! missing target. Concurrent/causal ordering and conflict branches arrive with
//! the sync + conflict model (ROADMAP S6); until then a single device's commit
//! order is the order.

use crate::envelope::{OperationEnvelope, Payload};
use crate::id::{DocumentId, WorkspaceId};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockView {
    pub id: crate::id::BlockId,
    pub text: String,
    /// Tombstoned: hidden from the projection but retained in history.
    pub removed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct DocumentState {
    pub title: String,
    pub blocks: Vec<BlockView>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct WorkspaceState {
    pub names: BTreeMap<WorkspaceId, String>,
    pub documents: BTreeMap<DocumentId, DocumentState>,
}

/// Fold an ordered sequence of envelopes into projected state.
pub fn replay<'a>(ops: impl IntoIterator<Item = &'a OperationEnvelope>) -> WorkspaceState {
    let mut ws = WorkspaceState::default();
    for env in ops {
        match &env.core.payload {
            Payload::CreateWorkspace { workspace, name } => {
                ws.names.insert(workspace.clone(), name.clone());
            }
            Payload::CreateDocument {
                document, title, ..
            } => {
                ws.documents.entry(document.clone()).or_default().title = title.clone();
            }
            Payload::InsertBlock {
                document,
                block,
                after,
                text,
            } => {
                let doc = ws.documents.entry(document.clone()).or_default();
                let view = BlockView {
                    id: block.clone(),
                    text: text.clone(),
                    removed: false,
                };
                match after {
                    None => doc.blocks.insert(0, view),
                    Some(a) => match doc.blocks.iter().position(|b| &b.id == a) {
                        Some(pos) => doc.blocks.insert(pos + 1, view),
                        None => doc.blocks.push(view), // missing target → deterministic append
                    },
                }
            }
            Payload::EditBlock {
                document,
                block,
                text,
            } => {
                if let Some(doc) = ws.documents.get_mut(document) {
                    if let Some(b) = doc.blocks.iter_mut().find(|b| &b.id == block) {
                        b.text = text.clone();
                    }
                }
            }
            Payload::RemoveBlock { document, block } => {
                if let Some(doc) = ws.documents.get_mut(document) {
                    if let Some(b) = doc.blocks.iter_mut().find(|b| &b.id == block) {
                        b.removed = true;
                    }
                }
            }
        }
    }
    ws
}
