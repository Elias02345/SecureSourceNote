//! Deterministic, convergent replay of an operation log into projected state.
//!
//! Replay is ORDER-INDEPENDENT: ops are folded in a deterministic total order
//! (causal topological order, tie-broken by authored time then op id), so every
//! device converges to the same projection regardless of the order it received
//! ops in (master §0.5). The op log is canonical; this projection is rebuildable.
//!
//! Concurrent edits to the same block are NOT silently merged by last-write-wins
//! (forbidden — master invariant #4). The deterministic winner becomes `text`;
//! every other concurrent value is preserved in `conflicts`, so nothing is lost.
//!
//! ponytail: this is conflict *preservation*, not a resolution UX. A delete only
//! takes effect when no concurrent edit survives, so content is never hidden by a
//! racing delete. Document/workspace titles still use total-order last-writer
//! (title conflict preservation is later ROADMAP work). Ancestry is recomputed
//! per block (O(n·edits)); memoize/index if op logs grow large.

use crate::envelope::{OperationEnvelope, Payload};
use crate::id::{BlockId, DocumentId, OpId, WorkspaceId};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockView {
    pub id: BlockId,
    pub text: String,
    /// Other concurrent values for this block, preserved (empty = no conflict).
    pub conflicts: Vec<String>,
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

/// Fold an unordered set of envelopes into deterministic projected state.
pub fn replay<'a>(ops: impl IntoIterator<Item = &'a OperationEnvelope>) -> WorkspaceState {
    let mut by_id: HashMap<&OpId, &OperationEnvelope> = HashMap::new();
    for e in ops {
        by_id.entry(&e.id).or_insert(e);
    }
    let ordered = total_order(&by_id);

    let mut ws = WorkspaceState::default();
    let mut block_order: BTreeMap<DocumentId, Vec<BlockId>> = BTreeMap::new();

    // Pass 1 (in total order): names, titles (last-writer), block insertion order.
    for e in &ordered {
        match &e.core.payload {
            Payload::CreateWorkspace { workspace, name } => {
                ws.names.insert(workspace.clone(), name.clone());
            }
            Payload::CreateDocument {
                document, title, ..
            } => {
                ws.documents.entry(document.clone()).or_default().title = title.clone();
                block_order.entry(document.clone()).or_default();
            }
            Payload::InsertBlock {
                document,
                block,
                after,
                ..
            } => {
                ws.documents.entry(document.clone()).or_default();
                let order = block_order.entry(document.clone()).or_default();
                if !order.contains(block) {
                    match after {
                        Some(a) => match order.iter().position(|b| b == a) {
                            Some(pos) => order.insert(pos + 1, block.clone()),
                            None => order.push(block.clone()),
                        },
                        None => order.insert(0, block.clone()),
                    }
                }
            }
            _ => {}
        }
    }

    // Pass 2: resolve each block's value via its causal heads.
    for (doc_id, order) in &block_order {
        let doc = ws.documents.entry(doc_id.clone()).or_default();
        for block in order {
            doc.blocks.push(resolve_block(block, &ordered, &by_id));
        }
    }
    ws
}

/// Deterministic causal topological order: an op follows its (present) parents;
/// ready ops are taken in (authored_ms, op_id) order. Content-addressed ids make
/// the graph acyclic, so every op is emitted exactly once.
fn total_order<'a>(by_id: &HashMap<&'a OpId, &'a OperationEnvelope>) -> Vec<&'a OperationEnvelope> {
    let mut indeg: HashMap<&OpId, usize> = by_id.keys().map(|&id| (id, 0usize)).collect();
    let mut children: HashMap<&OpId, Vec<&OpId>> = HashMap::new();
    for (&id, &e) in by_id {
        for p in &e.core.parents {
            if let Some((&pk, _)) = by_id.get_key_value(p) {
                *indeg.get_mut(id).unwrap() += 1;
                children.entry(pk).or_default().push(id);
            }
        }
    }
    let okey = |id: &OpId| (by_id[id].core.authored_ms, id.0.clone());
    let mut ready: Vec<&OpId> = indeg
        .iter()
        .filter(|(_, &d)| d == 0)
        .map(|(&id, _)| id)
        .collect();
    let mut out: Vec<&OperationEnvelope> = Vec::with_capacity(by_id.len());
    let mut done: HashSet<&OpId> = HashSet::new();
    while !ready.is_empty() {
        ready.sort_by_key(|id| std::cmp::Reverse(okey(id))); // descending so pop() yields the min
        let id = ready.pop().unwrap();
        if !done.insert(id) {
            continue;
        }
        out.push(by_id[id]);
        if let Some(cs) = children.get(id) {
            for &c in cs {
                let d = indeg.get_mut(c).unwrap();
                *d -= 1;
                if *d == 0 {
                    ready.push(c);
                }
            }
        }
    }
    // Defensive: emit any unreachable remainder (cycles are impossible for
    // content-addressed ids, but never drop data).
    if out.len() < by_id.len() {
        let mut rest: Vec<&OpId> = by_id
            .keys()
            .copied()
            .filter(|id| !done.contains(id))
            .collect();
        rest.sort_by_key(|id| okey(id));
        for id in rest {
            out.push(by_id[id]);
        }
    }
    out
}

/// Transitive causal ancestors of `start` that are present in the log.
fn ancestors_of(start: &OpId, by_id: &HashMap<&OpId, &OperationEnvelope>) -> HashSet<OpId> {
    let mut seen = HashSet::new();
    let mut stack: Vec<OpId> = match by_id.get(start) {
        Some(e) => e.core.parents.clone(),
        None => return seen,
    };
    while let Some(p) = stack.pop() {
        if seen.insert(p.clone()) {
            if let Some(e) = by_id.get(&p) {
                stack.extend(e.core.parents.iter().cloned());
            }
        }
    }
    seen
}

fn resolve_block(
    block: &BlockId,
    ordered: &[&OperationEnvelope],
    by_id: &HashMap<&OpId, &OperationEnvelope>,
) -> BlockView {
    struct BlockOp {
        id: OpId,
        text: Option<String>, // Some = insert/edit value, None = remove
        key: (i64, String),
    }
    let mut bos: Vec<BlockOp> = Vec::new();
    for e in ordered {
        let text = match &e.core.payload {
            Payload::InsertBlock { block: b, text, .. } if b == block => Some(text.clone()),
            Payload::EditBlock { block: b, text, .. } if b == block => Some(text.clone()),
            Payload::RemoveBlock { block: b, .. } if b == block => None,
            _ => continue,
        };
        bos.push(BlockOp {
            id: e.id.clone(),
            text,
            key: (e.core.authored_ms, e.id.0.clone()),
        });
    }

    // A block-op is a head iff no other block-op has it as a causal ancestor.
    let anc: Vec<HashSet<OpId>> = bos.iter().map(|b| ancestors_of(&b.id, by_id)).collect();
    let mut text_heads: Vec<&BlockOp> = Vec::new();
    let mut has_remove_head = false;
    for (i, bo) in bos.iter().enumerate() {
        let superseded = (0..bos.len()).any(|j| j != i && anc[j].contains(&bo.id));
        if superseded {
            continue;
        }
        match bo.text {
            Some(_) => text_heads.push(bo),
            None => has_remove_head = true,
        }
    }

    if text_heads.is_empty() {
        return BlockView {
            id: block.clone(),
            text: String::new(),
            conflicts: Vec::new(),
            removed: has_remove_head,
        };
    }

    // Surviving edits win over a concurrent delete (content is never silently hidden).
    text_heads.sort_by(|a, b| b.key.cmp(&a.key)); // newest first
    let winner = text_heads[0].text.clone().unwrap();
    let mut seen: BTreeSet<String> = BTreeSet::from([winner.clone()]);
    let mut conflicts = Vec::new();
    for t in text_heads.iter().skip(1) {
        let v = t.text.clone().unwrap();
        if seen.insert(v.clone()) {
            conflicts.push(v);
        }
    }
    BlockView {
        id: block.clone(),
        text: winner,
        conflicts,
        removed: false,
    }
}

/// The op-ids currently "live" for a block (its causal heads). An edit that names
/// all of these as parents supersedes every concurrent value, settling a conflict.
pub fn block_heads<'a>(
    ops: impl IntoIterator<Item = &'a OperationEnvelope>,
    block: &BlockId,
) -> Vec<OpId> {
    let mut by_id: HashMap<&OpId, &OperationEnvelope> = HashMap::new();
    for e in ops {
        by_id.entry(&e.id).or_insert(e);
    }
    let bos: Vec<&OperationEnvelope> = by_id
        .values()
        .copied()
        .filter(|e| {
            matches!(&e.core.payload,
                Payload::InsertBlock { block: b, .. }
                | Payload::EditBlock { block: b, .. }
                | Payload::RemoveBlock { block: b, .. } if b == block)
        })
        .collect();
    let anc: Vec<HashSet<OpId>> = bos.iter().map(|e| ancestors_of(&e.id, &by_id)).collect();
    let mut heads: Vec<OpId> = bos
        .iter()
        .enumerate()
        .filter(|(i, e)| !(0..bos.len()).any(|j| j != *i && anc[j].contains(&e.id)))
        .map(|(_, e)| e.id.clone())
        .collect();
    heads.sort();
    heads
}
