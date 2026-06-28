//! Durable local storage (master §0.5, §6.6).
//!
//! Two append-only logs model "local save precedes network truth" with no
//! silent data loss (invariant #3):
//!
//! - `ops.jsonl` — the canonical operation log (one sealed envelope per line)
//! - `acks.log` — op ids the server has receipted
//!
//! The outbox (committed-but-unacked ops) is derived from the difference, so
//! "outbox empty" is structurally distinct from "converged" (master §0.5).
//!
//! ponytail: append-only JSONL + fsync is the canonical durable source.
//! SQLite/SQLCipher becomes a *rebuildable* index/projection over this log when
//! query and at-rest encryption land (ROADMAP S3); the log stays the truth
//! (master §6.6: derived caches must not replace source truth).
//! ponytail: plaintext on disk for now; at-rest encryption is ROADMAP S3.

use crate::envelope::OperationEnvelope;
use crate::id::OpId;
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum StoreError {
    Io(std::io::Error),
    /// A fully-written log line failed to parse or failed its integrity check.
    Corruption(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io(e) => write!(f, "io error: {e}"),
            StoreError::Corruption(m) => write!(f, "store corruption: {m}"),
        }
    }
}
impl std::error::Error for StoreError {}
impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Io(e)
    }
}

#[derive(Debug)]
pub struct LocalStore {
    op_log: PathBuf,
    ack_log: PathBuf,
    ops: Vec<OperationEnvelope>,
    seen: BTreeSet<OpId>,
    acked: BTreeSet<OpId>,
}

fn append_line(path: &Path, line: &str) -> Result<(), StoreError> {
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    f.write_all(line.as_bytes())?;
    f.write_all(b"\n")?;
    f.sync_all()?; // fsync the file: return only once its bytes are on disk.
                   // ponytail: the parent directory entry is not fsynced, so a
                   // crash in the narrow window of first-time file creation could
                   // lose a brand-new log. The durable store layer (ROADMAP S3)
                   // closes this; acceptable for the S2 proof.
    Ok(())
}

fn load_ops(path: &Path) -> Result<(Vec<OperationEnvelope>, BTreeSet<OpId>), StoreError> {
    let mut ops = Vec::new();
    let mut seen = BTreeSet::new();
    if !path.exists() {
        return Ok((ops, seen));
    }
    let lines: Vec<String> = BufReader::new(File::open(path)?)
        .lines()
        .collect::<std::io::Result<Vec<_>>>()?;
    let last = lines.len().saturating_sub(1);
    for (i, line) in lines.iter().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<OperationEnvelope>(line) {
            Ok(env) => {
                if !env.verify_integrity() {
                    return Err(StoreError::Corruption(format!(
                        "integrity mismatch at line {}",
                        i + 1
                    )));
                }
                if seen.insert(env.id.clone()) {
                    ops.push(env);
                }
            }
            // Append-only means only the final line can be a torn write from a
            // crash mid-append: tolerate it (the op was never durably acked).
            // A parse failure anywhere earlier is real corruption.
            Err(_) if i == last => break,
            Err(e) => {
                return Err(StoreError::Corruption(format!(
                    "parse error at line {}: {e}",
                    i + 1
                )))
            }
        }
    }
    Ok((ops, seen))
}

fn load_acks(path: &Path) -> Result<BTreeSet<OpId>, StoreError> {
    let mut acked = BTreeSet::new();
    if !path.exists() {
        return Ok(acked);
    }
    for line in BufReader::new(File::open(path)?).lines() {
        let line = line?;
        let t = line.trim();
        if !t.is_empty() {
            acked.insert(OpId::new(t));
        }
    }
    Ok(acked)
}

impl LocalStore {
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, StoreError> {
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir)?;
        let op_log = dir.join("ops.jsonl");
        let ack_log = dir.join("acks.log");
        let (ops, seen) = load_ops(&op_log)?;
        let acked = load_acks(&ack_log)?;
        Ok(Self {
            op_log,
            ack_log,
            ops,
            seen,
            acked,
        })
    }

    /// Durably commit an envelope. Returns `Ok(true)` if newly stored,
    /// `Ok(false)` if it was already present (idempotent — safe to replay/retry).
    pub fn commit(&mut self, env: &OperationEnvelope) -> Result<bool, StoreError> {
        if !env.verify_integrity() {
            return Err(StoreError::Corruption(
                "refusing to commit an envelope with a bad integrity hash".into(),
            ));
        }
        if self.seen.contains(&env.id) {
            return Ok(false);
        }
        let line = serde_json::to_string(env).map_err(|e| StoreError::Corruption(e.to_string()))?;
        append_line(&self.op_log, &line)?;
        self.seen.insert(env.id.clone());
        self.ops.push(env.clone());
        Ok(true)
    }

    /// Record that the server has receipted this op. Durable and idempotent.
    pub fn mark_acked(&mut self, id: &OpId) -> Result<(), StoreError> {
        if self.acked.contains(id) {
            return Ok(());
        }
        append_line(&self.ack_log, id.as_str())?;
        self.acked.insert(id.clone());
        Ok(())
    }

    /// All committed envelopes, in commit order.
    pub fn ops(&self) -> &[OperationEnvelope] {
        &self.ops
    }

    /// Committed-but-unacked envelopes, in commit order (the send queue).
    pub fn outbox(&self) -> Vec<&OperationEnvelope> {
        self.ops
            .iter()
            .filter(|e| !self.acked.contains(&e.id))
            .collect()
    }

    pub fn outbox_len(&self) -> usize {
        self.ops
            .iter()
            .filter(|e| !self.acked.contains(&e.id))
            .count()
    }
}
