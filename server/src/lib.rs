//! SecureSourceNote zero-knowledge sync relay (ROADMAP S5).
//!
//! The server stores opaque, client-encrypted envelope blobs in append-only logs
//! bucketed by an opaque id (an HKDF tag of the client's workspace key — the
//! server cannot reverse it to content). It never sees plaintext (master
//! invariant #1); it knows only bucket ids, blob counts, sizes, and timing.
//!
//! Protocol (one append-only log per bucket):
//! - `POST /push/<bucket>`  body `{"blobs":["<hex>",...]}`  -> `{"cursor":N,"accepted":K}`
//! - `GET  /pull/<bucket>?since=N`                          -> `{"cursor":N,"blobs":[...]}`
//! - `GET  /health`                                         -> `ok`

use serde_json::json;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub struct Response {
    pub status: u16,
    pub body: String,
}

impl Response {
    fn ok(body: impl Into<String>) -> Self {
        Self {
            status: 200,
            body: body.into(),
        }
    }
    fn bad(msg: &str) -> Self {
        Self {
            status: 400,
            body: json!({ "error": msg }).to_string(),
        }
    }
    fn not_found() -> Self {
        Self {
            status: 404,
            body: json!({ "error": "not found" }).to_string(),
        }
    }
}

/// A bucket id is 64 lowercase-hex chars (an HKDF tag). Validated so it is a safe
/// filename — no path traversal, no surprises.
fn valid_bucket(b: &str) -> bool {
    b.len() == 64 && b.bytes().all(|c| c.is_ascii_hexdigit())
}

fn bucket_path(dir: &Path, bucket: &str) -> PathBuf {
    dir.join(format!("{bucket}.log"))
}

fn read_blobs(path: &Path) -> std::io::Result<Vec<String>> {
    if !path.exists() {
        return Ok(vec![]);
    }
    let mut out = Vec::new();
    for line in BufReader::new(File::open(path)?).lines() {
        let l = line?;
        if !l.trim().is_empty() {
            out.push(l);
        }
    }
    Ok(out)
}

/// Pure request handler over a storage directory. HTTP-framework-agnostic so it
/// is unit-testable without a socket.
pub fn handle(method: &str, path: &str, body: &str, dir: &Path) -> Response {
    let (route, query) = path.split_once('?').unwrap_or((path, ""));
    let parts: Vec<&str> = route.trim_matches('/').split('/').collect();
    match (method, parts.as_slice()) {
        ("GET", ["health"]) => Response::ok("ok"),
        ("POST", ["push", bucket]) => push(bucket, body, dir),
        ("GET", ["pull", bucket]) => pull(bucket, query, dir),
        _ => Response::not_found(),
    }
}

fn push(bucket: &str, body: &str, dir: &Path) -> Response {
    if !valid_bucket(bucket) {
        return Response::bad("invalid bucket");
    }
    let parsed: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return Response::bad("invalid json"),
    };
    let blobs = match parsed.get("blobs").and_then(|b| b.as_array()) {
        Some(a) => a,
        None => return Response::bad("missing blobs"),
    };
    if std::fs::create_dir_all(dir).is_err() {
        return Response::bad("storage error");
    }
    let path = bucket_path(dir, bucket);
    let mut f = match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(f) => f,
        Err(_) => return Response::bad("storage error"),
    };
    let mut accepted = 0usize;
    for b in blobs {
        // accept only non-empty opaque hex blobs (ciphertext); reject anything else
        if let Some(s) = b.as_str() {
            if !s.is_empty() && s.bytes().all(|c| c.is_ascii_hexdigit()) {
                if writeln!(f, "{s}").is_err() {
                    return Response::bad("storage error");
                }
                accepted += 1;
            }
        }
    }
    let _ = f.sync_all();
    let total = read_blobs(&path).map(|v| v.len()).unwrap_or(accepted);
    Response::ok(json!({ "cursor": total, "accepted": accepted }).to_string())
}

fn pull(bucket: &str, query: &str, dir: &Path) -> Response {
    if !valid_bucket(bucket) {
        return Response::bad("invalid bucket");
    }
    let since: usize = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("since="))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let all = match read_blobs(&bucket_path(dir, bucket)) {
        Ok(v) => v,
        Err(_) => return Response::bad("storage error"),
    };
    let total = all.len();
    let slice: &[String] = if since < total { &all[since..] } else { &[] };
    Response::ok(json!({ "cursor": total, "blobs": slice }).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_then_pull_with_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let bucket = "a".repeat(64);
        let p = handle(
            "POST",
            &format!("/push/{bucket}"),
            r#"{"blobs":["dead","beef"]}"#,
            dir.path(),
        );
        assert_eq!(p.status, 200);
        assert!(p.body.contains("\"cursor\":2"));

        let q = handle("GET", &format!("/pull/{bucket}?since=1"), "", dir.path());
        assert_eq!(q.status, 200);
        assert!(q.body.contains("beef"));
        assert!(!q.body.contains("dead"), "since=1 skips the first blob");
    }

    #[test]
    fn rejects_invalid_bucket() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            handle("POST", "/push/nothex", r#"{"blobs":[]}"#, dir.path()).status,
            400
        );
    }

    #[test]
    fn health_ok() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(handle("GET", "/health", "", dir.path()).body, "ok");
    }
}
