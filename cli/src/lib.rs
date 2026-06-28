//! `ssn` — SecureSourceNote command-line client (ROADMAP S4, CLI face).
//!
//! A local-first, encrypted-at-rest notes app over `ssn-core`. Data lives in
//! `$SSN_HOME` (default `./.ssn`): an encrypted op log, a key file, a device id.
//!
//! ponytail: the store key is kept in a dev-grade key file next to the data.
//! Real key protection (OS keychain / passphrase — ROADMAP S3-remainder) must
//! replace this before any non-dev use; at-rest encryption only helps once the
//! key lives elsewhere. Marked here so it is not mistaken for production-ready.

use serde_json::json;
use ssn_core::{
    replay, BlockId, DeviceId, DocumentId, EnvelopeCore, LocalStore, OpId, OperationEnvelope,
    Payload, SymKey, WorkspaceId, WorkspaceState, ENVELOPE_VERSION,
};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_WS: &str = "default";

/// Resolve the data directory from `$SSN_HOME` (default `./.ssn`).
pub fn home() -> PathBuf {
    std::env::var_os("SSN_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".ssn"))
}

/// Dispatch one command. Returns the text to print, or an error message.
pub fn run(args: &[String], home: &Path) -> Result<String, String> {
    match args.first().map(String::as_str).unwrap_or("help") {
        "init" => cmd_init(home),
        "new" => cmd_new(home, args.get(1).ok_or("usage: ssn new <title>")?),
        "add" => {
            let doc = args.get(1).ok_or("usage: ssn add <doc-id> <text...>")?;
            let text = args.get(2..).unwrap_or(&[]).join(" ");
            if text.is_empty() {
                return Err("usage: ssn add <doc-id> <text...>".into());
            }
            cmd_add(home, doc, &text)
        }
        "edit" => {
            let block = args.get(1).ok_or("usage: ssn edit <block-id> <text...>")?;
            let text = args.get(2..).unwrap_or(&[]).join(" ");
            if text.is_empty() {
                return Err("usage: ssn edit <block-id> <text...>".into());
            }
            cmd_edit(home, block, &text)
        }
        "rm" => cmd_rm(home, args.get(1).ok_or("usage: ssn rm <block-id>")?),
        "ls" => cmd_ls(home),
        "cat" => cmd_cat(home, args.get(1).ok_or("usage: ssn cat <doc-id>")?),
        "pair-code" => cmd_pair_code(home),
        "pair" => cmd_pair(
            home,
            args.get(1).ok_or("usage: ssn pair <workspace-key-hex>")?,
        ),
        "push" => cmd_push(home, &server_url(args.get(1))),
        "pull" => cmd_pull(home, &server_url(args.get(1))),
        "help" | "-h" | "--help" => Ok(usage()),
        other => Err(format!("unknown command '{other}'\n\n{}", usage())),
    }
}

fn usage() -> String {
    "ssn — SecureSourceNote CLI\n\
     \n\
     ssn init                 create the local encrypted store\n\
     ssn new <title>          create a note, prints its id\n\
     ssn add <doc> <text...>  append a text block to a note\n\
     ssn edit <block> <text>  replace a block's text\n\
     ssn rm <block>           remove (tombstone) a block\n\
     ssn ls                   list notes\n\
     ssn cat <doc>            print a note\n\
     \n\
     ssn pair-code            print this workspace's sync key (share with another device)\n\
     ssn pair <key-hex>       adopt a workspace sync key from another device\n\
     ssn push [server]        send local changes to the sync server\n\
     ssn pull [server]        fetch remote changes from the sync server\n\
     \n\
     Data lives in $SSN_HOME (default ./.ssn). Server default http://127.0.0.1:8787."
        .into()
}

// --- commands ---------------------------------------------------------------

fn cmd_init(home: &Path) -> Result<String, String> {
    let device = device_id(home)?;
    let mut store = open_store(home)?;
    ensure_ws(&mut store, &device)?;
    Ok(format!(
        "initialized encrypted store at {}",
        home.join("data").display()
    ))
}

fn cmd_new(home: &Path, title: &str) -> Result<String, String> {
    let device = device_id(home)?;
    let mut store = open_store(home)?;
    ensure_ws(&mut store, &device)?;
    let doc = gen_id("doc-");
    commit(
        &mut store,
        &device,
        Payload::CreateDocument {
            workspace: WorkspaceId::new(DEFAULT_WS),
            document: DocumentId::new(doc.as_str()),
            title: title.into(),
        },
    )?;
    Ok(doc)
}

fn cmd_add(home: &Path, doc: &str, text: &str) -> Result<String, String> {
    let device = device_id(home)?;
    let mut store = open_store(home)?;
    let state = replay(store.ops());
    let docid = DocumentId::new(doc);
    let d = state
        .documents
        .get(&docid)
        .ok_or_else(|| format!("no such note: {doc}"))?;
    let after = d
        .blocks
        .iter()
        .rev()
        .find(|b| !b.removed)
        .map(|b| b.id.clone());
    let block = gen_id("blk-");
    commit(
        &mut store,
        &device,
        Payload::InsertBlock {
            document: docid,
            block: BlockId::new(block.as_str()),
            after,
            text: text.into(),
        },
    )?;
    Ok(block)
}

fn cmd_edit(home: &Path, block: &str, text: &str) -> Result<String, String> {
    let device = device_id(home)?;
    let mut store = open_store(home)?;
    let state = replay(store.ops());
    let blockid = BlockId::new(block);
    let doc =
        find_doc_of_block(&state, &blockid).ok_or_else(|| format!("no such block: {block}"))?;
    commit(
        &mut store,
        &device,
        Payload::EditBlock {
            document: doc,
            block: blockid,
            text: text.into(),
        },
    )?;
    Ok(format!("edited {block}"))
}

fn cmd_rm(home: &Path, block: &str) -> Result<String, String> {
    let device = device_id(home)?;
    let mut store = open_store(home)?;
    let state = replay(store.ops());
    let blockid = BlockId::new(block);
    let doc =
        find_doc_of_block(&state, &blockid).ok_or_else(|| format!("no such block: {block}"))?;
    commit(
        &mut store,
        &device,
        Payload::RemoveBlock {
            document: doc,
            block: blockid,
        },
    )?;
    Ok(format!("removed {block}"))
}

fn cmd_ls(home: &Path) -> Result<String, String> {
    let store = open_store(home)?;
    let state = replay(store.ops());
    if state.documents.is_empty() {
        return Ok("(no notes yet — `ssn new <title>`)".into());
    }
    let mut out = String::new();
    for (doc, d) in &state.documents {
        let n = d.blocks.iter().filter(|b| !b.removed).count();
        out.push_str(&format!(
            "{doc}  {}  ({n} block{})\n",
            d.title,
            if n == 1 { "" } else { "s" }
        ));
    }
    Ok(out.trim_end().to_string())
}

fn cmd_cat(home: &Path, doc: &str) -> Result<String, String> {
    let store = open_store(home)?;
    let state = replay(store.ops());
    let d = state
        .documents
        .get(&DocumentId::new(doc))
        .ok_or_else(|| format!("no such note: {doc}"))?;
    let mut out = format!("# {}\n", d.title);
    for b in d.blocks.iter().filter(|b| !b.removed) {
        out.push_str(&format!("[{}] {}\n", b.id, b.text));
        for c in &b.conflicts {
            out.push_str(&format!("    ! conflicting value: {c}\n"));
        }
    }
    Ok(out.trim_end().to_string())
}

// --- helpers ----------------------------------------------------------------

fn ensure_ws(store: &mut LocalStore, device: &DeviceId) -> Result<(), String> {
    let ws = WorkspaceId::new(DEFAULT_WS);
    if !replay(store.ops()).names.contains_key(&ws) {
        commit(
            store,
            device,
            Payload::CreateWorkspace {
                workspace: ws,
                name: "Default".into(),
            },
        )?;
    }
    Ok(())
}

fn commit(store: &mut LocalStore, device: &DeviceId, payload: Payload) -> Result<(), String> {
    let parents = store
        .ops()
        .last()
        .map(|e| vec![e.id.clone()])
        .unwrap_or_default();
    let env = OperationEnvelope::seal(EnvelopeCore {
        v: ENVELOPE_VERSION,
        actor: device.clone(),
        parents,
        authored_ms: now_ms(),
        payload,
    });
    store.commit(&env).map_err(|e| e.to_string())?;
    Ok(())
}

fn find_doc_of_block(state: &WorkspaceState, block: &BlockId) -> Option<DocumentId> {
    state.documents.iter().find_map(|(doc, d)| {
        if d.blocks.iter().any(|b| &b.id == block) {
            Some(doc.clone())
        } else {
            None
        }
    })
}

fn open_store(home: &Path) -> Result<LocalStore, String> {
    let key = load_or_create_key(home)?;
    LocalStore::open(home.join("data"), key).map_err(|e| e.to_string())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn gen_id(prefix: &str) -> String {
    let mut b = [0u8; 6];
    getrandom::getrandom(&mut b).expect("OS CSPRNG unavailable");
    let mut s = String::from(prefix);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn device_id(home: &Path) -> Result<DeviceId, String> {
    std::fs::create_dir_all(home).map_err(|e| e.to_string())?;
    let dp = home.join("device.id");
    if dp.exists() {
        Ok(DeviceId::new(
            std::fs::read_to_string(&dp)
                .map_err(|e| e.to_string())?
                .trim(),
        ))
    } else {
        let id = gen_id("dev-");
        std::fs::write(&dp, &id).map_err(|e| e.to_string())?;
        Ok(DeviceId::new(id))
    }
}

fn load_or_create_key(home: &Path) -> Result<SymKey, String> {
    std::fs::create_dir_all(home).map_err(|e| e.to_string())?;
    let kp = home.join("store.key");
    if kp.exists() {
        let hex = std::fs::read_to_string(&kp).map_err(|e| e.to_string())?;
        Ok(SymKey::from_bytes(
            from_hex32(hex.trim()).ok_or("corrupt store.key")?,
        ))
    } else {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("OS CSPRNG unavailable");
        let hex: String = bytes.iter().map(|x| format!("{x:02x}")).collect();
        std::fs::write(&kp, hex).map_err(|e| e.to_string())?;
        Ok(SymKey::from_bytes(bytes))
    }
}

fn from_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

// --- sync (ROADMAP S5/S6-lite) ----------------------------------------------

fn server_url(arg: Option<&String>) -> String {
    arg.cloned()
        .or_else(|| std::env::var("SSN_SERVER").ok())
        .unwrap_or_else(|| "http://127.0.0.1:8787".into())
}

/// The workspace key is the SHARED sync secret (distinct from the per-device
/// at-rest store key). Envelopes are sealed under it before they leave the
/// device, so the relay only ever sees ciphertext.
fn load_or_create_ws_key(home: &Path) -> Result<SymKey, String> {
    std::fs::create_dir_all(home).map_err(|e| e.to_string())?;
    let kp = home.join("workspace.key");
    if kp.exists() {
        let hex = std::fs::read_to_string(&kp).map_err(|e| e.to_string())?;
        Ok(SymKey::from_bytes(
            from_hex32(hex.trim()).ok_or("corrupt workspace.key")?,
        ))
    } else {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("OS CSPRNG unavailable");
        let hex: String = bytes.iter().map(|x| format!("{x:02x}")).collect();
        std::fs::write(&kp, hex).map_err(|e| e.to_string())?;
        Ok(SymKey::from_bytes(bytes))
    }
}

fn cmd_pair_code(home: &Path) -> Result<String, String> {
    load_or_create_ws_key(home)?; // ensure it exists
    let hex = std::fs::read_to_string(home.join("workspace.key")).map_err(|e| e.to_string())?;
    Ok(format!(
        "workspace sync key (secret — import on another device with `ssn pair`):\n{}",
        hex.trim()
    ))
}

fn cmd_pair(home: &Path, hex: &str) -> Result<String, String> {
    from_hex32(hex.trim()).ok_or("invalid key: expected 64 hex chars")?;
    std::fs::create_dir_all(home).map_err(|e| e.to_string())?;
    std::fs::write(home.join("workspace.key"), hex.trim()).map_err(|e| e.to_string())?;
    Ok("workspace sync key adopted".into())
}

fn cmd_push(home: &Path, server: &str) -> Result<String, String> {
    let wk = load_or_create_ws_key(home)?;
    let bucket = wk.public_tag(b"ssn-bucket-v1");
    let mut store = open_store(home)?;
    let (blobs, ids): (Vec<String>, Vec<OpId>) = {
        let outbox = store.outbox();
        (
            outbox.iter().map(|e| wk.seal_line(&e.to_bytes())).collect(),
            outbox.iter().map(|e| e.id.clone()).collect(),
        )
    };
    if blobs.is_empty() {
        return Ok("nothing to push".into());
    }
    ureq::post(&format!("{server}/push/{bucket}"))
        .send_string(&json!({ "blobs": blobs }).to_string())
        .map_err(|e| format!("push failed: {e}"))?;
    for id in &ids {
        store.mark_acked(id).map_err(|e| e.to_string())?;
    }
    Ok(format!("pushed {} op(s)", ids.len()))
}

fn cmd_pull(home: &Path, server: &str) -> Result<String, String> {
    let wk = load_or_create_ws_key(home)?;
    let bucket = wk.public_tag(b"ssn-bucket-v1");
    let cursor = read_cursor(home);
    let resp = ureq::get(&format!("{server}/pull/{bucket}?since={cursor}"))
        .call()
        .map_err(|e| format!("pull failed: {e}"))?
        .into_string()
        .map_err(|e| e.to_string())?;
    let v: serde_json::Value = serde_json::from_str(&resp).map_err(|e| e.to_string())?;
    let new_cursor = v
        .get("cursor")
        .and_then(|c| c.as_u64())
        .unwrap_or(cursor as u64) as usize;
    let blobs = v
        .get("blobs")
        .and_then(|b| b.as_array())
        .cloned()
        .unwrap_or_default();

    let mut store = open_store(home)?;
    let mut applied = 0usize;
    for b in &blobs {
        let line = match b.as_str() {
            Some(s) => s,
            None => continue,
        };
        let bytes = wk
            .open_line(line)
            .ok_or("cannot decrypt a pulled blob (wrong workspace key?)")?;
        let env = OperationEnvelope::from_bytes(&bytes).ok_or("malformed pulled envelope")?;
        if store.commit(&env).map_err(|e| e.to_string())? {
            applied += 1;
        }
        // a pulled op is already on the server — mark it acked so we never bounce it back
        store.mark_acked(&env.id).map_err(|e| e.to_string())?;
    }
    write_cursor(home, new_cursor)?;
    Ok(format!("pulled {applied} new op(s) (cursor {new_cursor})"))
}

fn read_cursor(home: &Path) -> usize {
    std::fs::read_to_string(home.join("pull.cursor"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn write_cursor(home: &Path, cursor: usize) -> Result<(), String> {
    std::fs::write(home.join("pull.cursor"), cursor.to_string()).map_err(|e| e.to_string())
}
