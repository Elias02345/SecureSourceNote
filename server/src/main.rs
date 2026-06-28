use std::path::PathBuf;
use tiny_http::{Header, Method, Response, Server};

fn main() {
    let addr = std::env::var("SSN_SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:8787".into());
    let dir = std::env::var_os("SSN_SERVER_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".ssn-server"));

    let server = match Server::http(&addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to bind {addr}: {e}");
            std::process::exit(1);
        }
    };
    println!(
        "ssn-server (zero-knowledge relay) listening on http://{addr} — storage: {}",
        dir.display()
    );

    let json_header = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
        .expect("static header is valid");

    for mut req in server.incoming_requests() {
        let method = match req.method() {
            Method::Get => "GET",
            Method::Post => "POST",
            _ => "OTHER",
        };
        let path = req.url().to_string();
        let mut body = String::new();
        let _ = req.as_reader().read_to_string(&mut body);

        let resp = ssn_server::handle(method, &path, &body, &dir);
        let http = Response::from_string(resp.body)
            .with_status_code(resp.status)
            .with_header(json_header.clone());
        let _ = req.respond(http);
    }
}
