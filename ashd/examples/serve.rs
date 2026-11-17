//! Minimal socket server for conformance runs: `cargo run -p ashd --example serve -- <socket-path>`
use ashd::block::{Event, EventKind};
use ashd::socket::SocketServer;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let path = std::env::args().nth(1).expect("socket path");
    std::env::set_var("ASH_SOCKET", &path);
    let s = Arc::new(SocketServer::new("conform".into()).unwrap());
    for i in 0..3 {
        let e = Event::server("conform".into(), None, EventKind::Warn, serde_json::json!({"n": i}));
        s.publish_event(&e).unwrap();
    }
    s.run().await.unwrap();
}
