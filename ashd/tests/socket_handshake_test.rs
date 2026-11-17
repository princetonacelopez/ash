//! Socket Capability Handshake and Event Stream Tests (Spec §3.5, §3.6)

use ashd::block::{capabilities, Event, EventKind, EventPayload, SessionStartPayload};
use ashd::socket::SocketServer;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_socket_handshake_and_event_stream() {
    let session_id = format!("test-session-{}", ulid::Ulid::new());
    let server = Arc::new(SocketServer::new(session_id.clone()).unwrap());
    let socket_path = server.socket_path().clone();

    let server_handle = tokio::spawn({
        let server = Arc::clone(&server);
        async move {
            let _ = server.run().await;
        }
    });

    // Wait for server to bind
    sleep(Duration::from_millis(50)).await;

    // Connect client
    let mut stream = UnixStream::connect(&socket_path).await.unwrap();

    // Send hello handshake
    let hello = serde_json::json!({
        "type": "hello",
        "v": 1,
        "client": "ghostty/1.3",
        "wants": [capabilities::BLOCKS, capabilities::A11Y_TREE, "unsupported_extra_cap"]
    });
    let mut hello_line = serde_json::to_string(&hello).unwrap();
    hello_line.push('\n');
    stream.write_all(hello_line.as_bytes()).await.unwrap();

    // Read welcome response
    let (reader, _writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).await.unwrap();

    let welcome: serde_json::Value = serde_json::from_str(response_line.trim()).unwrap();
    assert_eq!(welcome["type"], "welcome");
    let granted: Vec<String> = welcome["granted"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(granted.contains(&capabilities::BLOCKS.to_string()));
    assert!(granted.contains(&capabilities::A11Y_TREE.to_string()));

    let denied: Vec<String> = welcome["denied"].as_array().unwrap().iter().map(|v| v["cap"].as_str().unwrap().to_string()).collect();
    assert!(denied.contains(&"unsupported_extra_cap".to_string()));

    // Now test event publish and reception
    let event = Event::new(
        session_id.clone(),
        None,
        EventKind::SessionStart,
        EventPayload::SessionStart(SessionStartPayload {
            shell: "zsh".to_string(),
            tty_rows: 24,
            tty_cols: 80,
            capabilities: vec![],
        }),
    );
    server.publish_event(&event).unwrap();

    let mut event_line = String::new();
    reader.read_line(&mut event_line).await.unwrap();
    let received: serde_json::Value = serde_json::from_str(event_line.trim()).unwrap();
    assert_eq!(received["type"], "session_start");
    assert_eq!(received["session"], session_id);

    server_handle.abort();
    let _ = std::fs::remove_file(socket_path);
}
