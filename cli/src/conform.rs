//! `ash-conform` - conformance harness (spec v0.2 §8.3).
//!
//! Drives a target daemon over its socket and writes a JSON report:
//! implementation, version, roles, levels, per-test results and environment.
//! Usage: ash-conform --socket <path> [--out report.json]
//! Covers the socket-level Core tests (CORE-02, CORE-04, CORE-05 and the
//! handshake). Sandbox and policy levels run via `cargo test -p ashd --test conformance_test`.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

fn connect(path: &str) -> std::io::Result<(BufReader<UnixStream>, UnixStream)> {
    let s = UnixStream::connect(path)?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    Ok((BufReader::new(s.try_clone()?), s))
}

fn read(r: &mut BufReader<UnixStream>) -> Option<Value> {
    let mut l = String::new();
    r.read_line(&mut l).ok()?;
    serde_json::from_str(l.trim()).ok()
}

fn handshake(path: &str) -> Result<(BufReader<UnixStream>, UnixStream, Value), String> {
    let (mut r, mut w) = connect(path).map_err(|e| e.to_string())?;
    writeln!(w, "{}", json!({"v":1,"type":"hello","client":"ash-conform","wants":["blocks"]})).map_err(|e| e.to_string())?;
    let welcome = read(&mut r).ok_or("no welcome")?;
    Ok((r, w, welcome))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let get = |k: &str| args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).cloned();
    let socket = match get("--socket") {
        Some(s) => s,
        None => {
            eprintln!("usage: ash-conform --socket <path> [--out report.json]");
            std::process::exit(2);
        }
    };
    let mut results: Vec<Value> = vec![];
    let mut rec = |id: &str, r: Result<(), String>| {
        results.push(json!({"id": id, "passed": r.is_ok(), "detail": r.err()}));
    };

    let mut server = Value::Null;
    rec("CORE-HANDSHAKE", (|| {
        let (_, _, w) = handshake(&socket)?;
        if w["type"] != "welcome" { return Err("expected welcome".into()); }
        if w["limits"]["max_line"].is_null() { return Err("welcome missing limits".into()); }
        server = w["server"].clone();
        Ok(())
    })());
    rec("CORE-02", (|| {
        let (mut r, mut w, _) = handshake(&socket)?;
        let big = vec![b'a'; 2 * 1024 * 1024];
        w.write_all(&big).and_then(|_| w.write_all(b"\n")).map_err(|e| e.to_string())?;
        let e = read(&mut r).ok_or("no error reply")?;
        if e["data"]["code"] != "oversize" { return Err(format!("got {}", e)); }
        writeln!(w, "{}", json!({"type":"ping","id":"p"})).map_err(|e| e.to_string())?;
        let a = read(&mut r).ok_or("connection died")?;
        if a["type"] != "ack" { return Err("no ack after oversize".into()); }
        Ok(())
    })());
    rec("CORE-04", (|| {
        let (mut r, mut w, _) = handshake(&socket)?;
        writeln!(w, "{}", json!({"type":"x-vendor.unknown","foo":1})).map_err(|e| e.to_string())?;
        writeln!(w, "{}", json!({"type":"ping","id":"q","unknown_field":true})).map_err(|e| e.to_string())?;
        let a = read(&mut r).ok_or("no ack")?;
        if a["type"] != "ack" || a["id"] != "q" { return Err("unknown message not ignored".into()); }
        Ok(())
    })());
    rec("CORE-05", (|| {
        let (mut r, mut w, _) = handshake(&socket)?;
        writeln!(w, "{}", json!({"type":"replay","id":"r","from_seq":0})).map_err(|e| e.to_string())?;
        let mut last: Option<u64> = None;
        for _ in 0..50 {
            match read(&mut r) {
                Some(v) if v["type"] == "warn" && v["data"]["code"] == "replay.gap" => return Ok(()),
                Some(v) => {
                    if let Some(s) = v["seq"].as_u64() {
                        if let Some(l) = last { if s != l + 1 { return Err(format!("gap {}->{}", l, s)); } }
                        last = Some(s);
                    }
                }
                None => break,
            }
        }
        Ok(())
    })());

    let passed = results.iter().filter(|r| r["passed"] == true).count();
    let report = json!({
        "implementation": server["name"].as_str().unwrap_or("unknown"),
        "version": server["version"].as_str().unwrap_or("unknown"),
        "roles": ["daemon"],
        "levels": { "core": results.iter().all(|r| r["passed"] == true) },
        "results": results,
        "summary": {"passed": passed, "total": results.len()},
        "environment": { "os": std::env::consts::OS, "arch": std::env::consts::ARCH },
    });
    let text = serde_json::to_string_pretty(&report).unwrap();
    match get("--out") {
        Some(p) => std::fs::write(p, &text).unwrap(),
        None => println!("{}", text),
    }
    if passed != report["summary"]["total"].as_u64().unwrap() as usize {
        std::process::exit(1);
    }
}
