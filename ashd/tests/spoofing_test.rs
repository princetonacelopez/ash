//! Spoofing resistance integration tests (M0 milestone exit criteria)
//!
//! Spec §3.2:
//! Problem: any program can print `\e]133;D;0\a` and fake a successful block.
//! Solution:
//! 1. The shell hook writes block events to private fd.
//! 2. ashd treats that as the only authority.
//! 3. The PTY proxy removes or escapes OSC 133 and ash OSC sequences in program output.
//! 4. ashd re-emits them itself.

use ashd::pty::{self, osc133};

#[test]
fn test_spoofed_osc133_prompt_stripped() {
    let malicious_output = b"hello\x1b]133;A\x07world";
    let pty_proxy = pty::PtyProxy::new(
        "test-session".to_string(),
        tempfile::tempdir().unwrap().path().join("rec.bin"),
        tokio::sync::broadcast::channel(16).0,
    )
    .unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let sanitized = rt.block_on(pty_proxy.process_output(malicious_output, None)).unwrap();

    let text = String::from_utf8_lossy(&sanitized.bytes);
    assert!(!text.contains("\x1b]133;A"));
    assert_eq!(text, "helloworld");
}

#[test]
fn test_spoofed_osc133_success_exit_stripped() {
    // Malicious script tries to fake exit 0
    let malicious = b"command output\x1b]133;D;0\x07trailing text";
    let pty_proxy = pty::PtyProxy::new(
        "test-session".to_string(),
        tempfile::tempdir().unwrap().path().join("rec.bin"),
        tokio::sync::broadcast::channel(16).0,
    )
    .unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let sanitized = rt.block_on(pty_proxy.process_output(malicious, None)).unwrap();

    let text = String::from_utf8_lossy(&sanitized.bytes);
    assert!(!text.contains("\x1b]133;D;0"));
    assert_eq!(text, "command outputtrailing text");
}

#[test]
fn test_spoofed_iterm2_sequences_stripped() {
    let malicious = b"text\x1b]1337;SetMark\x07more text";
    let pty_proxy = pty::PtyProxy::new(
        "test-session".to_string(),
        tempfile::tempdir().unwrap().path().join("rec.bin"),
        tokio::sync::broadcast::channel(16).0,
    )
    .unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let sanitized = rt.block_on(pty_proxy.process_output(malicious, None)).unwrap();

    let text = String::from_utf8_lossy(&sanitized.bytes);
    assert!(!text.contains("1337"));
    assert_eq!(text, "textmore text");
}

#[test]
fn test_vouched_sequences_re_emitted_correctly() {
    let pty_proxy = pty::PtyProxy::new(
        "test-session".to_string(),
        tempfile::tempdir().unwrap().path().join("rec.bin"),
        tokio::sync::broadcast::channel(16).0,
    )
    .unwrap();

    // Sequence originated from ashd itself
    let vouched_prompt = osc133::prompt_start();
    let re_emitted = pty_proxy.vouch_sequence(std::str::from_utf8(vouched_prompt).unwrap());
    assert_eq!(re_emitted, vouched_prompt);

    let vouched_end = osc133::command_end(0, "01JD5Z8K7Q3M2X9T4R6W1B0HNE", 420);
    let end_str = std::str::from_utf8(&vouched_end).unwrap();
    let re_emitted_end = pty_proxy.vouch_sequence(end_str);
    assert_eq!(re_emitted_end, vouched_end);
}
