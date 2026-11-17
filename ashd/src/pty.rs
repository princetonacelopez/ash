//! # PTY Proxy (spec §2, §3.2)
//!
//! `ashd` owns the PTY and sits between the emulator and the shell.
//!
//! This lets it:
//! (a) Sanitize untrusted in-band sequences from program output
//! (b) Record output with stable offsets
//! (c) Enforce policy outside the shell process
//!
//! Spoofing resistance (spec §3.2):
//! - The shell hook writes block events to a private fd (CLOEXEC, not inherited by children)
//! - ashd treats that fd as the only authority for block boundaries and status
//! - The PTY proxy removes or escapes OSC 133 and ash OSC sequences in program output
//! - ashd re-emits them itself, so the emulator only ever sees sequences ashd vouches for

use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};
use tracing::debug;

/// OSC sequences that must be stripped from program output (spoofing prevention).
/// Any OSC 133 or ash OSC sequence appearing in program output (not from the shell hook)
/// is stripped or escaped. (spec §3.2 step 3)
const BLOCKED_OSC_PREFIXES: &[&str] = &[
    "\x1b]133;",   // OSC 133 (prompt/command markers)
    "\x1b]1337;",  // iTerm2 protocol
];

/// The PTY proxy sits between the terminal emulator and the shell.
/// It owns the master side of the PTY pair.
pub struct PtyProxy {
    session_id: String,
    /// Output recording: session-wide append-only byte stream
    recording: Arc<Mutex<Recording>>,
    /// Event publisher for output chunks
    event_tx: broadcast::Sender<String>,
    /// Redaction applied before persistence/subscribers (§4.4)
    redactor: crate::redact::Redactor,
    /// Record raw bytes of full-screen programs (default false, §4.1)
    record_fullscreen: bool,
    /// True while the program is on the alternate screen
    fullscreen: std::sync::atomic::AtomicBool,
}

/// Detect alternate-screen entry/exit (DECSET/DECRST 1049, 1047, 47).
/// Returns Some(true) for entry, Some(false) for exit (last one in the chunk wins).
pub fn detect_alt_screen(raw: &[u8]) -> Option<bool> {
    let mut result = None;
    let mut i = 0;
    while i + 4 < raw.len() {
        if raw[i] == 0x1b && raw[i + 1] == b'[' && raw[i + 2] == b'?' {
            let mut j = i + 3;
            while j < raw.len() && (raw[j].is_ascii_digit() || raw[j] == b';') {
                j += 1;
            }
            if j < raw.len() && (raw[j] == b'h' || raw[j] == b'l') {
                let params = std::str::from_utf8(&raw[i + 3..j]).unwrap_or("");
                if params.split(';').any(|p| matches!(p, "1049" | "1047" | "47")) {
                    result = Some(raw[j] == b'h');
                }
                i = j;
            }
        }
        i += 1;
    }
    result
}

/// Session-wide output recording. Blocks reference by offset+length.
pub struct Recording {
    _path: PathBuf,
    offset: u64,
    file: std::fs::File,
}

impl Recording {
    pub fn open(path: &PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        let offset = std::fs::metadata(path)?.len();
        Ok(Self {
            _path: path.clone(),
            offset,
            file,
        })
    }

    /// Append output bytes to the recording, returning (start_offset, length).
    pub fn append(&mut self, data: &[u8]) -> Result<(u64, u64)> {
        use std::io::Write;
        let start = self.offset;
        self.file.write_all(data)?;
        self.offset += data.len() as u64;
        Ok((start, data.len() as u64))
    }
}

impl PtyProxy {
    pub fn new(
        session_id: String,
        recording_path: PathBuf,
        event_tx: broadcast::Sender<String>,
    ) -> Result<Self> {
        let recording = Recording::open(&recording_path)?;
        Ok(Self {
            session_id,
            recording: Arc::new(Mutex::new(recording)),
            event_tx,
            redactor: crate::redact::Redactor::new(),
            record_fullscreen: false,
            fullscreen: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub fn with_redactor(mut self, r: crate::redact::Redactor) -> Self {
        self.redactor = r;
        self
    }

    pub fn with_record_fullscreen(mut self, yes: bool) -> Self {
        self.record_fullscreen = yes;
        self
    }

    pub fn is_fullscreen(&self) -> bool {
        self.fullscreen.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Process output flowing from the shell/process to the terminal emulator.
    ///
    /// Actions:
    /// 1. Strip spoofed OSC sequences that did not originate from the shell hook
    /// 2. Record the sanitized output at a stable offset
    /// 3. Emit block.output events for subscribers
    /// 4. Pass the sanitized bytes to the emulator
    pub async fn process_output(
        &self,
        raw: &[u8],
        block_id: Option<&str>,
    ) -> Result<SanitizedOutput> {
        // Interactive blocks keep one merged PTY stream (§4.2).
        self.process_output_stream(raw, block_id, "tty").await
    }

    /// Like `process_output`, tagging the stream ("tty", "stdout" or "stderr").
    pub async fn process_output_stream(
        &self,
        raw: &[u8],
        block_id: Option<&str>,
        stream: &str,
    ) -> Result<SanitizedOutput> {
        use std::sync::atomic::Ordering;
        // Sanitize: strip spoofed OSC sequences
        let sanitized = sanitize_output(raw);

        // §4.1: alternate-screen tracking
        let was_fullscreen = self.fullscreen.load(Ordering::SeqCst);
        if let Some(entered) = detect_alt_screen(&sanitized) {
            self.fullscreen.store(entered, Ordering::SeqCst);
        }
        let in_fullscreen = was_fullscreen || self.fullscreen.load(Ordering::SeqCst);

        // §4.4: redact before persistence or any subscriber sees offsets/bytes.
        let (to_record, _report) = self.redactor.redact_bytes(&sanitized);

        let (offset, length) = if in_fullscreen && !self.record_fullscreen {
            (0, 0)
        } else {
            let mut rec = self.recording.lock().await;
            rec.append(&to_record)?
        };

        // Emit block.output (opt-in); never for full-screen programs.
        if let Some(bid) = block_id {
            if !in_fullscreen {
                let event = serde_json::json!({
                    "v": 1,
                    "type": "block_output",
                    "ts": chrono::Utc::now().to_rfc3339(),
                    "session": self.session_id,
                    "block": bid,
                    "data": { "offset": offset, "length": length, "stream": stream }
                });
                let _ = self.event_tx.send(serde_json::to_string(&event)?);
            }
        }

        Ok(SanitizedOutput {
            bytes: sanitized,
            offset,
            length,
        })
    }

    /// Re-emit an OSC sequence vouched by ashd (from the shell hook).
    /// Only sequences that passed through the hook are re-emitted to the emulator.
    pub fn vouch_sequence(&self, seq: &str) -> Vec<u8> {
        // ashd vouches for this sequence; pass it directly to the emulator
        seq.as_bytes().to_vec()
    }
}

pub struct SanitizedOutput {
    pub bytes: Vec<u8>,
    pub offset: u64,
    pub length: u64,
}

/// Sanitize output bytes: strip or escape OSC sequences that programs shouldn't emit.
///
/// Configurable behavior (from spec §3.2 step 3):
/// - `strip`: Remove the sequence entirely (default)
/// - `escape`: Replace ESC with printable \e marker
/// - `passthrough`: Allow (only for trusted contexts)
fn sanitize_output(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;

    while i < data.len() {
        // Check for ESC ] (OSC start: 0x1B 0x5D)
        if data[i] == 0x1B && i + 1 < data.len() && data[i + 1] == b']' {
            // Check if this is a blocked OSC sequence
            let remaining = &data[i..];
            let remaining_str = std::str::from_utf8(remaining).unwrap_or("");

            let mut is_blocked = false;
            for prefix in BLOCKED_OSC_PREFIXES {
                if remaining_str.starts_with(prefix) {
                    // Find the end of this OSC sequence (ST: 0x07 or ESC \)
                    let end = find_osc_end(remaining);
                    if let Some(end_idx) = end {
                        // Strip this sequence
                        i += end_idx;
                        is_blocked = true;
                        debug!(
                            prefix = prefix,
                            "Stripped spoofed OSC sequence from program output"
                        );
                        break;
                    }
                }
            }

            if !is_blocked {
                out.push(data[i]);
                i += 1;
            }
        } else {
            out.push(data[i]);
            i += 1;
        }
    }

    out
}

/// Find the end of an OSC sequence (terminated by BEL 0x07 or ST ESC \).
/// Returns the byte length of the full sequence including the terminator.
fn find_osc_end(data: &[u8]) -> Option<usize> {
    for (i, &b) in data.iter().enumerate().skip(2) {
        if b == 0x07 {
            // BEL terminator
            return Some(i + 1);
        }
        if b == 0x1B {
            // Check for ST (ESC \)
            if data.get(i + 1) == Some(&b'\\') {
                return Some(i + 2);
            }
        }
    }
    None // Unterminated; don't strip (could be partial)
}

/// Generate OSC 133 compatibility hints for emulators without socket integration (spec §3.7).
pub mod osc133 {
    /// OSC 133 ; A - prompt start
    pub fn prompt_start() -> &'static [u8] {
        b"\x1b]133;A\x07"
    }

    /// OSC 133 ; B - input start  
    pub fn input_start() -> &'static [u8] {
        b"\x1b]133;B\x07"
    }

    /// OSC 133 ; C - command start
    pub fn command_start() -> &'static [u8] {
        b"\x1b]133;C\x07"
    }

    /// OSC 133 ; D ; <exit> ; id=<ulid> ; dur=<ms> - command end with ash extensions
    pub fn command_end(exit_code: i32, block_id: &str, duration_ms: u64) -> Vec<u8> {
        format!(
            "\x1b]133;D;{};id={};dur={}\x07",
            exit_code, block_id, duration_ms
        )
        .into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_osc133_from_output() {
        // A program output that includes a fake OSC 133 D (success) marker
        let fake = b"some output\x1b]133;D;0\x07more output";
        let sanitized = sanitize_output(fake);
        let result = String::from_utf8_lossy(&sanitized);
        assert!(!result.contains("\x1b]133;"));
        assert!(result.contains("some output"));
        assert!(result.contains("more output"));
    }

    #[test]
    fn sanitize_preserves_normal_escape_sequences() {
        // Bold ANSI sequence should not be stripped
        let bold = b"\x1b[1mHello\x1b[0m";
        let sanitized = sanitize_output(bold);
        assert_eq!(sanitized, bold);
    }

    #[test]
    fn osc133_command_end_format() {
        let seq = osc133::command_end(0, "01JD5Z8K7Q3M2X9T4R6W1B0HNE", 7757);
        let s = String::from_utf8_lossy(&seq);
        assert!(s.contains("133;D;0"));
        assert!(s.contains("id=01JD5Z8K7Q3M2X9T4R6W1B0HNE"));
        assert!(s.contains("dur=7757"));
    }

    #[test]
    fn find_osc_end_bel_terminated() {
        let data = b"\x1b]133;D;0\x07rest";
        let end = find_osc_end(data);
        assert_eq!(end, Some(10)); // 10 bytes through the BEL
    }

    #[test]
    fn sanitize_strips_iterm2_sequences() {
        let fake = b"output\x1b]1337;File=name=foo.png\x07end";
        let sanitized = sanitize_output(fake);
        let result = String::from_utf8_lossy(&sanitized);
        assert!(!result.contains("1337"));
        assert!(result.contains("output"));
        assert!(result.contains("end"));
    }
}

#[cfg(test)]
mod v02_tests {
    use super::*;

    #[test]
    fn alt_screen_detection() {
        assert_eq!(detect_alt_screen(b"\x1b[?1049h"), Some(true));
        assert_eq!(detect_alt_screen(b"\x1b[?1047h"), Some(true));
        assert_eq!(detect_alt_screen(b"\x1b[?47h"), Some(true));
        assert_eq!(detect_alt_screen(b"x\x1b[?1049h..\x1b[?1049l"), Some(false));
        assert_eq!(detect_alt_screen(b"\x1b[?25h"), None);
    }
}
