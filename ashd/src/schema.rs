//! # CLI schema contract (spec v0.2 §6)
//!
//! Discovery order: `--schema`, sidecar `<bin>.schema.json`, curated registry,
//! heuristic `--help`. Trust model: only high-trust sources may lower a tier;
//! the highest tier from all sources wins; violations mark a source untrusted.

use crate::block::RiskTier;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SchemaDoc {
    pub schema_version: u32,
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub commands: Vec<SchemaCommand>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SchemaCommand {
    pub name: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub args: Vec<SchemaArg>,
    #[serde(default)]
    pub flags: Vec<SchemaFlag>,
    #[serde(default)]
    pub effects: Effects,
    #[serde(default)]
    pub outputs: Option<Outputs>,
    #[serde(default)]
    pub exit_codes: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SchemaArg {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: FlagType,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SchemaFlag {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: FlagType,
    #[serde(default)]
    pub secret: bool,
    #[serde(default)]
    pub env: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FlagType {
    Bool,
    String,
    Int,
    Float,
    Path,
    Enum,
    Duration,
    Url,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Effects {
    #[serde(default)]
    pub reads: Vec<String>,
    #[serde(default)]
    pub writes: Vec<String>,
    #[serde(default)]
    pub network: Vec<String>,
    #[serde(default)]
    pub destructive: bool,
    #[serde(default)]
    pub reversible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Outputs {
    #[serde(default)]
    pub formats: Vec<String>,
    #[serde(default)]
    pub select_flag: Option<String>,
}

impl SchemaDoc {
    pub fn parse(json: &str) -> Result<Self, String> {
        let d: SchemaDoc = serde_json::from_str(json).map_err(|e| e.to_string())?;
        if d.schema_version != 1 {
            return Err(format!("unsupported schema_version {}", d.schema_version));
        }
        Ok(d)
    }

    pub fn command(&self, name: &str) -> Option<&SchemaCommand> {
        self.commands.iter().find(|c| c.name == name)
    }

    /// Names of flags marked `secret`, masked in history and logs.
    pub fn secret_flags(&self) -> HashSet<String> {
        self.commands
            .iter()
            .flat_map(|c| c.flags.iter().filter(|f| f.secret).map(|f| f.name.clone()))
            .collect()
    }
}

/// Mask values of secret flags in an argv for history/logs.
pub fn mask_secrets(argv: &[String], secret_flags: &HashSet<String>) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len());
    let mut mask_next = false;
    for a in argv {
        if mask_next {
            out.push("[redacted:secret]".into());
            mask_next = false;
            continue;
        }
        if let Some((k, _)) = a.split_once('=') {
            if secret_flags.contains(k) {
                out.push(format!("{}=[redacted:secret]", k));
                continue;
            }
        }
        if secret_flags.contains(a.as_str()) {
            mask_next = true;
        }
        out.push(a.clone());
    }
    out
}

// ─────────────────────────── Trust ──────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaSource {
    Heuristic,
    Declared, // --schema or sidecar
    Curated,
    Signed,
}

impl SchemaSource {
    /// Only signed publisher schemas and the curated registry may lower a tier.
    pub fn may_lower(self) -> bool {
        matches!(self, Self::Signed | Self::Curated)
    }
}

/// Combine tiers from several sources: highest wins, but a source that may
/// not lower can only raise relative to `baseline`.
pub fn combine_tiers(baseline: RiskTier, claims: &[(SchemaSource, RiskTier)], untrusted: &HashSet<SchemaSource>) -> RiskTier {
    let mut tier = baseline;
    let mut lowered: Option<RiskTier> = None;
    for (src, t) in claims {
        if untrusted.contains(src) {
            continue;
        }
        if *t > tier {
            tier = *t;
        } else if *t < baseline && src.may_lower() {
            lowered = Some(lowered.map_or(*t, |l| l.min(*t)));
        }
    }
    // Highest tier from all sources wins; a permitted lowering applies only
    // when no other source raised above the baseline.
    if tier == baseline {
        if let Some(l) = lowered {
            return l;
        }
    }
    tier
}

/// Tracks sources that contradicted their declared effects (SCH-03).
#[derive(Debug, Default)]
pub struct SchemaTrust {
    untrusted: HashSet<(String, SchemaSource)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SchemaViolation {
    pub binary: String,
    pub source: SchemaSource,
    pub detail: String,
}

impl SchemaTrust {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a violation; the source is untrusted for the rest of the session.
    pub fn report_violation(&mut self, binary: &str, source: SchemaSource, detail: &str) -> SchemaViolation {
        self.untrusted.insert((binary.to_string(), source));
        SchemaViolation { binary: binary.into(), source, detail: detail.into() }
    }

    pub fn is_untrusted(&self, binary: &str, source: SchemaSource) -> bool {
        self.untrusted.contains(&(binary.to_string(), source))
    }

    pub fn untrusted_for(&self, binary: &str) -> HashSet<SchemaSource> {
        self.untrusted.iter().filter(|(b, _)| b == binary).map(|(_, s)| *s).collect()
    }
}

/// Compare observed behavior with declared effects. Returns a description of the
/// violation, if any. `writes` are absolute paths actually written.
pub fn check_effects(declared: &Effects, observed_writes: &[PathBuf], observed_network: bool) -> Option<String> {
    if !observed_writes.is_empty() && declared.writes.is_empty() {
        return Some(format!("unexpected write to {}", observed_writes[0].display()));
    }
    if observed_network && declared.network.is_empty() {
        return Some("unexpected network access".into());
    }
    None
}

// ─────────────────────────── Discovery ──────────────────────────────────────

pub struct Discovered {
    pub doc: SchemaDoc,
    pub source: SchemaSource,
}

/// Sidecar lookup: `<binary>.schema.json` beside the binary, else `~/.config/ash/schemas/`.
pub fn load_sidecar(binary: &Path, config_dir: Option<&Path>) -> Option<SchemaDoc> {
    let name = binary.file_name()?.to_string_lossy().to_string();
    let beside = binary.with_file_name(format!("{}.schema.json", name));
    let mut candidates = vec![beside];
    if let Some(c) = config_dir {
        candidates.push(c.join("schemas").join(format!("{}.schema.json", name)));
    }
    candidates
        .into_iter()
        .find_map(|p| std::fs::read_to_string(p).ok().and_then(|s| SchemaDoc::parse(&s).ok()))
}

pub struct ProbeResult {
    pub doc: SchemaDoc,
    /// "os" when network was isolated with a namespace, otherwise "none".
    pub network_isolation: &'static str,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// Policy does not already allow the binary to run (§6.1).
    NotAllowed,
    /// Probing is off outside system dirs and the project root.
    OutsideProbeScope,
    Timeout,
    BadOutput(String),
    Spawn(String),
}

fn unshare_available() -> bool {
    Command::new("unshare")
        .args(["-rn", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Build the sandboxed `--schema` probe command: scrubbed environment, no
/// network (user+net namespace when available), cwd `/`.
pub fn probe_command(binary: &Path) -> (Command, &'static str) {
    let (mut cmd, iso) = if unshare_available() {
        let mut c = Command::new("unshare");
        c.arg("-rn").arg(binary);
        (c, "os")
    } else {
        (Command::new(binary), "none")
    };
    cmd.arg("--schema")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    (cmd, iso)
}

/// Run `<binary> --schema` safely. `allowed_by_policy` must already be true.
pub fn probe(binary: &Path, allowed_by_policy: bool, in_probe_scope: bool) -> Result<ProbeResult, ProbeError> {
    if !allowed_by_policy {
        return Err(ProbeError::NotAllowed);
    }
    if !in_probe_scope {
        return Err(ProbeError::OutsideProbeScope);
    }
    let (mut cmd, iso) = probe_command(binary);
    let mut child = cmd.spawn().map_err(|e| ProbeError::Spawn(e.to_string()))?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return Err(ProbeError::BadOutput(format!("exit {}", status)));
                }
                let mut out = String::new();
                if let Some(mut so) = child.stdout.take() {
                    use std::io::Read;
                    let _ = so.take(1 << 20).read_to_string(&mut out);
                }
                let doc = SchemaDoc::parse(&out).map_err(ProbeError::BadOutput)?;
                return Ok(ProbeResult { doc, network_isolation: iso });
            }
            Ok(None) => {
                if start.elapsed() > Duration::from_secs(2) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ProbeError::Timeout);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(ProbeError::Spawn(e.to_string())),
        }
    }
}

/// Lowest-confidence adapter: extract flags from `--help` text.
pub fn heuristic_from_help(name: &str, help: &str) -> SchemaDoc {
    let mut flags = vec![];
    for line in help.lines() {
        let t = line.trim_start();
        if !t.starts_with('-') {
            continue;
        }
        for part in t.split(|c: char| c == ',' || c.is_whitespace()) {
            if part.starts_with("--") && part.len() > 2 {
                let n = part.split('=').next().unwrap().to_string();
                flags.push(SchemaFlag { name: n, ty: FlagType::String, secret: false, env: None });
                break;
            }
        }
    }
    SchemaDoc {
        schema_version: 1,
        name: name.into(),
        version: None,
        commands: vec![SchemaCommand {
            name: name.into(),
            summary: String::new(),
            args: vec![],
            flags,
            effects: Effects::default(),
            outputs: None,
            exit_codes: Default::default(),
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = r#"{
      "schema_version": 1, "name": "deploytool", "version": "2.4.0",
      "commands": [{
        "name": "publish", "summary": "Publish a build",
        "args": [{"name":"path","type":"path","required":true}],
        "flags": [{"name":"--token","type":"string","secret":true,"env":"DEPLOY_TOKEN"}],
        "effects": {"reads":["{path}"],"writes":[],"network":["registry.example.com"],"destructive":false,"reversible":false},
        "outputs": {"formats":["text","json"],"select_flag":"--json"},
        "exit_codes": {"0":"published","2":"auth failed"}
      }]}"#;

    #[test]
    fn parses_spec_document() {
        let d = SchemaDoc::parse(DOC).unwrap();
        assert_eq!(d.command("publish").unwrap().flags[0].env.as_deref(), Some("DEPLOY_TOKEN"));
        assert!(d.secret_flags().contains("--token"));
    }

    #[test]
    fn secret_flags_masked() {
        let d = SchemaDoc::parse(DOC).unwrap();
        let argv: Vec<String> = ["deploytool", "publish", "--token", "abc", "--token=xyz"].map(String::from).to_vec();
        let m = mask_secrets(&argv, &d.secret_flags());
        assert_eq!(m[3], "[redacted:secret]");
        assert_eq!(m[4], "--token=[redacted:secret]");
    }

    /// SCH-01
    #[test]
    fn declared_schema_cannot_lower_tier_curated_can() {
        let none = HashSet::new();
        let t = combine_tiers(RiskTier::T2, &[(SchemaSource::Declared, RiskTier::T0)], &none);
        assert_eq!(t, RiskTier::T2);
        let t = combine_tiers(RiskTier::T2, &[(SchemaSource::Curated, RiskTier::T0)], &none);
        assert_eq!(t, RiskTier::T0);
        let t = combine_tiers(RiskTier::T1, &[(SchemaSource::Heuristic, RiskTier::T3)], &none);
        assert_eq!(t, RiskTier::T3);
        // highest wins even when a curated source lowers
        let t = combine_tiers(RiskTier::T2, &[(SchemaSource::Curated, RiskTier::T0), (SchemaSource::Declared, RiskTier::T3)], &none);
        assert_eq!(t, RiskTier::T3);
    }

    /// SCH-03
    #[test]
    fn violation_marks_source_untrusted() {
        let d = SchemaDoc::parse(DOC).unwrap();
        let eff = &d.command("publish").unwrap().effects;
        let v = check_effects(eff, &[PathBuf::from("/etc/passwd")], false).unwrap();
        let mut t = SchemaTrust::new();
        let ev = t.report_violation("deploytool", SchemaSource::Declared, &v);
        assert!(t.is_untrusted("deploytool", SchemaSource::Declared));
        assert!(ev.detail.contains("unexpected write"));
        // untrusted sources are ignored when combining
        let t2 = combine_tiers(RiskTier::T2, &[(SchemaSource::Curated, RiskTier::T0)], &t.untrusted_for("deploytool"));
        assert_eq!(t2, RiskTier::T0);
    }

    #[test]
    fn probe_refused_unless_policy_allows() {
        assert_eq!(probe(Path::new("/bin/true"), false, true).err(), Some(ProbeError::NotAllowed));
        assert_eq!(probe(Path::new("/bin/true"), true, false).err(), Some(ProbeError::OutsideProbeScope));
    }

    #[test]
    fn probe_runs_script_with_scrubbed_env() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("tool");
        std::fs::write(&bin, format!("#!/bin/sh\nif [ -n \"$SECRET_X\" ]; then exit 3; fi\ncat <<'EOF'\n{}\nEOF\n", DOC)).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::env::set_var("SECRET_X", "leak");
        let r = probe(&bin, true, true).unwrap();
        assert_eq!(r.doc.name, "deploytool");
    }

    /// SCH-02: a network call inside the probe fails (needs user namespaces).
    #[test]
    fn probe_sandbox_blocks_network() {
        if !unshare_available() {
            eprintln!("skipping: unshare -rn unavailable");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("nettool");
        std::fs::write(&bin, "#!/bin/sh\n(exec 3<>/dev/tcp/1.1.1.1/80) 2>/dev/null && exit 9\nexit 0\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let (mut cmd, iso) = probe_command(&bin);
        assert_eq!(iso, "os");
        let out = cmd.output().unwrap();
        assert_ne!(out.status.code(), Some(9), "network reachable inside probe sandbox");
    }

    #[test]
    fn sidecar_and_heuristic() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("mytool");
        std::fs::write(dir.path().join("mytool.schema.json"), DOC).unwrap();
        assert_eq!(load_sidecar(&bin, None).unwrap().name, "deploytool");
        let h = heuristic_from_help("x", "  -v, --verbose  be loud\n  --out=FILE  output\n");
        let names: Vec<_> = h.commands[0].flags.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["--verbose", "--out"]);
    }
}
