//! # Policy Engine
//!
//! The policy engine decides whether, how, and with what privileges a command
//! runs. It applies identical logic to humans, agents, and scripts, with
//! different default policies per actor (spec §4).
//!
//! ## Classification pipeline (spec §4.3):
//! 1. Parse - tokenize, resolve aliases, expand globs
//! 2. Schema lookup - --schema contract
//! 3. Registry lookup - curated rules for common tools
//! 4. Heuristics - dangerous patterns
//! 5. Unknown handling - default to T2 with basis: unknown
//! 6. Dry-run probe (optional)

pub mod classifier;
pub mod config;
pub mod engine;
pub mod registry;
pub mod sandbox;
