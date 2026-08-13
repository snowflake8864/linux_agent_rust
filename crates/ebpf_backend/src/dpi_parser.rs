//! DPI pattern/rule text parser for eBPF backend.
//!
//! The driver backend writes comma-separated key=value patterns and rules to
//! `/proc/osec/dpi/` files.  The eBPF backend must parse the same text strings
//! and translate them into entries in the `dir_policies` BPF hash map.
//!
//! ## Pattern format (one per line, comma-separated key=value)
//!
//! ```text
//! name=ProtectDir_0,type=2,key=/etc/important,depth=15,case_offset=1
//! name=exiportInfo_0,key=.docx,offset=-5
//! ```
//!
//! Keys: `name`, `key`, `type`, `depth`, `offset`, `case_offset`, `pkt_len`,
//!       `isnot_extend`
//!
//! ## Rule format (one per line, comma-separated key=value)
//!
//! ```text
//! target=ProtectDir_0,pattern=ProtectDir_0,rule_idx=0,protect_rw=31,type=2
//! target=exiportInfo_0,pattern=exiportInfo_0,action=3,type=1
//! ```
//!
//! Keys: `target`, `pattern`, `action`, `type`, `protect_rw`, `rule_idx`,
//!       `TPNC`, `level`
//!
//! ## Rule type mapping
//!
//! | type | meaning          | eBPF action |
//! |------|------------------|-------------|
//! | 0    | global trust dir | ALLOW       |
//! | 1    | extortion        | DENY        |
//! | 2    | tamper           | DENY        |
//! | 3    | self-protection  | DENY        |

use std::collections::HashMap;

use super::types::{DirKey, DirPolicy};
use super::OP_CREATE;
use super::OP_DELETE;
use super::OP_READ;
use super::OP_WRITE;

// ── Parsed intermediate representations ──

/// A single parsed pattern line.
#[derive(Debug, Clone, Default)]
pub struct ParsedPattern {
    pub name: String,
    /// Directory path (starts with `/`) or suffix pattern (starts with `.`)
    pub key: String,
    /// 0=global trust, 1=extortion, 2=tamper, 3=self-protection
    pub pattern_type: u8,
    /// Offset for suffix patterns (negative), e.g. `-5` for `.docx`
    pub offset: Option<i32>,
    /// Depth for prefix patterns (length of path string)
    pub depth: Option<usize>,
    /// `case_offset=1` means case-insensitive
    pub case_offset: bool,
    /// `pkt_len=-1` means any length
    pub pkt_len: Option<i32>,
    /// `isnot_extend=1` means NOT recursive (the opposite of what you'd think)
    pub is_not_extend: bool,
}

/// A single parsed rule line.
#[derive(Debug, Clone, Default)]
pub struct ParsedRule {
    /// Alias target (not directly used by eBPF)
    pub target: String,
    /// Pattern name(s) this rule references, chained by `>`
    pub pattern_refs: Vec<String>,
    /// 1=allow, 2=exclude, 3=include (deny)
    pub action: u8,
    /// 0=global-trust, 1=extortion, 2=tamper, 3=self-protection
    pub rule_type: u8,
    /// protect_rw bitmask (type 2 only): 0=inherit, else bit0=read, bit1=write,
    /// bit2=delete, bit3=rename, bit4=create
    pub protect_rw: u8,
    /// Rule index for linking include/exclude suffix rules
    pub rule_idx: Option<String>,
    /// Trusted process number (references true_process_rt by index)
    pub tpnc: Option<String>,
    /// Log level (for type=2 white rules)
    pub level: Option<u8>,
}

/// A fully resolved dir_policies entry ready to write to the BPF map.
#[derive(Debug, Clone)]
pub struct ResolvedDirPolicy {
    pub key: DirKey,
    pub policy: DirPolicy,
}

// ── Parsing helpers ──

/// Parse a single comma-separated "key=value" pattern line.
pub fn parse_pattern_line(line: &str) -> Option<ParsedPattern> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    let mut p = ParsedPattern::default();
    for kv in line.split(',') {
        let kv = kv.trim();
        if let Some((k, v)) = kv.split_once('=') {
            let v = v.trim();
            match k.trim() {
                "name" => p.name = v.to_string(),
                "key" => p.key = v.to_string(),
                "type" => p.pattern_type = v.parse().unwrap_or(0),
                "offset" => p.offset = v.parse().ok(),
                "depth" => p.depth = v.parse().ok(),
                "pkt_len" => p.pkt_len = v.parse().ok(),
                "case_offset" => p.case_offset = v == "1",
                "isnot_extend" => p.is_not_extend = v == "1",
                _ => {}
            }
        }
    }

    if p.name.is_empty() {
        return None;
    }
    Some(p)
}

/// Parse a single comma-separated "key=value" rule line.
pub fn parse_rule_line(line: &str) -> Option<ParsedRule> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    let mut r = ParsedRule::default();
    for kv in line.split(',') {
        let kv = kv.trim();
        if let Some((k, v)) = kv.split_once('=') {
            let v = v.trim();
            match k.trim() {
                "target" => r.target = v.to_string(),
                "pattern" => {
                    // pattern can be chained: "ProtectDir_0>protectIncFileExe_0_0"
                    r.pattern_refs = v.split('>').map(|s| s.trim().to_string()).collect();
                }
                "action" => r.action = v.parse().unwrap_or(0),
                "type" => r.rule_type = v.parse().unwrap_or(0),
                "protect_rw" => r.protect_rw = v.parse().unwrap_or(0),
                "rule_idx" => r.rule_idx = Some(v.to_string()),
                "TPNC" => r.tpnc = Some(v.to_string()),
                "level" => r.level = v.parse().ok(),
                _ => {}
            }
        }
    }

    if r.pattern_refs.is_empty() {
        return None;
    }
    Some(r)
}

/// Parse a multi-line pattern string into a list of ParsedPattern.
pub fn parse_patterns(text: &str) -> Vec<ParsedPattern> {
    text.lines().filter_map(parse_pattern_line).collect()
}

/// Parse a multi-line rule string into a list of ParsedRule.
pub fn parse_rules(text: &str) -> Vec<ParsedRule> {
    text.lines().filter_map(parse_rule_line).collect()
}

/// Match patterns to their rules and produce `ResolvedDirPolicy` entries.
///
/// The matching logic:
/// 1. Build a `name → ParsedPattern` index.
/// 2. Process ALL rules: both standalone (`pattern=A`) and chained
///    (`pattern=A>B`). For chained rules the first ref is the directory.
/// 3. Deduplicate by (dev,inode): multiple rules (e.g. include/exclude
///    suffixes) may target the same directory — merge suffixes.
pub fn match_patterns_to_rules(
    patterns: &[ParsedPattern],
    rules: &[ParsedRule],
) -> Vec<ResolvedDirPolicy> {
    let pat_by_name: HashMap<&str, &ParsedPattern> =
        patterns.iter().map(|p| (p.name.as_str(), p)).collect();

    // Group resolved dir policies by (dev,inode) to deduplicate
    let mut by_key: HashMap<(u64, u64), ResolvedDirPolicy> = HashMap::new();

    for rule in rules {
        if rule.pattern_refs.is_empty() {
            continue;
        }

        // The first pattern_ref IS the directory pattern
        let primary_name = rule.pattern_refs.first().unwrap().as_str();
        let pattern = match pat_by_name.get(primary_name) {
            Some(p) => p,
            None => continue,
        };

        // Skip suffix-only patterns — no directory to key on
        let key = pattern.key.trim();
        if key.is_empty() || key.starts_with('.') {
            continue;
        }

        // Resolve directory → (dev, inode)
        let dir_key = match resolve_dir_to_key(key) {
            Some(dk) => dk,
            None => continue,
        };

        let ops_mask = compute_ops_mask(rule, pattern);
        let action = compute_action(rule);
        let recursive: u8 = if pattern.is_not_extend { 0 } else { 1 };

        // Collect suffixes from this rule's chain and related sub-rules
        let (filter_type, suffix_count, suffixes) =
            collect_suffixes_for_dir(primary_name, rules, patterns);

        let dk = (dir_key.dev, dir_key.inode);
        if let Some(existing) = by_key.get_mut(&dk) {
            // Merge: take the stricter action (DENY wins over ALLOW)
            if action == 1 {
                existing.policy.action = 1;
            }
            // OR ops (union of all operation restrictions)
            existing.policy.ops_mask |= ops_mask;
            // Merge suffixes
            if filter_type != 0 {
                existing.policy.filter_type = filter_type;
            }
            for i in 0..suffix_count as usize {
                if existing.policy.suffix_count < 8 {
                    existing.policy.suffixes[existing.policy.suffix_count as usize] = suffixes[i];
                    existing.policy.suffix_count += 1;
                }
            }
        } else {
            by_key.insert(dk, ResolvedDirPolicy {
                key: dir_key,
                policy: DirPolicy {
                    ops_mask,
                    action,
                    mode: 0,
                    recursive,
                    filter_type,
                    suffix_count,
                    reserved: [0; 2],
                    suffixes,
                    exact_filename: [0; 32],
                },
            });
        }
    }

    by_key.into_values().collect()
}

/// Collect suffix patterns linked to a directory rule via chained rules.
///
/// A directory rule like:
///   `target=ProtectDir_0,pattern=ProtectDir_0,protect_rw=31,type=2`
/// may have include-file sub-rules like:
///   `target=...,pattern=ProtectDir_0>protectIncFileExe_0_0,action=3,type=2`
/// and/or exclude-file sub-rules like:
///   `target=...,pattern=ProtectDir_0>protectExcFileExe_0_0,action=2,type=2`
///
/// action=3 → include-only (FILTER_SUFFIX=1)
/// action=2 → exclude (FILTER_EXCLUDE_SUFFIX=2)
fn collect_suffixes_for_dir(
    primary_name: &str,
    rules: &[ParsedRule],
    patterns: &[ParsedPattern],
) -> (u8, u8, [[u8; 8]; 8]) {
    let mut filter_type: u8 = 0; // FILTER_NONE
    let mut suffix_count: u8 = 0;
    let mut suffixes: [[u8; 8]; 8] = [[0u8; 8]; 8];

    // Find sub-rules that chain from this primary directory rule
    for rule in rules {
        if rule.pattern_refs.len() < 2 {
            continue;
        }
        if rule.pattern_refs.first().map(|s| s.as_str()) != Some(primary_name) {
            continue;
        }

        // Determine filter type from the sub-rule's action
        let ft = match rule.action {
            2 => 2, // exclude → FILTER_EXCLUDE_SUFFIX
            _ => 1, // include(3) or other → FILTER_SUFFIX
        };
        if filter_type == 0 {
            filter_type = ft;
        }

        // The last pattern_ref is the suffix pattern name
        let suffix_pat_name = match rule.pattern_refs.last() {
            Some(n) => n.as_str(),
            None => continue,
        };
        let suffix_pat = match patterns.iter().find(|p| p.name == suffix_pat_name) {
            Some(p) => p,
            None => continue,
        };

        let key = suffix_pat.key.trim();
        if key.starts_with('.') && key.len() > 1 {
            let s = &key[1..]; // strip leading '.'
            if suffix_count < 8 && s.len() <= 8 {
                let mut buf = [0u8; 8];
                let n = s.len().min(8);
                buf[..n].copy_from_slice(s.as_bytes());
                suffixes[suffix_count as usize] = buf;
                suffix_count += 1;
            }
        }
    }

    (filter_type, suffix_count, suffixes)
}

/// Map `protect_rw` bitmask from rule to eBPF `ops_mask` bitmask.
///
/// Driver `protect_rw` bits (from gnHead.h):
///   bit0 = read, bit1 = write, bit2 = delete, bit3 = rename, bit4 = create
///
/// eBPF `ops_mask` (from file_agent.bpf.c):
///   OP_READ(1) | OP_WRITE(2) | OP_MODIFY(4) | OP_CREATE(8) | OP_DELETE(16)
fn compute_ops_mask(rule: &ParsedRule, _pattern: &ParsedPattern) -> u8 {
    let rw = rule.protect_rw;

    // rule_type=1 (extortion) → all operations
    // rule_type=2 (tamper) → map protect_rw bits
    // rule_type=3 (self-protection) → all operations
    // rule_type=0 (global trust) → all operations (for allow listing)

    if rule.rule_type == 1 || rule.rule_type == 3 {
        // Extortion / self-protection: block create, write, delete
        return OP_CREATE | OP_WRITE | OP_DELETE;
    }

    if rule.rule_type == 0 {
        // Global trust dir: trust all operations (allow)
        return OP_READ | OP_WRITE | OP_CREATE | OP_DELETE;
    }

    // rule_type == 2 (tamper): map protect_rw bits
    if rw == 0 {
        // inherit — default to all ops
        return OP_READ | OP_WRITE | OP_CREATE | OP_DELETE;
    }

    let mut mask: u8 = 0;
    if rw & 1 != 0 {
        mask |= OP_READ;
    } // bit0: read
    if rw & 2 != 0 {
        mask |= OP_WRITE;
    } // bit1: write
    if rw & 4 != 0 {
        mask |= OP_DELETE;
    } // bit2: delete
    if rw & 8 != 0 {
        mask |= OP_WRITE;
    } // bit3: rename → write
    if rw & 16 != 0 {
        mask |= OP_CREATE;
    } // bit4: create
    mask
}

/// Determine the eBPF action from the DPI rule action.
///
/// DPI action values: 1=allow, 2=exclude, 3=include (deny).
/// Returns: ACTION_ALLOW(0) or ACTION_DENY(1).
fn compute_action(rule: &ParsedRule) -> u8 {
    match rule.action {
        1 => 0, // allow
        _ => 1, // include(3) or exclude(2) → deny
    }
}

/// Resolve a directory path to its (dev, inode) tuple via `stat()`.
pub fn resolve_dir_to_key(dir: &str) -> Option<DirKey> {
    let meta = std::fs::metadata(dir).ok()?;
    // On Linux, std::fs::Metadata exposes dev() and ino()
    #[cfg(target_os = "linux")]
    {
        use std::os::linux::fs::MetadataExt;
        let dev = meta.st_dev();
        let inode = meta.st_ino();
        Some(DirKey { dev, inode })
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Non-Linux: try the portable approach
        // std doesn't expose dev/inode portably; fall back
        let _ = meta;
        None
    }
}

/// Check if a path exists and is a directory (or a parent is).
/// For suffix patterns we can't resolve — skip them.
pub fn path_is_accessible_dir(path: &str) -> bool {
    std::fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false)
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_extortion_pattern() {
        let line = "name=exiportInfo_0,key=.docx,offset=-5";
        let p = parse_pattern_line(line).unwrap();
        assert_eq!(p.name, "exiportInfo_0");
        assert_eq!(p.key, ".docx");
        assert_eq!(p.offset, Some(-5));
        assert_eq!(p.pattern_type, 0);
    }

    #[test]
    fn test_parse_tamper_pattern() {
        let line = "name=ProtectDir_0,type=2,key=/etc/important,depth=15,case_offset=1";
        let p = parse_pattern_line(line).unwrap();
        assert_eq!(p.name, "ProtectDir_0");
        assert_eq!(p.key, "/etc/important");
        assert_eq!(p.pattern_type, 2);
        assert_eq!(p.depth, Some(15));
        assert!(p.case_offset);
    }

    #[test]
    fn test_parse_pattern_not_extend() {
        let line = "name=ProtectDir_0,type=2,key=/etc/important,isnot_extend=1";
        let p = parse_pattern_line(line).unwrap();
        assert!(p.is_not_extend);
    }

    #[test]
    fn test_parse_extortion_rule() {
        let line = "target=exiportInfo_0,pattern=exiportInfo_0,action=3,type=1";
        let r = parse_rule_line(line).unwrap();
        assert_eq!(r.target, "exiportInfo_0");
        assert_eq!(r.pattern_refs, vec!["exiportInfo_0"]);
        assert_eq!(r.action, 3);
        assert_eq!(r.rule_type, 1);
    }

    #[test]
    fn test_parse_tamper_rule() {
        let line = "target=ProtectDir_0,pattern=ProtectDir_0,rule_idx=0,protect_rw=31,type=2";
        let r = parse_rule_line(line).unwrap();
        assert_eq!(r.pattern_refs, vec!["ProtectDir_0"]);
        assert_eq!(r.protect_rw, 31);
        assert_eq!(r.rule_idx.as_deref(), Some("0"));
        assert_eq!(r.rule_type, 2);
    }

    #[test]
    fn test_parse_chained_rule() {
        let line = "target=protectIncFileExe_0,pattern=ProtectDir_0>protectIncFileExe_0_0,rule_idx=0,action=3,protect_rw=31,type=2";
        let r = parse_rule_line(line).unwrap();
        assert_eq!(r.pattern_refs, vec!["ProtectDir_0", "protectIncFileExe_0_0"]);
        assert_eq!(r.action, 3);
    }

    #[test]
    fn test_parse_self_protection_rule() {
        let line = "target=self,pattern=self_1,type=3";
        let r = parse_rule_line(line).unwrap();
        assert_eq!(r.target, "self");
        assert_eq!(r.rule_type, 3);
    }

    #[test]
    fn test_parse_global_trust_rule() {
        let line = "target=TDir_rule,type=0,pattern=trueDir_0";
        let r = parse_rule_line(line).unwrap();
        assert_eq!(r.rule_type, 0);
    }

    #[test]
    fn test_compute_ops_mask_tamper_all() {
        let rule = ParsedRule {
            rule_type: 2,
            protect_rw: 31, // all bits set
            ..Default::default()
        };
        let pat = ParsedPattern::default();
        let mask = compute_ops_mask(&rule, &pat);
        assert_eq!(mask, OP_READ | OP_WRITE | OP_DELETE | OP_CREATE);
    }

    #[test]
    fn test_compute_ops_mask_extortion() {
        let rule = ParsedRule {
            rule_type: 1,
            ..Default::default()
        };
        let pat = ParsedPattern::default();
        let mask = compute_ops_mask(&rule, &pat);
        assert_eq!(mask, OP_CREATE | OP_WRITE | OP_DELETE);
    }

    #[test]
    fn test_parse_patterns_multiline() {
        let text = "name=a,key=/tmp\nname=b,key=.txt,offset=-4\n";
        let pats = parse_patterns(text);
        assert_eq!(pats.len(), 2);
    }

    #[test]
    fn test_parse_rules_multiline() {
        let text = "target=a,pattern=a,action=3,type=1\ntarget=b,pattern=b,action=1,type=2\n";
        let rules = parse_rules(text);
        assert_eq!(rules.len(), 2);
    }
}
