pub mod pattern_rules_mgr;
pub mod process_pattern_rules_mgr;
pub use process_pattern_rules_mgr::{ProcessPatternRulesMgr};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, OnceLock};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GlobalTrustDir {
    pub dir: String,
    #[serde(rename = "type")]
    pub typ: u8,
    pub is_extend: u8,
}

/// Lightweight trait to decouple DPI writing from the SecurityBackend.
/// The `pattern` crate cannot depend on `common` (circular dep), so
/// higher-level crates register an adapter that forwards to the active backend.
pub trait DpiWriter: Send + Sync {
    /// Clear all pattern/rule/true-process state (equivalent to "c\n" on all files)
    fn clear_all(&self);
    /// Write a pattern+rule pair (may be buffered until build())
    fn write_pair(&self, pat: &str, rule: &str);
    /// Write true-process whitelist data
    fn write_true_process(&self, data: &str);
    /// Finalize / commit (equivalent to "b\n" on file_patterns)
    fn build(&self);

    // ── 进程 DPI（process_dpi / 信任进程白名单），与 file-DPI 相互独立 ──
    /// Clear process DPI pattern/rule state
    fn clear_process(&self);
    /// Write a process pattern+rule pair (may be buffered until build_process())
    fn write_process_pair(&self, pat: &str, rule: &str);
    /// Finalize / commit process DPI (equivalent to "b\n" on process_dpi/file_patterns)
    fn build_process(&self);
}

/// Global DPI writer. When set, `PatternRulesMgr` routes through it;
/// otherwise it falls back to direct `/proc/osec` writes.
static DPI_WRITER: OnceLock<Arc<dyn DpiWriter>> = OnceLock::new();

/// Register a DPI writer (called once at startup by boot code).
pub fn set_dpi_writer(w: Arc<dyn DpiWriter>) {
    let _ = DPI_WRITER.set(w);
}

/// Get the registered DPI writer, if any.
pub fn get_dpi_writer() -> Option<Arc<dyn DpiWriter>> {
    DPI_WRITER.get().cloned()
}
