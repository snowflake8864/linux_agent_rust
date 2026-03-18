// crates/virus_scan_grpc/src/lynis_scanner.rs
// Lynis 系统漏洞扫描器 - 执行扫描并解析报告

use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::time::Instant;
use tokio::process::Command;
use tokio::fs;
use tokio_util::sync::CancellationToken;
use logging::{log_error, log_info};

/// Lynis 扫描结果
#[derive(Debug, Clone)]
pub struct LynisScanResult {
    pub hardening_index: i32,
    pub warning_count: usize,
    pub suggestion_count: usize,
    pub warnings: Vec<LynisWarning>,
    pub suggestions: Vec<LynisSuggestion>,
    pub details: Vec<LynisDetail>,
    pub raw_report: String,
    pub duration_ms: u64,
}

/// 警告信息
#[derive(Debug, Clone)]
pub struct LynisWarning {
    pub test_id: String,
    pub message: String,
    pub detail: String,
}

/// 建议信息
#[derive(Debug, Clone)]
pub struct LynisSuggestion {
    pub test_id: String,
    pub message: String,
    pub remediation: String,
}

/// 详细配置问题
#[derive(Debug, Clone)]
pub struct LynisDetail {
    pub test_id: String,
    pub service: String,
    pub field: String,
    pub current_value: String,
    pub recommended_value: String,
}

/// Lynis 扫描器
pub struct LynisScanner;

impl LynisScanner {
    /// 执行 Lynis 扫描，支持通过 CancellationToken 中途停止
    pub async fn scan(quick_mode: bool, cancel: CancellationToken) -> Result<LynisScanResult, String> {
        let start_time = Instant::now();
        let report_path = "/tmp/lynis-report.txt";

        // 检查 lynis 是否存在
        if !Path::new("/opt/lynis/lynis").exists() {
            return Err("Lynis not found at /opt/lynis/lynis".to_string());
        }

        log_info!("[LynisScanner] Starting Lynis scan, quick_mode={}", quick_mode);

        // 构建命令，使用 spawn() 保留子进程句柄以便杀死
        let mut cmd = Command::new("/opt/lynis/lynis");
        cmd.current_dir("/opt/lynis")
            .arg("audit")
            .arg("system")
            .arg("--quiet")
            .arg("--no-colors")
            .arg("--report-file")
            .arg(report_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if quick_mode {
            cmd.arg("--quick");
        }

        // spawn() 而非 output()，保留子进程句柄
        let mut child = cmd.spawn().map_err(|e| format!("Failed to spawn lynis: {}", e))?;

        // 等待完成，同时监听取消信号
        let status = tokio::select! {
            result = child.wait() => {
                result.map_err(|e| format!("Failed to wait for lynis: {}", e))?
            }
            _ = cancel.cancelled() => {
                // 收到停止信号，杀死 lynis 进程
                let _ = child.kill().await;
                log_info!("[LynisScanner] Lynis process killed by stop request");
                return Err("Scan cancelled by user".to_string());
            }
        };

        if !status.success() {
            return Err(format!("Lynis scan exited with status: {}", status));
        }

        log_info!("[LynisScanner] Lynis scan completed, parsing report...");

        // 读取报告文件
        let report_content = fs::read_to_string(report_path)
            .await
            .map_err(|e| format!("Failed to read report file: {}", e))?;

        // 解析报告
        let result = Self::parse_report(&report_content)?;

        let duration_ms = start_time.elapsed().as_millis() as u64;

        log_info!(
            "[LynisScanner] Scan result: hardening_index={}, warnings={}, suggestions={}, duration={}ms",
            result.hardening_index,
            result.warning_count,
            result.suggestion_count,
            duration_ms
        );

        Ok(LynisScanResult {
            hardening_index: result.hardening_index,
            warning_count: result.warning_count,
            suggestion_count: result.suggestion_count,
            warnings: result.warnings,
            suggestions: result.suggestions,
            details: result.details,
            raw_report: report_content,
            duration_ms,
        })
    }

    /// 解析 Lynis 报告
    fn parse_report(content: &str) -> Result<ParsedReport, String> {
        let mut data: HashMap<String, Vec<String>> = HashMap::new();
        let mut single_values: HashMap<String, String> = HashMap::new();

        // 按行解析键值对
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // 解析 key=value 格式
            if let Some(pos) = line.find('=') {
                let key = line[..pos].trim().to_string();
                let value = line[pos + 1..].trim().to_string();

                // 处理数组类型（带 [] 后缀的键）
                if key.ends_with("[]") {
                    let base_key = key.trim_end_matches("[]").to_string();
                    data.entry(base_key).or_default().push(value);
                } else {
                    single_values.insert(key, value);
                }
            }
        }

        // 提取加固指数
        let hardening_index = single_values
            .get("hardening_index")
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(0);

        // 提取警告
        let warnings = if let Some(warning_list) = data.get("warning") {
            warning_list
                .iter()
                .filter_map(|raw| Self::parse_warning(raw))
                .collect()
        } else {
            Vec::new()
        };

        // 提取建议
        let suggestions = if let Some(suggestion_list) = data.get("suggestion") {
            suggestion_list
                .iter()
                .filter_map(|raw| Self::parse_suggestion(raw))
                .collect()
        } else {
            Vec::new()
        };

        // 提取详细配置问题
        let details = if let Some(detail_list) = data.get("details") {
            detail_list
                .iter()
                .filter_map(|raw| Self::parse_detail(raw))
                .collect()
        } else {
            Vec::new()
        };

        Ok(ParsedReport {
            hardening_index,
            warning_count: warnings.len(),
            suggestion_count: suggestions.len(),
            warnings,
            suggestions,
            details,
        })
    }

    /// 解析警告条目
    /// 格式: test_id|message|detail|solution
    fn parse_warning(raw: &str) -> Option<LynisWarning> {
        let parts: Vec<&str> = raw.split('|').collect();
        if parts.len() < 2 {
            return None;
        }

        Some(LynisWarning {
            test_id: parts[0].trim().to_string(),
            message: parts[1].trim().to_string(),
            detail: parts.get(2).unwrap_or(&"").trim().to_string(),
        })
    }

    /// 解析建议条目
    /// 格式: test_id|message|remediation|url
    fn parse_suggestion(raw: &str) -> Option<LynisSuggestion> {
        let parts: Vec<&str> = raw.split('|').collect();
        if parts.len() < 2 {
            return None;
        }

        Some(LynisSuggestion {
            test_id: parts[0].trim().to_string(),
            message: parts[1].trim().to_string(),
            remediation: parts.get(2).unwrap_or(&"").trim().to_string(),
        })
    }

    /// 解析详细配置问题
    /// 格式: test_id|service|field:xxx;prefval:xxx;value:xxx
    fn parse_detail(raw: &str) -> Option<LynisDetail> {
        let parts: Vec<&str> = raw.split('|').collect();
        if parts.len() < 3 {
            return None;
        }

        let test_id = parts[0].trim().to_string();
        let service = parts[1].trim().to_string();
        let detail_info = parts[2];

        // 解析 field:xxx;prefval:xxx;value:xxx 格式
        let mut field = String::new();
        let mut current_value = String::new();
        let mut recommended_value = String::new();

        for segment in detail_info.split(';') {
            if let Some(pos) = segment.find(':') {
                let key = segment[..pos].trim();
                let value = segment[pos + 1..].trim();

                match key {
                    "field" => field = value.to_string(),
                    "value" => current_value = value.to_string(),
                    "prefval" => recommended_value = value.to_string(),
                    _ => {}
                }
            }
        }

        Some(LynisDetail {
            test_id,
            service,
            field,
            current_value,
            recommended_value,
        })
    }
}

/// 解析后的报告结构
struct ParsedReport {
    hardening_index: i32,
    warning_count: usize,
    suggestion_count: usize,
    warnings: Vec<LynisWarning>,
    suggestions: Vec<LynisSuggestion>,
    details: Vec<LynisDetail>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_warning() {
        let raw = "KRNL-5830|Reboot of system is most likely needed||text:reboot|";
        let warning = LynisScanner::parse_warning(raw).unwrap();
        assert_eq!(warning.test_id, "KRNL-5830");
        assert_eq!(warning.message, "Reboot of system is most likely needed");
    }

    #[test]
    fn test_parse_suggestion() {
        let raw = "AUTH-9262|Install a PAM module for password strength testing|pam_cracklib|-";
        let suggestion = LynisScanner::parse_suggestion(raw).unwrap();
        assert_eq!(suggestion.test_id, "AUTH-9262");
        assert_eq!(suggestion.remediation, "pam_cracklib");
    }

    #[test]
    fn test_parse_detail() {
        let raw = "SSH-7408|ssh|field:PermitRootLogin;prefval:no;value:yes";
        let detail = LynisScanner::parse_detail(raw).unwrap();
        assert_eq!(detail.test_id, "SSH-7408");
        assert_eq!(detail.service, "ssh");
        assert_eq!(detail.field, "PermitRootLogin");
        assert_eq!(detail.current_value, "yes");
        assert_eq!(detail.recommended_value, "no");
    }
}
