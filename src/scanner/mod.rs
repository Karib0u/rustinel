//! Yara scanner module
//!
//! Handles compiling rules, listening for process events, and scanning files.

use anyhow::{Context, Result};
use ferrisetw::parser::Parser;
use ferrisetw::EventRecord;
use std::fs;
use std::path::Path;
use tokio::sync::mpsc::Sender;
use tracing::{debug, info, warn};
use yara_x::{Compiler, Rules, Scanner as XScanner};

use crate::collector::EventHandler;
use crate::models::EventCategory;

fn normalize_yara_path(nt_path: &str) -> String {
    let cleaned = nt_path.strip_prefix("\\??\\").unwrap_or(nt_path);
    crate::utils::convert_nt_to_dos(cleaned)
}

/// Main Scanner struct holding compiled rules
pub struct Scanner {
    rules: Rules,
}

impl Scanner {
    /// Compile all .yar files in a directory
    pub fn new<P: AsRef<Path>>(rules_dir: P) -> Result<Self> {
        let rules_dir = rules_dir.as_ref();
        let mut compiler = Compiler::new();
        let mut files_found = 0;
        let mut files_compiled = 0;

        info!("Loading YARA rules from: {:?}", rules_dir);

        if rules_dir.exists() && rules_dir.is_dir() {
            for entry in fs::read_dir(rules_dir)? {
                let entry = entry?;
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    if ext == "yar" || ext == "yara" {
                        files_found += 1;
                        debug!("Found YARA rule file: {:?}", path);
                        let src = fs::read_to_string(&path)
                            .with_context(|| format!("Failed to read {:?}", path))?;

                        match compiler.add_source(src.as_str()) {
                            Ok(_) => {
                                files_compiled += 1;
                                debug!("✓ Compiled YARA rule: {:?}", path);
                            }
                            Err(e) => {
                                warn!("✗ Failed to compile {:?}: {}", path, e);
                            }
                        }
                    }
                }
            }
        } else {
            warn!(
                "YARA rules directory does not exist or is not a directory: {:?}",
                rules_dir
            );
        }

        let rules = compiler.build();
        info!(
            "YARA Scanner: Found {} rule files, compiled {} successfully",
            files_found, files_compiled
        );
        Ok(Self { rules })
    }

    /// Scan a file path and return matching rule names
    pub fn scan_file(&self, path: &str) -> Result<Vec<String>> {
        let mut matches = Vec::new();
        let mut scanner = XScanner::new(&self.rules);

        // Scan the file
        match scanner.scan_file(path) {
            Ok(scan_results) => {
                for rule in scan_results.matching_rules() {
                    matches.push(rule.identifier().to_string());
                }
            }
            Err(e) => {
                // File locking issues are common in EDR, just debug log them
                debug!("Skipping scan of {}: {}", path, e);
            }
        }

        Ok(matches)
    }
}

/// ETW Handler that sends file paths to the background worker
pub struct YaraEventHandler {
    pub tx: Sender<(String, u32)>, // Sends (FilePath, PID)
}

impl EventHandler for YaraEventHandler {
    fn handle_event(&self, record: &EventRecord, category: EventCategory) {
        // We only care about Process Start (OpCode 1) events
        if category == EventCategory::Process && record.opcode() == 1 {
            debug!(
                "YARA: ProcessStart event detected - PID: {}",
                record.process_id()
            );

            // We use a lightweight parser just to get ImageName
            if let Ok(schema) =
                ferrisetw::schema_locator::SchemaLocator::default().event_schema(record)
            {
                let parser = Parser::create(record, &schema);

                // Try to get the ImageName (path)
                if let Ok(nt_path) = parser.try_parse::<String>("ImageName") {
                    let pid = record.process_id();
                    debug!("YARA: Got NT path: {} (PID: {})", nt_path, pid);

                    // Convert NT Device path to DOS path using shared mapper.
                    // Handle Win32 prefix before conversion.
                    let dos_path = normalize_yara_path(&nt_path);

                    debug!("YARA: Converted to DOS path: {} (PID: {})", dos_path, pid);

                    // Send to background worker (non-blocking)
                    match self.tx.try_send((dos_path.clone(), pid)) {
                        Ok(_) => debug!("YARA: Queued for scanning: {}", dos_path),
                        Err(e) => warn!("YARA: Failed to queue file (channel full?): {}", e),
                    }
                } else {
                    debug!(
                        "YARA: Failed to parse ImageName from ProcessStart event (PID: {})",
                        record.process_id()
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        // Test that we can create a scanner even with an empty/missing directory
        let result = Scanner::new("nonexistent_dir");
        assert!(result.is_ok());
    }

    #[test]
    fn test_normalize_yara_path_strips_win32_prefix() {
        let input = r"\??\C:\Windows\System32\cmd.exe";
        let normalized = normalize_yara_path(input);
        assert_eq!(normalized, r"C:\Windows\System32\cmd.exe");
    }

    #[test]
    fn test_normalize_yara_path_passthrough() {
        let input = r"C:\Temp\edrust.exe";
        let normalized = normalize_yara_path(input);
        assert_eq!(normalized, input);
    }
}
