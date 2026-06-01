use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSource {
    /// Category (e.g., process_creation, network_connection)
    #[serde(default)]
    pub category: Option<String>,

    /// Product (e.g., windows)
    #[serde(default)]
    pub product: Option<String>,

    /// Service (e.g., sysmon)
    #[serde(default)]
    pub service: Option<String>,
}

/// Normalized Sigma logsource key used for rule indexing and event routing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LogSourceKey {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
}

impl LogSourceKey {
    pub(crate) fn normalize_value(value: Option<&str>) -> Option<String> {
        value
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty())
    }

    pub fn from_logsource(logsource: &LogSource) -> Self {
        Self {
            product: Self::normalize_value(logsource.product.as_deref()),
            service: Self::normalize_value(logsource.service.as_deref()),
            category: Self::normalize_value(logsource.category.as_deref()),
        }
    }

    pub(crate) fn from_parts(
        product: Option<&str>,
        service: Option<&str>,
        category: Option<&str>,
    ) -> Self {
        Self {
            product: product.map(ToString::to_string),
            service: service.map(ToString::to_string),
            category: category.map(ToString::to_string),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.product.is_none() && self.service.is_none() && self.category.is_none()
    }

    pub(crate) fn matches_tuple(&self, tuple: &Self) -> bool {
        self.product
            .as_deref()
            .map(|value| tuple.product.as_deref() == Some(value))
            .unwrap_or(true)
            && self
                .service
                .as_deref()
                .map(|value| tuple.service.as_deref() == Some(value))
                .unwrap_or(true)
            && self
                .category
                .as_deref()
                .map(|value| tuple.category.as_deref() == Some(value))
                .unwrap_or(true)
    }

    pub fn display(&self) -> String {
        let mut parts = Vec::new();

        if let Some(product) = &self.product {
            parts.push(format!("product: {}", product));
        }
        if let Some(service) = &self.service {
            parts.push(format!("service: {}", service));
        }
        if let Some(category) = &self.category {
            parts.push(format!("category: {}", category));
        }

        if parts.is_empty() {
            "<empty logsource>".to_string()
        } else {
            parts.join(", ")
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuleLoadDecision {
    Load { collector_active: bool },
    ProductMismatch,
    Deferred,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)] // Used by companion binaries outside the library crate.
pub enum LogSourceStatus {
    Supported,
    ProductMismatch,
    Deferred,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)] // Used by companion binaries outside the library crate.
pub struct LogSourceClassification {
    pub status: LogSourceStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collector_active: Option<bool>,
}

pub(crate) fn current_platform() -> Platform {
    #[cfg(windows)]
    {
        Platform::Windows
    }

    #[cfg(target_os = "linux")]
    {
        Platform::Linux
    }

    #[cfg(target_os = "macos")]
    {
        Platform::MacOS
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Platform::Windows
    }
}

pub(crate) fn platform_product(platform: Platform) -> &'static str {
    match platform {
        Platform::Windows => "windows",
        Platform::Linux => "linux",
        Platform::MacOS => "macos",
    }
}

/// Field pattern for matching
impl Engine {
    pub(crate) fn normalized_logsource(rule: &SigmaRule) -> LogSourceKey {
        LogSourceKey::from_logsource(&rule.logsource)
    }

    pub(crate) fn is_supported_category(category: &str) -> bool {
        matches!(
            category,
            "process_creation"
                | "network_connection"
                | "file_event"
                | "file_create"
                | "file_delete"
                | "file_change"
                | "file_rename"
                | "registry_event"
                | "registry_add"
                | "registry_set"
                | "registry_delete"
                | "dns_query"
                | "dns"
                | "image_load"
                | "ps_script"
                | "wmi_event"
                | "service_creation"
                | "task_creation"
        )
    }

    pub(crate) fn is_recognized_windows_service(service: &str) -> bool {
        matches!(
            service,
            "sysmon"
                | "security"
                | "system"
                | "taskscheduler"
                | "task scheduler"
                | "powershell"
                | "powershell-classic"
                | "microsoft-windows-powershell"
                | "dns-client"
                | "dns"
                | "wmi"
        )
    }

    pub(crate) fn is_deferred_linux_service(service: &str) -> bool {
        matches!(
            service,
            "auditd"
                | "auth"
                | "sudo"
                | "sshd"
                | "cron"
                | "syslog"
                | "clamav"
                | "vsftpd"
                | "guacamole"
                | "builtin"
        )
    }

    pub(crate) fn active_logsource_tuples(&self) -> Vec<LogSourceKey> {
        let mut tuples = match self.platform {
            Platform::Linux => vec![
                LogSourceKey::from_parts(Some("linux"), Some("sysmon"), Some("process_creation")),
                LogSourceKey::from_parts(Some("linux"), Some("sysmon"), Some("network_connection")),
                LogSourceKey::from_parts(Some("linux"), Some("sysmon"), Some("file_event")),
                LogSourceKey::from_parts(Some("linux"), Some("sysmon"), Some("file_create")),
                LogSourceKey::from_parts(Some("linux"), Some("sysmon"), Some("file_delete")),
                LogSourceKey::from_parts(Some("linux"), Some("sysmon"), Some("file_change")),
                LogSourceKey::from_parts(Some("linux"), Some("sysmon"), Some("file_rename")),
                LogSourceKey::from_parts(Some("linux"), Some("sysmon"), Some("dns_query")),
            ],
            // macOS telemetry comes from ESF (process, file) and /dev/bpf
            // (network, DNS); mirror the Linux collector coverage.
            Platform::MacOS => vec![
                LogSourceKey::from_parts(Some("macos"), Some("sysmon"), Some("process_creation")),
                LogSourceKey::from_parts(Some("macos"), Some("sysmon"), Some("network_connection")),
                LogSourceKey::from_parts(Some("macos"), Some("sysmon"), Some("file_event")),
                LogSourceKey::from_parts(Some("macos"), Some("sysmon"), Some("file_create")),
                LogSourceKey::from_parts(Some("macos"), Some("sysmon"), Some("file_delete")),
                LogSourceKey::from_parts(Some("macos"), Some("sysmon"), Some("file_change")),
                LogSourceKey::from_parts(Some("macos"), Some("sysmon"), Some("file_rename")),
                LogSourceKey::from_parts(Some("macos"), Some("sysmon"), Some("dns_query")),
            ],
            Platform::Windows => vec![
                LogSourceKey::from_parts(Some("windows"), Some("sysmon"), Some("process_creation")),
                LogSourceKey::from_parts(
                    Some("windows"),
                    Some("sysmon"),
                    Some("network_connection"),
                ),
                LogSourceKey::from_parts(Some("windows"), Some("sysmon"), Some("file_event")),
                LogSourceKey::from_parts(Some("windows"), Some("sysmon"), Some("file_create")),
                LogSourceKey::from_parts(Some("windows"), Some("sysmon"), Some("file_delete")),
                LogSourceKey::from_parts(Some("windows"), Some("sysmon"), Some("file_change")),
                LogSourceKey::from_parts(Some("windows"), Some("sysmon"), Some("file_rename")),
                LogSourceKey::from_parts(Some("windows"), Some("sysmon"), Some("registry_event")),
                LogSourceKey::from_parts(Some("windows"), Some("sysmon"), Some("registry_add")),
                LogSourceKey::from_parts(Some("windows"), Some("sysmon"), Some("registry_set")),
                LogSourceKey::from_parts(Some("windows"), Some("sysmon"), Some("registry_delete")),
                LogSourceKey::from_parts(Some("windows"), Some("sysmon"), Some("image_load")),
                LogSourceKey::from_parts(Some("windows"), Some("dns-client"), Some("dns_query")),
                LogSourceKey::from_parts(Some("windows"), Some("dns"), Some("dns_query")),
                LogSourceKey::from_parts(Some("windows"), Some("powershell"), Some("ps_script")),
                LogSourceKey::from_parts(
                    Some("windows"),
                    Some("powershell-classic"),
                    Some("ps_script"),
                ),
                LogSourceKey::from_parts(
                    Some("windows"),
                    Some("microsoft-windows-powershell"),
                    Some("ps_script"),
                ),
                LogSourceKey::from_parts(Some("windows"), Some("wmi"), Some("wmi_event")),
                LogSourceKey::from_parts(Some("windows"), Some("system"), Some("service_creation")),
                LogSourceKey::from_parts(
                    Some("windows"),
                    Some("taskscheduler"),
                    Some("task_creation"),
                ),
                LogSourceKey::from_parts(
                    Some("windows"),
                    Some("task scheduler"),
                    Some("task_creation"),
                ),
            ],
        };

        tuples.push(LogSourceKey::from_parts(
            None,
            Some("connection"),
            Some("network"),
        ));
        tuples.push(LogSourceKey::from_parts(None, Some("dns"), Some("network")));
        tuples.push(LogSourceKey::from_parts(None, None, Some("dns")));

        tuples
    }

    pub(crate) fn matches_active_logsource(&self, logsource: &LogSourceKey) -> bool {
        self.active_logsource_tuples()
            .iter()
            .any(|tuple| logsource.matches_tuple(tuple))
    }

    pub(crate) fn is_known_but_inactive_logsource(&self, logsource: &LogSourceKey) -> bool {
        let category = logsource.category.as_deref();
        let service = logsource.service.as_deref();

        match self.platform {
            // macOS shares the Linux collector model: only the generic DNS
            // network logsource is known-but-inactive.
            Platform::Linux | Platform::MacOS => {
                matches!(service, Some("dns"))
                    && matches!(category, None | Some("network"))
                    && logsource
                        .product
                        .as_deref()
                        .map(|product| product == platform_product(self.platform))
                        .unwrap_or(true)
            }
            Platform::Windows => {
                let service_known = service
                    .map(Self::is_recognized_windows_service)
                    .unwrap_or(true);
                let category_known = category
                    .map(|category| category == "network" || Self::is_supported_category(category))
                    .unwrap_or(true);

                service_known
                    && category_known
                    && logsource
                        .product
                        .as_deref()
                        .map(|product| product == "windows")
                        .unwrap_or(true)
            }
        }
    }

    pub(crate) fn is_deferred_linux_logsource(&self, logsource: &LogSourceKey) -> bool {
        if self.platform != Platform::Linux || logsource.product.as_deref() != Some("linux") {
            return false;
        }

        if logsource.service.is_none() && logsource.category.is_none() {
            return true;
        }

        logsource
            .service
            .as_deref()
            .map(Self::is_deferred_linux_service)
            .unwrap_or(false)
    }

    #[allow(dead_code)] // Used by companion binaries outside the library crate.
    pub fn classify_logsource_key(&self, logsource: &LogSourceKey) -> LogSourceClassification {
        let decision = self.rule_load_decision(logsource);
        let status = match decision {
            RuleLoadDecision::Load { .. } => LogSourceStatus::Supported,
            RuleLoadDecision::ProductMismatch => LogSourceStatus::ProductMismatch,
            RuleLoadDecision::Deferred => LogSourceStatus::Deferred,
            RuleLoadDecision::Unknown => LogSourceStatus::Unknown,
        };
        let collector_active = match decision {
            RuleLoadDecision::Load { collector_active } => Some(collector_active),
            _ => None,
        };

        LogSourceClassification {
            status,
            collector_active,
        }
    }

    #[allow(dead_code)] // Used by companion binaries outside the library crate.
    pub fn classify_logsource(&self, logsource: &LogSource) -> LogSourceClassification {
        self.classify_logsource_key(&LogSourceKey::from_logsource(logsource))
    }

    pub(crate) fn rule_load_decision(&self, logsource: &LogSourceKey) -> RuleLoadDecision {
        if logsource.is_empty() {
            return RuleLoadDecision::Unknown;
        }

        if let Some(product) = logsource.product.as_deref() {
            if product != platform_product(self.platform) {
                return RuleLoadDecision::ProductMismatch;
            }
        }

        if self.is_deferred_linux_logsource(logsource) {
            return RuleLoadDecision::Deferred;
        }

        if self.matches_active_logsource(logsource) {
            return RuleLoadDecision::Load {
                collector_active: true,
            };
        }

        if self.is_known_but_inactive_logsource(logsource) {
            return RuleLoadDecision::Load {
                collector_active: false,
            };
        }

        RuleLoadDecision::Unknown
    }

    pub(crate) fn record_skip_for_logsource(
        &mut self,
        decision: RuleLoadDecision,
        logsource: &LogSourceKey,
    ) {
        match decision {
            RuleLoadDecision::ProductMismatch => self.skipped_product_rules += 1,
            RuleLoadDecision::Deferred => {
                self.skipped_deferred_rules += 1;
                *self
                    .deferred_logsource_counts
                    .entry(logsource.clone())
                    .or_default() += 1;
            }
            RuleLoadDecision::Unknown => {
                self.skipped_unknown_logsource_rules += 1;
                *self
                    .unknown_logsource_counts
                    .entry(logsource.clone())
                    .or_default() += 1;
            }
            RuleLoadDecision::Load {
                collector_active: false,
            } => {
                self.inactive_collector_rules += 1;
            }
            RuleLoadDecision::Load {
                collector_active: true,
            } => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::platform_product;
    use crate::sensor::Platform;

    #[test]
    fn platform_product_maps_macos() {
        assert_eq!(platform_product(Platform::MacOS), "macos");
        assert_eq!(platform_product(Platform::Linux), "linux");
        assert_eq!(platform_product(Platform::Windows), "windows");
    }
}
