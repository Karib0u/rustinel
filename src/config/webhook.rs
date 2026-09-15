//! `[[alerts.webhook]]` destinations and their load-time validation.
//!
//! Every check that can fail is made when the configuration loads, so a
//! malformed destination stops startup (and shows up in `rustinel doctor`)
//! instead of surfacing at the first alert.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

use reqwest::header::{HeaderName, HeaderValue};
use serde::{Deserialize, Serialize, Serializer};

/// Placeholder written wherever a configured secret would otherwise appear.
pub const REDACTED: &str = "<redacted>";

/// Headers the sink sets itself. Letting configuration override them would
/// break framing or forge the signature a receiver verifies.
const RESERVED_HEADERS: &[&str] = &["content-length", "host", "transfer-encoding", "connection"];
const RESERVED_HEADER_PREFIX: &str = "x-rustinel-";

/// Retry attempts are bounded so a dead endpoint cannot pin one alert forever.
pub const MAX_ATTEMPTS_LIMIT: u32 = 20;

/// One HTTP endpoint that receives every alert as an ECS JSON document.
#[derive(Clone, Deserialize, Serialize)]
pub struct WebhookConfig {
    /// Label used in logs and telemetry. Defaults to the URL's host and port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `http` or `https` endpoint. Treated as secret beyond its host and port,
    /// since many webhook services embed the token in the path.
    #[serde(serialize_with = "redact_url")]
    pub url: String,
    /// Extra request headers. Values are treated as secrets.
    #[serde(default, serialize_with = "redact_header_values")]
    pub headers: BTreeMap<String, String>,
    /// Shared secret for the `X-Rustinel-Signature` HMAC-SHA256 header.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "redact_option"
    )]
    pub secret: Option<String>,
    /// Time limit for one request attempt, connection included.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Verify the server certificate. Disable only for lab endpoints.
    #[serde(default = "default_tls_verify")]
    pub tls_verify: bool,
    /// Extra PEM CA bundle trusted in addition to the system roots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<PathBuf>,
    /// Alerts waiting for delivery. New alerts are dropped when it is full.
    #[serde(default = "default_queue_capacity")]
    pub queue_capacity: usize,
    /// Attempts per alert, the first one included.
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    /// Delay before the first retry. Doubles on each further retry.
    #[serde(default = "default_retry_initial_ms")]
    pub retry_initial_ms: u64,
    /// Longest delay between two attempts.
    #[serde(default = "default_retry_max_ms")]
    pub retry_max_ms: u64,
    /// Alerts whose JSON is larger are not sent to this destination.
    #[serde(default = "default_max_payload_bytes")]
    pub max_payload_bytes: usize,
}

fn default_timeout_ms() -> u64 {
    5_000
}
fn default_tls_verify() -> bool {
    true
}
fn default_queue_capacity() -> usize {
    1_024
}
fn default_max_attempts() -> u32 {
    5
}
fn default_retry_initial_ms() -> u64 {
    500
}
fn default_retry_max_ms() -> u64 {
    30_000
}
fn default_max_payload_bytes() -> usize {
    1_048_576
}

impl WebhookConfig {
    /// A destination for `url` with every other option at its default.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            name: None,
            url: url.into(),
            headers: BTreeMap::new(),
            secret: None,
            timeout_ms: default_timeout_ms(),
            tls_verify: default_tls_verify(),
            ca_file: None,
            queue_capacity: default_queue_capacity(),
            max_attempts: default_max_attempts(),
            retry_initial_ms: default_retry_initial_ms(),
            retry_max_ms: default_retry_max_ms(),
            max_payload_bytes: default_max_payload_bytes(),
        }
    }

    /// `scheme://host[:port]`, the part of the URL that is safe to log.
    pub fn target(&self) -> String {
        match url::Url::parse(&self.url) {
            Ok(url) => safe_target(&url),
            Err(_) => "<invalid url>".to_string(),
        }
    }

    /// The label used in logs and telemetry.
    pub fn label(&self) -> String {
        if let Some(name) = &self.name {
            return name.clone();
        }
        match url::Url::parse(&self.url) {
            Ok(url) => match (url.host_str(), url.port()) {
                (Some(host), Some(port)) => format!("{host}:{port}"),
                (Some(host), None) => host.to_string(),
                _ => "webhook".to_string(),
            },
            Err(_) => "webhook".to_string(),
        }
    }

    /// Whether any configured value would travel as a credential.
    pub fn carries_credentials(&self) -> bool {
        !self.headers.is_empty()
            || self.secret.is_some()
            || url::Url::parse(&self.url)
                .map(|url| !url.username().is_empty() || url.password().is_some())
                .unwrap_or(false)
    }

    /// Parse the URL, headers, and CA bundle, and check the limits.
    ///
    /// Error messages name the destination by its safe label and never
    /// include a header value, the secret, or the URL path.
    pub fn validate(&self, index: usize) -> Result<(), String> {
        let context = format!("alerts.webhook[{index}]");
        let url = url::Url::parse(&self.url)
            .map_err(|err| format!("{context}: url is not a valid URL ({err})"))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(format!(
                "{context}: url scheme must be http or https, not {}",
                url.scheme()
            ));
        }
        if url.host_str().is_none_or(str::is_empty) {
            return Err(format!("{context}: url has no host"));
        }
        if let Some(name) = &self.name {
            if name.trim().is_empty() {
                return Err(format!("{context}: name must not be empty"));
            }
        }

        for (name, value) in &self.headers {
            let header = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| format!("{context}: header name {name:?} is not valid"))?;
            let lower = header.as_str();
            if RESERVED_HEADERS.contains(&lower) || lower.starts_with(RESERVED_HEADER_PREFIX) {
                return Err(format!(
                    "{context}: header {name:?} is set by Rustinel and cannot be configured"
                ));
            }
            HeaderValue::from_str(value).map_err(|_| {
                format!("{context}: value of header {name:?} contains invalid characters")
            })?;
        }

        if self.secret.as_deref().is_some_and(str::is_empty) {
            return Err(format!("{context}: secret must not be empty when set"));
        }
        if self.timeout_ms == 0 {
            return Err(format!("{context}: timeout_ms must be greater than 0"));
        }
        if self.queue_capacity == 0 {
            return Err(format!("{context}: queue_capacity must be greater than 0"));
        }
        if !(1..=MAX_ATTEMPTS_LIMIT).contains(&self.max_attempts) {
            return Err(format!(
                "{context}: max_attempts must be between 1 and {MAX_ATTEMPTS_LIMIT}"
            ));
        }
        if self.retry_initial_ms == 0 {
            return Err(format!(
                "{context}: retry_initial_ms must be greater than 0"
            ));
        }
        if self.retry_max_ms < self.retry_initial_ms {
            return Err(format!(
                "{context}: retry_max_ms must be at least retry_initial_ms"
            ));
        }
        if self.max_payload_bytes == 0 {
            return Err(format!(
                "{context}: max_payload_bytes must be greater than 0"
            ));
        }

        if let Some(path) = &self.ca_file {
            if !self.tls_verify {
                return Err(format!(
                    "{context}: ca_file has no effect with tls_verify = false; remove one of them"
                ));
            }
            self.load_ca_bundle()
                .map_err(|err| format!("{context}: ca_file {}: {err}", path.display()))?;
        }
        Ok(())
    }

    /// Read and parse `ca_file`, if set.
    pub fn load_ca_bundle(&self) -> Result<Vec<reqwest::Certificate>, String> {
        let Some(path) = &self.ca_file else {
            return Ok(Vec::new());
        };
        let pem = std::fs::read(path).map_err(|err| err.to_string())?;
        let certificates = reqwest::Certificate::from_pem_bundle(&pem)
            .map_err(|_| "not a PEM certificate bundle".to_string())?;
        if certificates.is_empty() {
            return Err("contains no PEM certificates".to_string());
        }
        Ok(certificates)
    }
}

/// Validate every destination, and that their labels are distinct.
pub fn validate_all(webhooks: &[WebhookConfig]) -> Result<(), String> {
    let mut labels = std::collections::BTreeSet::new();
    for (index, webhook) in webhooks.iter().enumerate() {
        webhook.validate(index)?;
        let label = webhook.label();
        if !labels.insert(label.clone()) {
            return Err(format!(
                "alerts.webhook[{index}]: another destination is already named {label:?}; set a distinct name"
            ));
        }
    }
    Ok(())
}

pub(crate) fn safe_target(url: &url::Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(port) => format!("{}://{host}:{port}", url.scheme()),
        None => format!("{}://{host}", url.scheme()),
    }
}

impl fmt::Debug for WebhookConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookConfig")
            .field("name", &self.name)
            .field("url", &self.target())
            .field(
                "headers",
                &self
                    .headers
                    .keys()
                    .map(|name| (name.as_str(), REDACTED))
                    .collect::<BTreeMap<_, _>>(),
            )
            .field("secret", &self.secret.as_ref().map(|_| REDACTED))
            .field("timeout_ms", &self.timeout_ms)
            .field("tls_verify", &self.tls_verify)
            .field("ca_file", &self.ca_file)
            .field("queue_capacity", &self.queue_capacity)
            .field("max_attempts", &self.max_attempts)
            .field("retry_initial_ms", &self.retry_initial_ms)
            .field("retry_max_ms", &self.retry_max_ms)
            .field("max_payload_bytes", &self.max_payload_bytes)
            .finish()
    }
}

fn redact_url<S: Serializer>(value: &str, serializer: S) -> Result<S::Ok, S::Error> {
    let target = match url::Url::parse(value) {
        Ok(url) => safe_target(&url),
        Err(_) => REDACTED.to_string(),
    };
    serializer.serialize_str(&target)
}

fn redact_header_values<S: Serializer>(
    headers: &BTreeMap<String, String>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_map(headers.keys().map(|name| (name, REDACTED)))
}

fn redact_option<S: Serializer>(value: &Option<String>, serializer: S) -> Result<S::Ok, S::Error> {
    match value {
        Some(_) => serializer.serialize_str(REDACTED),
        None => serializer.serialize_none(),
    }
}
