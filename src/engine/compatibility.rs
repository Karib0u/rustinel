//! Per-document Sigma compatibility diagnostics.
//!
//! The analyzer is deliberately separate from rule loading. It inspects every
//! parsed document, including documents that the runtime would filter out,
//! and evaluates detection conditions against the field shapes the selected
//! platform can actually emit.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Context, Result};
use rsigma_parser::{
    ArrayQuantifier, ConditionExpr, CorrelationCondition, CorrelationRule, CorrelationType,
    Detection, DetectionItem, Detections, FilterRule, FilterRuleTarget, Modifier, Quantifier,
    SelectorPattern, SigmaRule, SigmaValue,
};
use serde::Serialize;

use crate::config::AppConfig;
use crate::field_availability::{self, Availability, EventFieldContract, FIELD_AVAILABILITY};
use crate::models::{event_actions, Fidelity, FieldViewName};
use crate::vocab::Platform;

use super::logsource::platform_product;
use super::{Engine, LogSourceKey, LogSourceStatus};

pub const SIGMA_COMPATIBILITY_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompatibilityVerdict {
    CanFire,
    Degraded,
    CanNeverFire,
}

impl CompatibilityVerdict {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CanFire => "can-fire",
            Self::Degraded => "degraded",
            Self::CanNeverFire => "can-never-fire",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentKind {
    Detection,
    Correlation,
    Filter,
    Invalid,
}

impl DocumentKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Detection => "detection",
            Self::Correlation => "correlation",
            Self::Filter => "filter",
            Self::Invalid => "invalid",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    ParseError,
    CompileError,
    ProductMismatch,
    DeferredLogsource,
    UnknownLogsource,
    InactiveCollector,
    CollectorDisabled,
    NoPlatformTelemetry,
    UnavailableField,
    ConditionalField,
    DerivedField,
    BestEffortField,
    TruncatedField,
    StaleField,
    MissingReference,
    DependencyUnavailable,
    UntargetedFilter,
}

impl ReasonCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ParseError => "parse_error",
            Self::CompileError => "compile_error",
            Self::ProductMismatch => "product_mismatch",
            Self::DeferredLogsource => "deferred_logsource",
            Self::UnknownLogsource => "unknown_logsource",
            Self::InactiveCollector => "inactive_collector",
            Self::CollectorDisabled => "collector_disabled",
            Self::NoPlatformTelemetry => "no_platform_telemetry",
            Self::UnavailableField => "unavailable_field",
            Self::ConditionalField => "conditional_field",
            Self::DerivedField => "derived_field",
            Self::BestEffortField => "best_effort_field",
            Self::TruncatedField => "truncated_field",
            Self::StaleField => "stale_field",
            Self::MissingReference => "missing_reference",
            Self::DependencyUnavailable => "dependency_unavailable",
            Self::UntargetedFilter => "untargeted_filter",
        }
    }
}

/// How much a reason weighs on the verdict.
///
/// A `Caveat` records a known imperfection that has been measured as rare on
/// the platform, so the document still counts as `can-fire`.
/// A `Limitation` is a real gap and degrades the document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonSeverity {
    #[default]
    Limitation,
    Caveat,
}

impl ReasonSeverity {
    fn is_limitation(&self) -> bool {
        *self == Self::Limitation
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompatibilityReason {
    pub code: ReasonCode,
    #[serde(skip_serializing_if = "ReasonSeverity::is_limitation")]
    pub severity: ReasonSeverity,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

impl CompatibilityReason {
    fn new(code: ReasonCode, message: impl Into<String>) -> Self {
        Self {
            code,
            severity: ReasonSeverity::Limitation,
            message: message.into(),
            field: None,
            reference: None,
        }
    }

    fn with_severity(mut self, severity: ReasonSeverity) -> Self {
        self.severity = severity;
        self
    }

    fn field(code: ReasonCode, field: &str, message: impl Into<String>) -> Self {
        Self {
            code,
            severity: ReasonSeverity::Limitation,
            message: message.into(),
            field: Some(field.to_string()),
            reference: None,
        }
    }

    fn reference(code: ReasonCode, reference: &str, message: impl Into<String>) -> Self {
        Self {
            code,
            severity: ReasonSeverity::Limitation,
            message: message.into(),
            field: None,
            reference: Some(reference.to_string()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldCompatibilityStatus {
    Always,
    Conditional,
    Never,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldCompatibility {
    pub field: String,
    pub availability: FieldCompatibilityStatus,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fidelity: Vec<Fidelity>,
    /// Measured to be populated reliably enough that conditional or derived
    /// availability is reported as a caveat instead of degrading the document.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub reliable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleLogsource {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    pub collector_active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DocumentCompatibility {
    pub source: String,
    pub kind: DocumentKind,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub verdict: CompatibilityVerdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logsource: Option<RuleLogsource>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<FieldCompatibility>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<String>,
    pub reasons: Vec<CompatibilityReason>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct VerdictCounts {
    pub can_fire: usize,
    pub degraded: usize,
    pub can_never_fire: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CompatibilitySummary {
    pub documents: usize,
    pub verdicts: VerdictCounts,
    /// Documents that can fire but carry at least one caveat.
    pub can_fire_with_caveats: usize,
    pub reasons: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SigmaCompatibilityReport {
    pub schema_version: u16,
    pub platform: String,
    pub field_view: String,
    pub rules_path: PathBuf,
    pub summary: CompatibilitySummary,
    pub exit_code: i32,
    pub documents: Vec<DocumentCompatibility>,
}

impl SigmaCompatibilityReport {
    fn new(
        platform: Platform,
        field_view: FieldViewName,
        rules_path: PathBuf,
        mut documents: Vec<DocumentCompatibility>,
    ) -> Self {
        documents.sort_by(|left, right| {
            (&left.source, left.kind, &left.title, &left.id).cmp(&(
                &right.source,
                right.kind,
                &right.title,
                &right.id,
            ))
        });
        let mut summary = CompatibilitySummary {
            documents: documents.len(),
            ..Default::default()
        };
        let mut hard_error = false;
        for document in &documents {
            match document.verdict {
                CompatibilityVerdict::CanFire => {
                    summary.verdicts.can_fire += 1;
                    if !document.reasons.is_empty() {
                        summary.can_fire_with_caveats += 1;
                    }
                }
                CompatibilityVerdict::Degraded => summary.verdicts.degraded += 1,
                CompatibilityVerdict::CanNeverFire => summary.verdicts.can_never_fire += 1,
            }
            for reason in &document.reasons {
                *summary
                    .reasons
                    .entry(reason.code.as_str().to_string())
                    .or_default() += 1;
                hard_error |= matches!(
                    reason.code,
                    ReasonCode::ParseError | ReasonCode::CompileError
                );
            }
        }
        let exit_code = if hard_error {
            2
        } else if summary.verdicts.degraded > 0 || summary.verdicts.can_never_fire > 0 {
            1
        } else {
            0
        };
        Self {
            schema_version: SIGMA_COMPATIBILITY_SCHEMA_VERSION,
            platform: platform.as_str().to_string(),
            field_view: field_view.as_str().to_string(),
            rules_path,
            summary,
            exit_code,
            documents,
        }
    }

    pub fn fatal(platform: Platform, rules_path: PathBuf, message: impl Into<String>) -> Self {
        Self::new(
            platform,
            FieldViewName::DEFAULT,
            rules_path,
            vec![DocumentCompatibility {
                source: "<configuration>".to_string(),
                kind: DocumentKind::Invalid,
                title: "Compatibility report could not be generated".to_string(),
                id: None,
                verdict: CompatibilityVerdict::CanNeverFire,
                logsource: None,
                fields: Vec::new(),
                dependencies: Vec::new(),
                reasons: vec![CompatibilityReason::new(ReasonCode::ParseError, message)],
            }],
        )
    }
}

enum ParsedDocument {
    Detection {
        source: String,
        rule: SigmaRule,
    },
    Correlation {
        source: String,
        rule: CorrelationRule,
    },
    Filter {
        source: String,
        rule: FilterRule,
    },
    Invalid {
        source: String,
        title: String,
        message: String,
    },
}

#[derive(Debug, Clone, Copy)]
struct Truth {
    can_be_true: bool,
    can_be_false: bool,
}

impl Truth {
    const TRUE: Self = Self {
        can_be_true: true,
        can_be_false: false,
    };
    const FALSE: Self = Self {
        can_be_true: false,
        can_be_false: true,
    };
    const UNKNOWN: Self = Self {
        can_be_true: true,
        can_be_false: true,
    };

    fn not(self) -> Self {
        Self {
            can_be_true: self.can_be_false,
            can_be_false: self.can_be_true,
        }
    }

    fn and(values: impl IntoIterator<Item = Self>) -> Self {
        let values = values.into_iter().collect::<Vec<_>>();
        Self {
            can_be_true: values.iter().all(|value| value.can_be_true),
            can_be_false: values.iter().any(|value| value.can_be_false),
        }
    }

    fn or(values: impl IntoIterator<Item = Self>) -> Self {
        let values = values.into_iter().collect::<Vec<_>>();
        Self {
            can_be_true: values.iter().any(|value| value.can_be_true),
            can_be_false: values.iter().all(|value| value.can_be_false),
        }
    }
}

#[derive(Default)]
struct FieldUse {
    reasons: BTreeSet<String>,
    fidelity: BTreeSet<Fidelity>,
    saw_always: bool,
    saw_conditional: bool,
    saw_never: bool,
}

struct ContractEvaluation {
    truth: Truth,
    fields: BTreeMap<String, FieldUse>,
}

pub fn analyze_rules(
    rules_path: &Path,
    platform: Platform,
    config: &AppConfig,
) -> Result<SigmaCompatibilityReport> {
    let parsed = parse_documents(rules_path)?;
    let field_view = FieldViewName::DEFAULT;
    let engine = Engine::new_for_platform(platform);
    let mut reports = Vec::new();
    let mut detections = Vec::new();
    let mut correlations = Vec::new();
    let mut filters = Vec::new();

    for document in parsed {
        match document {
            ParsedDocument::Detection { source, rule } => detections.push((source, rule)),
            ParsedDocument::Correlation { source, rule } => correlations.push((source, rule)),
            ParsedDocument::Filter { source, rule } => filters.push((source, rule)),
            ParsedDocument::Invalid {
                source,
                title,
                message,
            } => reports.push(DocumentCompatibility {
                source,
                kind: DocumentKind::Invalid,
                title,
                id: None,
                verdict: CompatibilityVerdict::CanNeverFire,
                logsource: None,
                fields: Vec::new(),
                dependencies: Vec::new(),
                reasons: vec![CompatibilityReason::new(ReasonCode::ParseError, message)],
            }),
        }
    }

    let mut identities: HashMap<String, usize> = HashMap::new();
    let mut detection_contracts: HashMap<String, Vec<&'static EventFieldContract>> = HashMap::new();
    for (source, rule) in &detections {
        let report = analyze_detection(source, rule, platform, config, &engine);
        let index = reports.len();
        add_detection_identity(&mut identities, rule, index);
        let contracts = contracts_for_logsource(
            platform,
            &LogSourceKey {
                product: normalize(rule.logsource.product.as_deref()),
                service: normalize(rule.logsource.service.as_deref()),
                category: normalize(rule.logsource.category.as_deref()),
            },
        )
        .into_iter()
        .filter(|contract| {
            evaluate_detections(&rule.detection, contract)
                .truth
                .can_be_true
        })
        .collect::<Vec<_>>();
        for key in detection_keys(rule) {
            detection_contracts.insert(key, contracts.clone());
        }
        reports.push(report);
    }

    let mut correlation_indices = Vec::new();
    for (source, rule) in &correlations {
        let report = analyze_correlation(source, rule, &reports, &identities, &detection_contracts);
        let index = reports.len();
        if let Some(id) = &rule.id {
            identities.insert(id.clone(), index);
        }
        if let Some(name) = &rule.name {
            identities.insert(name.clone(), index);
        }
        correlation_indices.push(index);
        reports.push(report);
    }

    // Correlations can reference correlations declared later. Re-evaluate the
    // dependency-only verdict to a fixed point once every identity is known.
    for _ in 0..correlations.len().max(1) {
        let mut changed = false;
        for ((source, rule), index) in correlations.iter().zip(&correlation_indices) {
            let updated =
                analyze_correlation(source, rule, &reports, &identities, &detection_contracts);
            if reports[*index] != updated {
                reports[*index] = updated;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    let filter_context = FilterAnalysisContext {
        platform,
        config,
        engine: &engine,
        reports: &reports,
        identities: &identities,
        detection_contracts: &detection_contracts,
        detections: &detections,
    };
    let filter_reports = filters
        .iter()
        .map(|(source, filter)| analyze_filter(source, filter, &filter_context))
        .collect::<Vec<_>>();
    reports.extend(filter_reports);

    Ok(SigmaCompatibilityReport::new(
        platform,
        field_view,
        rules_path.to_path_buf(),
        reports,
    ))
}

fn parse_documents(root: &Path) -> Result<Vec<ParsedDocument>> {
    if !root.exists() {
        anyhow::bail!("rules path {} does not exist", root.display());
    }
    let mut files = Vec::new();
    collect_yaml_files(root, &mut files)?;
    files.sort();
    let mut documents = Vec::new();
    for path in files {
        let source = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let content = fs::read_to_string(&path)
            .with_context(|| format!("read Sigma rule file {}", path.display()))?;
        match rsigma_parser::parse_sigma_yaml(&content) {
            Ok(collection) => {
                for (index, error) in collection.errors.into_iter().enumerate() {
                    documents.push(ParsedDocument::Invalid {
                        source: source.clone(),
                        title: format!("Invalid document {}", index + 1),
                        message: error,
                    });
                }
                documents.extend(collection.rules.into_iter().map(|rule| {
                    ParsedDocument::Detection {
                        source: source.clone(),
                        rule,
                    }
                }));
                documents.extend(collection.correlations.into_iter().map(|rule| {
                    ParsedDocument::Correlation {
                        source: source.clone(),
                        rule,
                    }
                }));
                documents.extend(collection.filters.into_iter().map(|rule| {
                    ParsedDocument::Filter {
                        source: source.clone(),
                        rule,
                    }
                }));
            }
            Err(error) => documents.push(ParsedDocument::Invalid {
                source,
                title: "Invalid Sigma document".to_string(),
                message: error.to_string(),
            }),
        }
    }
    Ok(documents)
}

fn collect_yaml_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in
        fs::read_dir(dir).with_context(|| format!("read rules directory {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_yaml_files(&path, files)?;
        } else if matches!(
            path.extension().and_then(|value| value.to_str()),
            Some("yml" | "yaml")
        ) {
            files.push(path);
        }
    }
    Ok(())
}

fn analyze_detection(
    source: &str,
    rule: &SigmaRule,
    platform: Platform,
    config: &AppConfig,
    engine: &Engine,
) -> DocumentCompatibility {
    let key = LogSourceKey {
        product: normalize(rule.logsource.product.as_deref()),
        service: normalize(rule.logsource.service.as_deref()),
        category: normalize(rule.logsource.category.as_deref()),
    };
    let classification = engine.classify_logsource_key(&key);
    let collector_active = classification.collector_active.unwrap_or(false);
    let logsource = Some(RuleLogsource {
        product: key.product.clone(),
        service: key.service.clone(),
        category: key.category.clone(),
        collector_active,
    });
    let mut report = DocumentCompatibility {
        source: source.to_string(),
        kind: DocumentKind::Detection,
        title: rule.title.clone(),
        id: rule.id.clone(),
        verdict: CompatibilityVerdict::CanNeverFire,
        logsource,
        fields: Vec::new(),
        dependencies: Vec::new(),
        reasons: Vec::new(),
    };

    if let Err(error) = rsigma_eval::compile_rule(rule) {
        report.reasons.push(CompatibilityReason::new(
            ReasonCode::CompileError,
            error.to_string(),
        ));
        return report;
    }

    match classification.status {
        LogSourceStatus::ProductMismatch => {
            report.reasons.push(CompatibilityReason::new(
                ReasonCode::ProductMismatch,
                format!("logsource does not target {}", platform.as_str()),
            ));
            return report;
        }
        LogSourceStatus::Deferred => {
            report.reasons.push(CompatibilityReason::new(
                ReasonCode::DeferredLogsource,
                "logsource is recognized but not evaluated by the runtime",
            ));
            return report;
        }
        LogSourceStatus::Unknown => {
            report.reasons.push(CompatibilityReason::new(
                ReasonCode::UnknownLogsource,
                "logsource is not routed by the runtime",
            ));
            return report;
        }
        LogSourceStatus::Supported => {}
    }
    if !collector_active {
        report.reasons.push(CompatibilityReason::new(
            ReasonCode::InactiveCollector,
            "the logsource has no active collector on this platform",
        ));
        return report;
    }

    let contracts = contracts_for_logsource(platform, &key);
    if contracts.is_empty() {
        report.reasons.push(CompatibilityReason::new(
            ReasonCode::NoPlatformTelemetry,
            "no emitted event shape provides telemetry for this logsource",
        ));
        return report;
    }

    let routed_event_ids = routed_event_ids(&contracts);
    let mut enabled_viable = false;
    let mut disabled_viable = false;
    let mut all_fields: BTreeMap<String, FieldUse> = BTreeMap::new();
    let mut viable_fields: BTreeMap<String, FieldUse> = BTreeMap::new();
    for contract in contracts {
        let evaluation = evaluate_detections(&rule.detection, contract);
        if evaluation.truth.can_be_true {
            if collector_enabled_for_contract(config, contract) {
                enabled_viable = true;
            } else {
                disabled_viable = true;
            }
            merge_field_uses(&mut viable_fields, evaluation.fields);
        } else {
            merge_field_uses(&mut all_fields, evaluation.fields);
        }
    }
    if viable_fields.is_empty() {
        viable_fields = all_fields;
    }
    report.fields = field_reports(platform, &key, viable_fields);

    if enabled_viable {
        report.reasons = limitation_reasons(&report.fields);
        report.verdict = if has_limitation(&report.reasons) {
            CompatibilityVerdict::Degraded
        } else {
            CompatibilityVerdict::CanFire
        };
    } else if disabled_viable {
        report.reasons.push(CompatibilityReason::new(
            ReasonCode::CollectorDisabled,
            "the only compatible event shapes are disabled by configuration",
        ));
    } else {
        report.reasons = unavailable_reasons(&report.fields);
        if report.reasons.is_empty() {
            let message = if routed_event_ids.is_empty() {
                "the condition cannot be satisfied by any emitted event shape".to_string()
            } else {
                format!(
                    "the condition cannot be satisfied by any emitted event shape; this logsource routes only to EventID {routed_event_ids}"
                )
            };
            report.reasons.push(CompatibilityReason::new(
                ReasonCode::UnavailableField,
                message,
            ));
        }
    }
    report
}

/// The `EventID`s of the shapes a logsource routes to, or empty when any shape
/// leaves `EventID` unconstrained.
fn routed_event_ids(contracts: &[&'static EventFieldContract]) -> String {
    let mut ids = BTreeSet::new();
    for contract in contracts
        .iter()
        .filter(|contract| contract.provider != "none")
    {
        let before = ids.len();
        ids.extend(contract.presented_event_ids());
        if ids.len() == before && contract.presented_event_ids().next().is_none() {
            return String::new();
        }
    }
    ids.into_iter()
        .map(|id| id.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn analyze_correlation(
    source: &str,
    rule: &CorrelationRule,
    reports: &[DocumentCompatibility],
    identities: &HashMap<String, usize>,
    detection_contracts: &HashMap<String, Vec<&'static EventFieldContract>>,
) -> DocumentCompatibility {
    if let Err(error) = rsigma_eval::correlation::compile_correlation(rule) {
        return DocumentCompatibility {
            source: source.to_string(),
            kind: DocumentKind::Correlation,
            title: rule.title.clone(),
            id: rule.id.clone(),
            verdict: CompatibilityVerdict::CanNeverFire,
            logsource: None,
            fields: Vec::new(),
            dependencies: sorted_unique(rule.rules.clone()),
            reasons: vec![CompatibilityReason::new(
                ReasonCode::CompileError,
                error.to_string(),
            )],
        };
    }
    let (mut verdict, mut reasons) = correlation_dependency_verdict(rule, reports, identities);
    let mut fields = correlation_fields(rule)
        .into_iter()
        .map(|field| field_across_dependencies(&field, &rule.rules, detection_contracts))
        .collect::<Vec<_>>();
    fields.sort_by(|left, right| left.field.cmp(&right.field));
    let field_reasons = limitation_reasons(&fields);
    if verdict != CompatibilityVerdict::CanNeverFire && !field_reasons.is_empty() {
        if has_limitation(&field_reasons) {
            verdict = CompatibilityVerdict::Degraded;
        }
        reasons.extend(field_reasons);
    }
    DocumentCompatibility {
        source: source.to_string(),
        kind: DocumentKind::Correlation,
        title: rule.title.clone(),
        id: rule.id.clone(),
        verdict,
        logsource: None,
        fields,
        dependencies: sorted_unique(rule.rules.clone()),
        reasons,
    }
}

struct FilterAnalysisContext<'a> {
    platform: Platform,
    config: &'a AppConfig,
    engine: &'a Engine,
    reports: &'a [DocumentCompatibility],
    identities: &'a HashMap<String, usize>,
    detection_contracts: &'a HashMap<String, Vec<&'static EventFieldContract>>,
    detections: &'a [(String, SigmaRule)],
}

fn analyze_filter(
    source: &str,
    filter: &FilterRule,
    context: &FilterAnalysisContext<'_>,
) -> DocumentCompatibility {
    let dependencies = match &filter.rules {
        FilterRuleTarget::Any => {
            return DocumentCompatibility {
                source: source.to_string(),
                kind: DocumentKind::Filter,
                title: filter.title.clone(),
                id: filter.id.clone(),
                verdict: CompatibilityVerdict::CanNeverFire,
                logsource: None,
                fields: Vec::new(),
                dependencies: Vec::new(),
                reasons: vec![CompatibilityReason::new(
                    ReasonCode::UntargetedFilter,
                    "filter does not list target rules; name each rule id or title under filter.rules",
                )],
            };
        }
        FilterRuleTarget::Specific(references) => sorted_unique(references.clone()),
    };
    let (dependency_state, mut reasons) = if dependencies.is_empty() {
        (CompatibilityVerdict::CanFire, Vec::new())
    } else {
        filter_dependency_verdict(&dependencies, context.reports, context.identities)
    };
    if dependency_state != CompatibilityVerdict::CanNeverFire {
        if let Err(error) = compile_filter(filter, context.detections) {
            return DocumentCompatibility {
                source: source.to_string(),
                kind: DocumentKind::Filter,
                title: filter.title.clone(),
                id: filter.id.clone(),
                verdict: CompatibilityVerdict::CanNeverFire,
                logsource: None,
                fields: Vec::new(),
                dependencies,
                reasons: vec![CompatibilityReason::new(
                    ReasonCode::CompileError,
                    error.to_string(),
                )],
            };
        }
    }
    let key = filter.logsource.as_ref().map(|logsource| LogSourceKey {
        product: normalize(logsource.product.as_deref()),
        service: normalize(logsource.service.as_deref()),
        category: normalize(logsource.category.as_deref()),
    });
    let contracts = key.as_ref().map_or_else(
        || {
            dependencies
                .iter()
                .flat_map(|dependency| {
                    context
                        .detection_contracts
                        .get(dependency)
                        .into_iter()
                        .flatten()
                })
                .copied()
                .collect::<Vec<_>>()
        },
        |key| contracts_for_logsource(context.platform, key),
    );
    let mut fields = BTreeMap::new();
    let mut viable = false;
    for contract in &contracts {
        let evaluated = evaluate_detections(&filter.detection, contract);
        viable |=
            evaluated.truth.can_be_true && collector_enabled_for_contract(context.config, contract);
        merge_field_uses(&mut fields, evaluated.fields);
    }
    let fields = field_reports(
        context.platform,
        key.as_ref().unwrap_or(&LogSourceKey {
            product: Some(context.platform.as_str().to_string()),
            service: None,
            category: None,
        }),
        fields,
    );
    let mut verdict = dependency_state;
    if verdict != CompatibilityVerdict::CanNeverFire {
        if contracts.is_empty() || !viable {
            verdict = CompatibilityVerdict::CanNeverFire;
            reasons.extend(unavailable_reasons(&fields));
            if reasons.is_empty() {
                reasons.push(CompatibilityReason::new(
                    ReasonCode::NoPlatformTelemetry,
                    "no target event shape can satisfy this filter",
                ));
            }
        } else {
            let limitations = limitation_reasons(&fields);
            if has_limitation(&limitations) {
                verdict = CompatibilityVerdict::Degraded;
            }
            reasons.extend(limitations);
        }
    }
    let logsource = key.map(|key| {
        let classification = context.engine.classify_logsource_key(&key);
        RuleLogsource {
            product: key.product,
            service: key.service,
            category: key.category,
            collector_active: classification.collector_active.unwrap_or(false),
        }
    });
    DocumentCompatibility {
        source: source.to_string(),
        kind: DocumentKind::Filter,
        title: filter.title.clone(),
        id: filter.id.clone(),
        verdict,
        logsource,
        fields,
        dependencies,
        reasons: deduplicate_reasons(reasons),
    }
}

fn compile_filter(
    filter: &FilterRule,
    detections: &[(String, SigmaRule)],
) -> rsigma_eval::Result<()> {
    let mut engine = rsigma_eval::Engine::new();
    let _ = engine.add_rules(detections.iter().map(|(_, rule)| rule));
    engine.apply_filter(filter)
}

fn correlation_dependency_verdict(
    rule: &CorrelationRule,
    reports: &[DocumentCompatibility],
    identities: &HashMap<String, usize>,
) -> (CompatibilityVerdict, Vec<CompatibilityReason>) {
    let mut reasons = Vec::new();
    let mut verdicts = Vec::new();
    for dependency in &rule.rules {
        let Some(report) = identities
            .get(dependency)
            .and_then(|index| reports.get(*index))
        else {
            reasons.push(CompatibilityReason::reference(
                ReasonCode::MissingReference,
                dependency,
                "referenced document was not found",
            ));
            continue;
        };
        verdicts.push((dependency, report.verdict));
    }
    if !reasons.is_empty() {
        return (
            CompatibilityVerdict::CanNeverFire,
            deduplicate_reasons(reasons),
        );
    }

    let unavailable = verdicts
        .iter()
        .filter(|(_, verdict)| *verdict == CompatibilityVerdict::CanNeverFire)
        .collect::<Vec<_>>();
    let degraded = verdicts
        .iter()
        .any(|(_, verdict)| *verdict == CompatibilityVerdict::Degraded);
    let requires_every_dependency = matches!(
        rule.correlation_type,
        CorrelationType::Temporal | CorrelationType::TemporalOrdered
    );
    let no_dependency_can_fire = unavailable.len() == verdicts.len();

    if no_dependency_can_fire || (requires_every_dependency && !unavailable.is_empty()) {
        reasons.extend(unavailable.into_iter().map(|(dependency, _)| {
            CompatibilityReason::reference(
                ReasonCode::DependencyUnavailable,
                dependency,
                "referenced document cannot fire on the selected platform",
            )
        }));
        return (
            CompatibilityVerdict::CanNeverFire,
            deduplicate_reasons(reasons),
        );
    }

    if degraded || !unavailable.is_empty() {
        reasons.extend(unavailable.into_iter().map(|(dependency, _)| {
            CompatibilityReason::reference(
                ReasonCode::DependencyUnavailable,
                dependency,
                "referenced document cannot contribute events on the selected platform",
            )
        }));
        return (CompatibilityVerdict::Degraded, deduplicate_reasons(reasons));
    }
    (CompatibilityVerdict::CanFire, Vec::new())
}

fn filter_dependency_verdict(
    dependencies: &[String],
    reports: &[DocumentCompatibility],
    identities: &HashMap<String, usize>,
) -> (CompatibilityVerdict, Vec<CompatibilityReason>) {
    let mut reasons = Vec::new();
    let mut usable = 0usize;
    let mut degraded = false;
    for dependency in dependencies {
        match identities
            .get(dependency)
            .and_then(|index| reports.get(*index))
        {
            None => reasons.push(CompatibilityReason::reference(
                ReasonCode::MissingReference,
                dependency,
                "referenced filter target was not found",
            )),
            Some(report) if report.verdict == CompatibilityVerdict::CanNeverFire => {
                reasons.push(CompatibilityReason::reference(
                    ReasonCode::DependencyUnavailable,
                    dependency,
                    "referenced filter target cannot fire on the selected platform",
                ));
            }
            Some(report) => {
                usable += 1;
                degraded |= report.verdict == CompatibilityVerdict::Degraded;
            }
        }
    }
    if usable == 0 {
        (
            CompatibilityVerdict::CanNeverFire,
            deduplicate_reasons(reasons),
        )
    } else if degraded || !reasons.is_empty() {
        (CompatibilityVerdict::Degraded, deduplicate_reasons(reasons))
    } else {
        (CompatibilityVerdict::CanFire, Vec::new())
    }
}

fn evaluate_detections(
    detections: &Detections,
    contract: &EventFieldContract,
) -> ContractEvaluation {
    let mut fields = BTreeMap::new();
    let named = detections
        .named
        .iter()
        .map(|(name, detection)| {
            (
                name.as_str(),
                evaluate_detection(detection, contract, &mut fields),
            )
        })
        .collect::<HashMap<_, _>>();
    let truth = evaluate_conditions_exact(&detections.conditions, &named);
    ContractEvaluation { truth, fields }
}

fn evaluate_detection(
    detection: &Detection,
    contract: &EventFieldContract,
    fields: &mut BTreeMap<String, FieldUse>,
) -> Truth {
    match detection {
        Detection::AllOf(items) => Truth::and(
            items
                .iter()
                .map(|item| evaluate_item(item, contract, fields)),
        ),
        Detection::AnyOf(detections) => Truth::or(
            detections
                .iter()
                .map(|detection| evaluate_detection(detection, contract, fields)),
        ),
        Detection::Keywords(_) => Truth::UNKNOWN,
        Detection::ArrayMatch {
            field,
            quantifier,
            body,
        } => {
            let availability = record_field(field, contract, fields);
            if matches!(availability, Availability::Never(_)) {
                return match quantifier {
                    ArrayQuantifier::AllOrEmpty | ArrayQuantifier::None => Truth::TRUE,
                    ArrayQuantifier::Any | ArrayQuantifier::All => Truth::FALSE,
                };
            }
            let body = evaluate_detection(body, contract, fields);
            match quantifier {
                ArrayQuantifier::Any | ArrayQuantifier::All => body,
                ArrayQuantifier::AllOrEmpty | ArrayQuantifier::None => Truth::UNKNOWN,
            }
        }
        Detection::And(detections) => Truth::and(
            detections
                .iter()
                .map(|detection| evaluate_detection(detection, contract, fields)),
        ),
        Detection::Conditional { named, condition } => {
            let truths = named
                .iter()
                .map(|(name, detection)| {
                    (
                        name.as_str(),
                        evaluate_detection(detection, contract, fields),
                    )
                })
                .collect::<HashMap<_, _>>();
            evaluate_conditions_exact(std::slice::from_ref(condition), &truths)
        }
    }
}

fn evaluate_item(
    item: &DetectionItem,
    contract: &EventFieldContract,
    fields: &mut BTreeMap<String, FieldUse>,
) -> Truth {
    let Some(field) = item.field.name.as_deref() else {
        return Truth::UNKNOWN;
    };
    let availability = record_field(field, contract, fields);
    if item.field.modifiers.contains(&Modifier::FieldRef) {
        for value in &item.values {
            if let SigmaValue::String(value) = value {
                if let Some(target) = value.as_plain() {
                    let target_availability = record_field(&target, contract, fields);
                    if matches!(target_availability, Availability::Never(_)) {
                        return Truth::FALSE;
                    }
                }
            }
        }
    }

    let exists = item.field.modifiers.contains(&Modifier::Exists);
    if exists {
        let expected = item
            .values
            .first()
            .and_then(|value| match value {
                SigmaValue::Bool(value) => Some(*value),
                _ => None,
            })
            .unwrap_or(true);
        return match availability {
            Availability::Always => {
                if expected {
                    Truth::TRUE
                } else {
                    Truth::FALSE
                }
            }
            Availability::Conditional(_) => Truth::UNKNOWN,
            Availability::Never(_) => {
                if expected {
                    Truth::FALSE
                } else {
                    Truth::TRUE
                }
            }
        };
    }

    if matches!(availability, Availability::Never(_)) {
        return if item
            .values
            .iter()
            .any(|value| matches!(value, SigmaValue::Null))
        {
            Truth::TRUE
        } else {
            Truth::FALSE
        };
    }

    if contract.category == "application"
        && field == "Level"
        && item.field.modifiers.is_empty()
        && !item.values.is_empty()
        && item.values.iter().all(|value| {
            matches!(value, SigmaValue::String(text) if text.as_plain().is_some_and(|text| text.parse::<u8>().is_err()))
        })
    {
        return Truth::FALSE;
    }

    let invariants = invariant_values(contract, field);
    if !invariants.is_empty() {
        // How many of the values the shape can hold some listed value matches.
        let matching = invariants
            .iter()
            .filter(|invariant| {
                item.values
                    .iter()
                    .any(|value| value_matches(value, invariant))
            })
            .count();
        let selected = match matching {
            0 => Truth::FALSE,
            count if count == invariants.len() => Truth::TRUE,
            _ => Truth::UNKNOWN,
        };
        if item.field.modifiers.is_empty() {
            return selected;
        }
        if item.field.modifiers == [Modifier::Neq] {
            return selected.not();
        }
    }
    Truth::UNKNOWN
}

fn evaluate_condition(expr: &ConditionExpr, named: &HashMap<&str, Truth>) -> Truth {
    match expr {
        ConditionExpr::And(expressions) => Truth::and(
            expressions
                .iter()
                .map(|expr| evaluate_condition(expr, named)),
        ),
        ConditionExpr::Or(expressions) => Truth::or(
            expressions
                .iter()
                .map(|expr| evaluate_condition(expr, named)),
        ),
        ConditionExpr::Not(expression) => evaluate_condition(expression, named).not(),
        ConditionExpr::Identifier(name) => {
            named.get(name.as_str()).copied().unwrap_or(Truth::FALSE)
        }
        ConditionExpr::Selector {
            quantifier,
            pattern,
        } => evaluate_selector(quantifier, pattern, named),
    }
}

fn evaluate_conditions_exact(conditions: &[ConditionExpr], named: &HashMap<&str, Truth>) -> Truth {
    let unknown = named
        .iter()
        .filter_map(|(name, truth)| (truth.can_be_true && truth.can_be_false).then_some(*name))
        .collect::<Vec<_>>();
    if unknown.len() > 16 {
        return Truth::or(
            conditions
                .iter()
                .map(|condition| evaluate_condition(condition, named)),
        );
    }

    let mut can_be_true = false;
    let mut can_be_false = false;
    let combinations = 1usize << unknown.len();
    for bits in 0..combinations {
        let value = conditions
            .iter()
            .any(|condition| evaluate_condition_assignment(condition, named, &unknown, bits));
        can_be_true |= value;
        can_be_false |= !value;
        if can_be_true && can_be_false {
            break;
        }
    }
    Truth {
        can_be_true,
        can_be_false,
    }
}

fn evaluate_condition_assignment(
    expr: &ConditionExpr,
    named: &HashMap<&str, Truth>,
    unknown: &[&str],
    bits: usize,
) -> bool {
    match expr {
        ConditionExpr::And(expressions) => expressions
            .iter()
            .all(|expr| evaluate_condition_assignment(expr, named, unknown, bits)),
        ConditionExpr::Or(expressions) => expressions
            .iter()
            .any(|expr| evaluate_condition_assignment(expr, named, unknown, bits)),
        ConditionExpr::Not(expression) => {
            !evaluate_condition_assignment(expression, named, unknown, bits)
        }
        ConditionExpr::Identifier(name) => assignment_value(name, named, unknown, bits),
        ConditionExpr::Selector {
            quantifier,
            pattern,
        } => {
            let matches = named
                .keys()
                .filter(|name| pattern.matches_detection_name(name))
                .filter(|name| assignment_value(name, named, unknown, bits))
                .count() as u64;
            let total = named
                .keys()
                .filter(|name| pattern.matches_detection_name(name))
                .count() as u64;
            match quantifier {
                Quantifier::Any => matches > 0,
                Quantifier::All => matches == total,
                Quantifier::Count(required) => matches >= *required,
            }
        }
    }
}

fn assignment_value(
    name: &str,
    named: &HashMap<&str, Truth>,
    unknown: &[&str],
    bits: usize,
) -> bool {
    let Some(truth) = named.get(name) else {
        return false;
    };
    if !truth.can_be_false {
        return true;
    }
    if !truth.can_be_true {
        return false;
    }
    unknown
        .iter()
        .position(|candidate| *candidate == name)
        .is_some_and(|index| bits & (1usize << index) != 0)
}

fn evaluate_selector(
    quantifier: &Quantifier,
    pattern: &SelectorPattern,
    named: &HashMap<&str, Truth>,
) -> Truth {
    let values = named
        .iter()
        .filter(|(name, _)| pattern.matches_detection_name(name))
        .map(|(_, value)| *value)
        .collect::<Vec<_>>();
    match quantifier {
        Quantifier::Any => Truth::or(values),
        Quantifier::All => Truth::and(values),
        Quantifier::Count(required) => {
            let minimum = values.iter().filter(|value| !value.can_be_false).count() as u64;
            let maximum = values.iter().filter(|value| value.can_be_true).count() as u64;
            Truth {
                can_be_true: maximum >= *required,
                can_be_false: minimum < *required,
            }
        }
    }
}

fn record_field(
    field: &str,
    contract: &EventFieldContract,
    fields: &mut BTreeMap<String, FieldUse>,
) -> Availability {
    let availability = availability_for_contract(contract, field);
    let entry = fields.entry(field.to_string()).or_default();
    match availability {
        Availability::Always => entry.saw_always = true,
        Availability::Conditional(reason) => {
            entry.saw_conditional = true;
            entry.reasons.insert(reason.to_string());
        }
        Availability::Never(reason) => {
            entry.saw_never = true;
            entry.reasons.insert(reason.to_string());
        }
    }
    availability
}

fn availability_for_contract(contract: &EventFieldContract, field: &str) -> Availability {
    if matches!(field, "EventID" | "timestamp" | "event_time") {
        return Availability::Always;
    }
    let field = crate::models::field_view::contract_field_name(contract.view, field);
    contract
        .fields
        .iter()
        .find(|candidate| candidate.field == field || candidate.field == "*")
        .map(|candidate| candidate.availability)
        .unwrap_or(Availability::Never(
            if contract.view == FieldViewName::AUDITD {
                "the field is not exposed by this event shape in the auditd field view"
            } else {
                "the field is not exposed by this event shape in the sysmon field view"
            },
        ))
}

/// Every value `field` can hold on this shape, when the shape fixes it.
fn invariant_values(contract: &EventFieldContract, field: &str) -> Vec<String> {
    if field == "EventID" {
        return contract
            .presented_event_ids()
            .map(|event_id| event_id.to_string())
            .collect();
    }
    if contract.category == "application" && field == "Provider_Name" && contract.source != "MSSQL*"
    {
        return vec![contract.source.to_string()];
    }
    let Some(candidate) = contract
        .fields
        .iter()
        .find(|candidate| candidate.field == field)
    else {
        return Vec::new();
    };
    if !candidate.values.is_empty() {
        return candidate.values.iter().map(ToString::to_string).collect();
    }
    candidate
        .value
        .map(ToString::to_string)
        .into_iter()
        .collect()
}

fn value_matches(value: &SigmaValue, invariant: &str) -> bool {
    match value {
        SigmaValue::String(value) => value
            .as_plain()
            .is_some_and(|value| value.eq_ignore_ascii_case(invariant)),
        SigmaValue::Integer(value) => invariant.parse::<i64>() == Ok(*value),
        SigmaValue::Float(value) => invariant
            .parse::<f64>()
            .is_ok_and(|candidate| (candidate - value).abs() < f64::EPSILON),
        SigmaValue::Bool(value) => invariant.parse::<bool>() == Ok(*value),
        SigmaValue::Null => false,
    }
}

/// The contracts a logsource routes to. A contract's routes name the view that
/// evaluates it (`service: auditd` is the auditd view's), so no view is passed.
fn contracts_for_logsource(
    platform: Platform,
    logsource: &LogSourceKey,
) -> Vec<&'static EventFieldContract> {
    FIELD_AVAILABILITY
        .iter()
        .zip(contract_routes())
        .filter(|(contract, _)| contract.platform == platform)
        .filter(|(_, routes)| routes.iter().any(|route| logsource.matches_tuple(route)))
        .map(|(contract, _)| contract)
        .collect()
}

/// The logsource routes of each `FIELD_AVAILABILITY` row, in table order.
fn contract_routes() -> &'static [Vec<LogSourceKey>] {
    static ROUTES: OnceLock<Vec<Vec<LogSourceKey>>> = OnceLock::new();
    ROUTES.get_or_init(|| FIELD_AVAILABILITY.iter().map(routes_for_contract).collect())
}

/// Every route the runtime gives an event of this shape.
///
/// This asks `Engine::concrete_logsource_routes` rather than keeping a copy
/// of its table, so the diagnostic cannot disagree with the runtime about which
/// rules see which events. A shape no sensor can emit has no runtime route, so
/// it keeps the Sysmon route its category would have, which lets rules for it
/// report the field gap instead of a missing logsource.
fn routes_for_contract(contract: &EventFieldContract) -> Vec<LogSourceKey> {
    let Some(category) = field_availability::category_from_name(contract.category) else {
        return vec![LogSourceKey::from_parts(
            Some(platform_product(contract.platform)),
            Some(FieldViewName::SYSMON.as_str()),
            Some(contract.category),
        )];
    };
    let row = contract
        .action
        .and_then(|action| event_actions::row_for_action(category, action));
    let opcode = row.map_or(0, |row| row.action_code);
    let mut event_ids = contract.presented_event_ids().collect::<Vec<_>>();
    if event_ids.is_empty() {
        event_ids.push(row.map_or(0, |row| row.event_id));
    }
    let mut routes: Vec<LogSourceKey> = Vec::new();
    for event_id in event_ids {
        for route in
            Engine::concrete_logsource_routes(contract.platform, category, event_id, opcode)
                .into_iter()
                .filter(|route| route.view == contract.view)
                .map(|route| route.key)
        {
            if !routes.contains(&route) {
                routes.push(route);
            }
        }
    }
    routes
}

fn collector_enabled_for_contract(config: &AppConfig, contract: &EventFieldContract) -> bool {
    if contract.platform == Platform::Windows && contract.category == "security" {
        match contract.event_id {
            Some(5152 | 5156 | 5157) => {
                return config.windows.security_filtering_platform_connections
            }
            Some(4672 | 4799 | 5140) => return config.windows.security_long_tail_events,
            Some(4768 | 4769 | 4662 | 4742 | 4661 | 4673 | 5137 | 5141) => {
                return config.windows.security_domain_controller_events
            }
            _ => {}
        }
    }
    contract.provider != "none"
}

fn field_reports(
    platform: Platform,
    logsource: &LogSourceKey,
    fields: BTreeMap<String, FieldUse>,
) -> Vec<FieldCompatibility> {
    fields
        .into_iter()
        .map(|(field, mut usage)| {
            usage
                .fidelity
                .extend(potential_fidelity(platform, logsource, &field));
            let availability = if usage.saw_always && !usage.saw_conditional && !usage.saw_never {
                FieldCompatibilityStatus::Always
            } else if usage.saw_always || usage.saw_conditional {
                FieldCompatibilityStatus::Conditional
            } else {
                FieldCompatibilityStatus::Never
            };
            let reliable = measured_reliable(platform, logsource, &field);
            FieldCompatibility {
                field,
                availability,
                reasons: usage.reasons.into_iter().collect(),
                fidelity: usage.fidelity.into_iter().collect(),
                reliable,
            }
        })
        .collect()
}

/// Fields whose conditional or derived availability has been measured as rare
/// loss on ordinary workloads.
///
/// Windows process start: `CommandLine` is back-filled for 99.9% of starts
/// and `ParentImage` is populated, absolute, and correct for 100%.
/// Linux process start (eBPF, kernel 7.0, rustinel 1.9.1, 9.2k starts with a
/// 6000-exec four-way fork storm): `CommandLine`, `Image`, `ParentImage`, and
/// `ParentCommandLine` were populated for 100% with no loss, and `Image` was
/// absolute for 100% including relative and 150-byte paths.
/// macOS process start (Endpoint Security, rustinel 1.9.1, 7.5k starts with a
/// 6000-exec four-way fork storm): `CommandLine` and `Image` were populated
/// and absolute for 100% with no loss.
/// macOS `ParentImage` was present only when the parent's exec had been
/// observed (301 of 301) and never for a parent that predates the sensor or
/// never execs (0 of 7220), so it stays strict. Since then, parents already
/// running at startup are seeded, but that is not re-measured.
/// Other platforms and fields stay strict until they are measured too.
fn measured_reliable(platform: Platform, logsource: &LogSourceKey, field: &str) -> bool {
    if logsource.category.as_deref() != Some("process_creation") {
        return false;
    }
    match platform {
        Platform::Windows => matches!(
            field,
            "CommandLine" | "Image" | "ParentImage" | "ParentProcessId"
        ),
        Platform::Linux => matches!(
            field,
            "CommandLine" | "Image" | "ParentImage" | "ParentCommandLine"
        ),
        Platform::MacOS => matches!(field, "CommandLine" | "Image"),
    }
}

fn potential_fidelity(platform: Platform, logsource: &LogSourceKey, field: &str) -> Vec<Fidelity> {
    let category = logsource.category.as_deref().unwrap_or_default();
    let mut values = BTreeSet::new();
    if matches!(field, "ParentImage" | "ParentCommandLine" | "ParentUser") {
        values.insert(Fidelity::Derived);
    }
    if category == "process_creation" && matches!(field, "CommandLine" | "ParentProcessId" | "User")
    {
        values.insert(Fidelity::Derived);
    }
    if platform == Platform::Linux
        && category == "process_creation"
        && matches!(field, "Image" | "ProcessStartTime" | "CurrentDirectory")
    {
        values.insert(Fidelity::Derived);
    }
    if category != "process_creation" && matches!(field, "Image" | "User") {
        values.insert(Fidelity::Derived);
    }
    if platform == Platform::MacOS
        && matches!(category, "network_connection" | "dns_query")
        && matches!(field, "Image" | "ProcessId")
    {
        values.insert(Fidelity::Derived);
        values.insert(Fidelity::BestEffort);
    }
    if platform == Platform::Windows && category == "registry_event" && field == "TargetObject" {
        values.insert(Fidelity::Derived);
    }
    if matches!(
        category,
        "file_event" | "file_create" | "file_delete" | "file_rename"
    ) && matches!(field, "TargetFilename" | "SourceFilename")
    {
        values.insert(Fidelity::Derived);
    }
    values.into_iter().collect()
}

fn merge_field_uses(target: &mut BTreeMap<String, FieldUse>, source: BTreeMap<String, FieldUse>) {
    for (field, source) in source {
        let target = target.entry(field).or_default();
        target.saw_always |= source.saw_always;
        target.saw_conditional |= source.saw_conditional;
        target.saw_never |= source.saw_never;
        target.reasons.extend(source.reasons);
        target.fidelity.extend(source.fidelity);
    }
}

fn has_limitation(reasons: &[CompatibilityReason]) -> bool {
    reasons
        .iter()
        .any(|reason| reason.severity == ReasonSeverity::Limitation)
}

fn limitation_reasons(fields: &[FieldCompatibility]) -> Vec<CompatibilityReason> {
    let mut reasons = Vec::new();
    for field in fields {
        let severity = if field.reliable {
            ReasonSeverity::Caveat
        } else {
            ReasonSeverity::Limitation
        };
        match field.availability {
            FieldCompatibilityStatus::Always => {}
            FieldCompatibilityStatus::Conditional => reasons.push(
                CompatibilityReason::field(
                    ReasonCode::ConditionalField,
                    &field.field,
                    field.reasons.join("; "),
                )
                .with_severity(severity),
            ),
            FieldCompatibilityStatus::Never => reasons.push(CompatibilityReason::field(
                ReasonCode::UnavailableField,
                &field.field,
                field.reasons.join("; "),
            )),
        }
        for fidelity in &field.fidelity {
            let code = match fidelity {
                Fidelity::Derived => ReasonCode::DerivedField,
                Fidelity::BestEffort => ReasonCode::BestEffortField,
                Fidelity::Truncated => ReasonCode::TruncatedField,
                Fidelity::Stale => ReasonCode::StaleField,
            };
            let severity = if *fidelity == Fidelity::Derived {
                severity
            } else {
                ReasonSeverity::Limitation
            };
            reasons.push(
                CompatibilityReason::field(
                    code,
                    &field.field,
                    format!(
                        "{} may be {} on this platform",
                        field.field,
                        fidelity_label(*fidelity)
                    ),
                )
                .with_severity(severity),
            );
        }
    }
    deduplicate_reasons(reasons)
}

fn unavailable_reasons(fields: &[FieldCompatibility]) -> Vec<CompatibilityReason> {
    deduplicate_reasons(
        fields
            .iter()
            .filter(|field| field.availability == FieldCompatibilityStatus::Never)
            .map(|field| {
                CompatibilityReason::field(
                    ReasonCode::UnavailableField,
                    &field.field,
                    field.reasons.join("; "),
                )
            })
            .collect(),
    )
}

fn fidelity_label(fidelity: Fidelity) -> &'static str {
    match fidelity {
        Fidelity::Derived => "derived",
        Fidelity::BestEffort => "best-effort",
        Fidelity::Truncated => "truncated",
        Fidelity::Stale => "stale",
    }
}

fn field_status_label(status: FieldCompatibilityStatus) -> &'static str {
    match status {
        FieldCompatibilityStatus::Always => "always",
        FieldCompatibilityStatus::Conditional => "conditional",
        FieldCompatibilityStatus::Never => "never",
    }
}

fn correlation_fields(rule: &CorrelationRule) -> BTreeSet<String> {
    let mut fields = rule.group_by.iter().cloned().collect::<BTreeSet<_>>();
    if let CorrelationCondition::Threshold {
        field: Some(condition_fields),
        ..
    } = &rule.condition
    {
        fields.extend(condition_fields.iter().cloned());
    }
    for alias in &rule.aliases {
        fields.extend(alias.mapping.values().cloned());
    }
    fields
}

fn field_across_dependencies(
    field: &str,
    dependencies: &[String],
    contracts: &HashMap<String, Vec<&'static EventFieldContract>>,
) -> FieldCompatibility {
    let mut use_entry = FieldUse::default();
    for contract in dependencies
        .iter()
        .filter_map(|dependency| contracts.get(dependency))
        .flatten()
    {
        let mut fields = BTreeMap::new();
        record_field(field, contract, &mut fields);
        if let Some(found) = fields.remove(field) {
            use_entry.saw_always |= found.saw_always;
            use_entry.saw_conditional |= found.saw_conditional;
            use_entry.saw_never |= found.saw_never;
            use_entry.reasons.extend(found.reasons);
        }
    }
    let availability = if use_entry.saw_always && !use_entry.saw_conditional && !use_entry.saw_never
    {
        FieldCompatibilityStatus::Always
    } else if use_entry.saw_always || use_entry.saw_conditional {
        FieldCompatibilityStatus::Conditional
    } else {
        FieldCompatibilityStatus::Never
    };
    FieldCompatibility {
        field: field.to_string(),
        availability,
        reasons: use_entry.reasons.into_iter().collect(),
        fidelity: Vec::new(),
        reliable: false,
    }
}

fn add_detection_identity(identities: &mut HashMap<String, usize>, rule: &SigmaRule, index: usize) {
    for key in detection_keys(rule) {
        identities.insert(key, index);
    }
}

fn detection_keys(rule: &SigmaRule) -> Vec<String> {
    let mut keys = vec![rule.title.clone()];
    if let Some(id) = &rule.id {
        keys.push(id.clone());
    }
    if let Some(name) = &rule.name {
        keys.push(name.clone());
    }
    keys
}

fn normalize(value: Option<&str>) -> Option<String> {
    value
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
}

fn sorted_unique(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn deduplicate_reasons(reasons: Vec<CompatibilityReason>) -> Vec<CompatibilityReason> {
    let mut seen = HashSet::new();
    reasons
        .into_iter()
        .filter(|reason| {
            seen.insert((
                reason.code,
                reason.field.clone(),
                reason.reference.clone(),
                reason.message.clone(),
            ))
        })
        .collect()
}

pub fn format_human(report: &SigmaCompatibilityReport) -> String {
    let mut output = format!(
        "Sigma compatibility\nPlatform: {}\nField view: {}\nRules: {}\nSummary: {} can fire ({} with caveats), {} degraded, {} can never fire\n",
        report.platform,
        report.field_view,
        report.rules_path.display(),
        report.summary.verdicts.can_fire,
        report.summary.can_fire_with_caveats,
        report.summary.verdicts.degraded,
        report.summary.verdicts.can_never_fire,
    );
    for document in &report.documents {
        output.push_str(&format!(
            "\n[{}] {} {} ({})\n  source: {}\n",
            document.verdict.as_str(),
            document.kind.as_str(),
            document.title,
            document.id.as_deref().unwrap_or("no id"),
            document.source,
        ));
        if let Some(logsource) = &document.logsource {
            let key = LogSourceKey {
                product: logsource.product.clone(),
                service: logsource.service.clone(),
                category: logsource.category.clone(),
            };
            output.push_str(&format!("  logsource: {}\n", key.display()));
        }
        if !document.dependencies.is_empty() {
            output.push_str(&format!(
                "  dependencies: {}\n",
                document.dependencies.join(", ")
            ));
        }
        for field in &document.fields {
            let fidelity = if field.fidelity.is_empty() {
                String::new()
            } else {
                format!(
                    ", fidelity: {}",
                    field
                        .fidelity
                        .iter()
                        .map(|value| fidelity_label(*value))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            output.push_str(&format!(
                "  field {}: {}{}\n",
                field.field,
                field_status_label(field.availability),
                fidelity
            ));
        }
        for reason in &document.reasons {
            let label = match reason.severity {
                ReasonSeverity::Limitation => "",
                ReasonSeverity::Caveat => "caveat ",
            };
            output.push_str(&format!(
                "  {label}{}: {}\n",
                reason.code.as_str(),
                reason.message
            ));
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn report(yaml: &str, platform: Platform) -> SigmaCompatibilityReport {
        let dir = TempDir::new().expect("temporary rules directory");
        fs::write(dir.path().join("rules.yml"), yaml).expect("write fixture");
        analyze_rules(dir.path(), platform, &AppConfig::default()).expect("analyze rules")
    }

    #[test]
    fn product_less_dns_rule_is_not_reported_inert_on_any_platform() {
        let rule = r#"title: Telegram Bot API Request
logsource:
  category: dns
detection:
  selection:
    query: api.telegram.org
  condition: selection
"#;
        for platform in [Platform::Windows, Platform::Linux, Platform::MacOS] {
            let report = report(rule, platform);
            assert_ne!(
                report.documents[0].verdict,
                CompatibilityVerdict::CanNeverFire,
                "{platform:?}"
            );
        }
    }

    fn auditd_rule(title: &str, detection: &str) -> String {
        format!(
            "title: {title}\nlogsource:\n  product: linux\n  service: auditd\ndetection:\n{detection}"
        )
    }

    #[test]
    fn auditd_rules_the_view_can_satisfy_are_backed_by_an_active_collector() {
        let report = report(
            &auditd_rule(
                "Clipboard",
                "  selection:\n    type: EXECVE\n    a0: xclip\n    a1: '-sel'\n  condition: selection\n",
            ),
            Platform::Linux,
        );
        let document = &report.documents[0];
        assert_ne!(
            document.verdict,
            CompatibilityVerdict::CanNeverFire,
            "{:?}",
            document.reasons
        );
        assert_eq!(
            document.logsource.as_ref().map(|l| l.collector_active),
            Some(true)
        );
    }

    #[test]
    fn auditd_rules_the_view_cannot_satisfy_are_reported_unsatisfiable() {
        for (title, detection) in [
            (
                "Audit key",
                "  selection:\n    key: susp_activity\n  condition: selection\n",
            ),
            (
                "Service stop",
                "  selection:\n    type: SERVICE_STOP\n    unit: ufw\n  condition: selection\n",
            ),
            (
                "Sysinfo syscall",
                "  selection:\n    type: SYSCALL\n    SYSCALL: sysinfo\n  condition: selection\n",
            ),
            (
                "Mknod syscall",
                "  selection:\n    type: SYSCALL\n    SYSCALL: mknod\n  condition: selection\n",
            ),
        ] {
            let report = report(&auditd_rule(title, detection), Platform::Linux);
            let document = &report.documents[0];
            assert_eq!(
                document.verdict,
                CompatibilityVerdict::CanNeverFire,
                "{title}"
            );
            assert!(
                document
                    .reasons
                    .iter()
                    .any(|reason| reason.code == ReasonCode::UnavailableField),
                "{title}: {:?}",
                document.reasons
            );
        }
    }

    #[test]
    fn auditd_rule_with_one_satisfiable_branch_still_fires() {
        let report = report(
            &auditd_rule(
                "Memfd or audio",
                "  execve:\n    type: EXECVE\n    a0: arecord\n  syscall:\n    type: SYSCALL\n    SYSCALL: memfd_create\n  condition: 1 of *\n",
            ),
            Platform::Linux,
        );
        assert_ne!(
            report.documents[0].verdict,
            CompatibilityVerdict::CanNeverFire
        );
    }

    #[test]
    fn dns_txt_rule_names_the_blocking_field_off_linux() {
        let rule = r#"title: DNS TXT Answer
logsource:
  category: dns
detection:
  selection:
    record_type: TXT
    answer|contains: exec
  condition: selection
"#;
        assert_ne!(
            report(rule, Platform::Linux).documents[0].verdict,
            CompatibilityVerdict::CanNeverFire
        );
        for platform in [Platform::Windows, Platform::MacOS] {
            assert_eq!(
                report(rule, platform).documents[0].verdict,
                CompatibilityVerdict::CanNeverFire,
                "{platform:?}"
            );
        }
    }

    #[test]
    fn unavailable_or_branch_does_not_make_rule_inert() {
        let report = report(
            r#"title: Alternative fields
logsource:
  product: linux
  category: process_creation
detection:
  unavailable:
    OriginalFileName: whoami.exe
  available:
    Image|endswith: /whoami
  condition: unavailable or available
"#,
            Platform::Linux,
        );
        assert_eq!(report.documents[0].verdict, CompatibilityVerdict::Degraded);
        assert!(report.documents[0]
            .reasons
            .iter()
            .any(|reason| reason.code == ReasonCode::UnavailableField));
    }

    #[test]
    fn negated_unavailable_selection_can_still_match() {
        let report = report(
            r#"title: Negated field
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: /whoami
  filter:
    OriginalFileName: whoami.exe
  condition: selection and not filter
"#,
            Platform::Linux,
        );
        assert_ne!(
            report.documents[0].verdict,
            CompatibilityVerdict::CanNeverFire
        );
    }

    #[test]
    fn required_unavailable_field_is_inert() {
        let report = report(
            r#"title: Windows-only field
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    OriginalFileName: whoami.exe
  condition: selection
"#,
            Platform::Linux,
        );
        assert_eq!(
            report.documents[0].verdict,
            CompatibilityVerdict::CanNeverFire
        );
        assert_eq!(report.exit_code, 1);
    }

    #[test]
    fn contradictory_condition_cannot_fire() {
        let report = report(
            r#"title: Contradictory condition
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    ProcessId|exists: true
  condition: selection and not selection
"#,
            Platform::Linux,
        );
        assert_eq!(
            report.documents[0].verdict,
            CompatibilityVerdict::CanNeverFire
        );
    }

    #[test]
    fn measured_linux_process_fields_are_caveats() {
        let report = report(
            r#"title: Parent image fidelity
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    ParentImage|endswith: /bash
    CommandLine|contains: /dev/tcp/
  condition: selection
"#,
            Platform::Linux,
        );
        let document = &report.documents[0];
        assert_eq!(document.verdict, CompatibilityVerdict::CanFire);
        assert!(document.reasons.iter().any(|reason| {
            reason.code == ReasonCode::DerivedField
                && reason.severity == ReasonSeverity::Caveat
                && reason.field.as_deref() == Some("ParentImage")
        }));
    }

    #[test]
    fn macos_command_line_is_a_caveat_but_parent_image_degrades() {
        let yaml = |field: &str| {
            format!(
                "title: macOS fidelity\nlogsource:\n  product: macos\n  category: process_creation\ndetection:\n  selection:\n    {field}|contains: x\n  condition: selection\n"
            )
        };
        let command_line = report(&yaml("CommandLine"), Platform::MacOS);
        assert_eq!(
            command_line.documents[0].verdict,
            CompatibilityVerdict::CanFire
        );
        let parent = report(&yaml("ParentImage"), Platform::MacOS);
        assert_eq!(parent.documents[0].verdict, CompatibilityVerdict::Degraded);
    }

    #[test]
    fn unmeasured_linux_process_field_is_degraded() {
        let report = report(
            r#"title: User fidelity
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    User: root
  condition: selection
"#,
            Platform::Linux,
        );
        assert_eq!(report.documents[0].verdict, CompatibilityVerdict::Degraded);
        assert!(report.documents[0].reasons.iter().any(|reason| {
            reason.code == ReasonCode::DerivedField
                && reason.severity == ReasonSeverity::Limitation
                && reason.field.as_deref() == Some("User")
        }));
    }

    #[test]
    fn measured_windows_process_fields_are_caveats() {
        let report = report(
            r#"title: Windows command line
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: \\cmd.exe
    CommandLine|contains: /c
    ParentImage|endswith: \\winword.exe
  condition: selection
"#,
            Platform::Windows,
        );
        let document = &report.documents[0];
        assert_eq!(document.verdict, CompatibilityVerdict::CanFire);
        assert!(!document.reasons.is_empty());
        assert!(document
            .reasons
            .iter()
            .all(|reason| reason.severity == ReasonSeverity::Caveat));
        assert_eq!(report.summary.can_fire_with_caveats, 1);
        assert_eq!(report.exit_code, 0);
    }

    #[test]
    fn unmeasured_windows_field_still_degrades() {
        let report = report(
            r#"title: Windows original file name
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: /c
    OriginalFileName: Cmd.Exe
  condition: selection
"#,
            Platform::Windows,
        );
        let document = &report.documents[0];
        assert_eq!(document.verdict, CompatibilityVerdict::Degraded);
        assert!(document.reasons.iter().any(|reason| {
            reason.severity == ReasonSeverity::Limitation
                && reason.field.as_deref() == Some("OriginalFileName")
        }));
        assert_eq!(report.exit_code, 1);
    }

    fn windows_verdict(logsource: &str, detection: &str) -> CompatibilityVerdict {
        let report = report(
            &format!(
                "title: Event ID shape\nlogsource:\n  product: windows\n{logsource}detection:\n  selection:\n{detection}  condition: selection\n"
            ),
            Platform::Windows,
        );
        report.documents[0].verdict
    }

    #[test]
    fn sysmon_service_only_reaches_the_event_ids_the_runtime_routes_to_it() {
        // Sysmon 16 (config change) is on none of the shapes `service: sysmon`
        // routes to, and Sysmon 27 to 29 are not file IDs the sensor numbers.
        for event_id in [16, 27, 28, 29] {
            assert_eq!(
                windows_verdict("  service: sysmon\n", &format!("    EventID: {event_id}\n")),
                CompatibilityVerdict::CanNeverFire,
                "EventID {event_id}"
            );
        }
        assert_ne!(
            windows_verdict("  service: sysmon\n", "    EventID: 1\n"),
            CompatibilityVerdict::CanNeverFire
        );
    }

    #[test]
    fn file_and_registry_shapes_pin_the_ids_the_sensors_emit() {
        for (category, event_id, can_fire) in [
            ("file_event", 11, true),
            ("file_delete", 23, true),
            ("file_event", 27, false),
            ("registry_event", 13, true),
            ("registry_event", 14, false),
        ] {
            let verdict = windows_verdict(
                &format!("  category: {category}\n"),
                &format!("    EventID: {event_id}\n"),
            );
            assert_eq!(
                verdict != CompatibilityVerdict::CanNeverFire,
                can_fire,
                "{category} {event_id}"
            );
        }
    }

    #[test]
    fn wmi_event_category_does_not_reach_sysmon_subscription_ids_or_the_5861_fields() {
        for event_id in [19, 20, 21] {
            assert_eq!(
                windows_verdict(
                    "  category: wmi_event\n",
                    &format!("    EventID: {event_id}\n")
                ),
                CompatibilityVerdict::CanNeverFire,
                "EventID {event_id}"
            );
        }
        // `Destination` exists only on 5861, which routes under `service: wmi`
        // with no category.
        assert_eq!(
            windows_verdict("  category: wmi_event\n", "    Destination|contains: x\n"),
            CompatibilityVerdict::CanNeverFire
        );
        assert_ne!(
            windows_verdict("  category: wmi_event\n", "    EventID: 22\n"),
            CompatibilityVerdict::CanNeverFire
        );
    }

    #[test]
    fn windows_dns_rules_may_pin_the_sysmon_alias_id() {
        for event_id in [22, 3006, 3008] {
            assert_ne!(
                windows_verdict(
                    "  category: dns_query\n",
                    &format!("    EventID: {event_id}\n")
                ),
                CompatibilityVerdict::CanNeverFire,
                "EventID {event_id}"
            );
        }
    }

    /// The shape's routes must be the runtime's, and its IDs must be the ones
    /// the runtime presents to Sigma and the sensors number.
    #[test]
    fn contract_routes_and_event_ids_match_the_runtime() {
        use crate::models::EventCategory;

        for (contract, routes) in FIELD_AVAILABILITY.iter().zip(contract_routes()) {
            let Some(category) = field_availability::category_from_name(contract.category) else {
                continue;
            };
            let row = contract
                .action
                .and_then(|action| event_actions::row_for_action(category, action));
            if matches!(category, EventCategory::File | EventCategory::Registry)
                && contract.platform == Platform::Windows
            {
                let row = row.expect("file and registry actions have a row");
                assert_eq!(
                    contract.event_id,
                    Some(row.event_id),
                    "{} {:?}",
                    contract.category,
                    contract.action
                );
            }
            assert!(
                !routes.is_empty(),
                "{} {:?} has no runtime route",
                contract.category,
                contract.action
            );
            for event_id in contract.presented_event_ids() {
                let runtime = Engine::concrete_logsource_routes(
                    contract.platform,
                    category,
                    event_id,
                    row.map_or(0, |row| row.action_code),
                );
                assert!(
                    runtime
                        .iter()
                        .filter(|route| route.view == contract.view)
                        .all(|route| routes.contains(&route.key)),
                    "{} {event_id}",
                    contract.category
                );
            }
        }
    }

    #[test]
    fn wmi_trace_shape_lists_no_operational_or_sysmon_subscription_ids() {
        let ids = field_availability::WMI_TRACE_EVENT_IDS;
        assert!(ids.iter().all(|id| !(5857..=5861).contains(id)));
        assert!(ids.iter().all(|id| !(19..=21).contains(id)));
    }

    #[test]
    fn exact_event_id_observes_disabled_collector() {
        let report = report(
            r#"title: Filtering platform
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5156
  condition: selection
"#,
            Platform::Windows,
        );
        assert_eq!(
            report.documents[0].reasons[0].code,
            ReasonCode::CollectorDisabled
        );
    }

    #[test]
    fn defender_operational_rule_has_a_backed_logsource_and_fields() {
        let report = report(
            r#"title: Defender exclusion added
logsource:
  product: windows
  service: windefend
detection:
  selection:
    EventID: 5007
    NewValue|contains: Exclusions
    Provider_Name: Microsoft-Windows-Windows Defender
  condition: selection
"#,
            Platform::Windows,
        );
        assert_ne!(
            report.documents[0].verdict,
            CompatibilityVerdict::CanNeverFire
        );
        assert!(!report.documents[0]
            .reasons
            .iter()
            .any(|reason| reason.code == ReasonCode::InactiveCollector));
    }

    #[test]
    fn product_less_antivirus_rule_fires_on_windows_only() {
        let rule = r#"title: Antivirus Hacktool Signature
logsource:
  category: antivirus
detection:
  selection:
    Signature|contains: HackTool
  condition: selection
"#;
        let windows = report(rule, Platform::Windows);
        assert_ne!(
            windows.documents[0].verdict,
            CompatibilityVerdict::CanNeverFire
        );
        for platform in [Platform::Linux, Platform::MacOS] {
            let other = report(rule, platform);
            assert_eq!(
                other.documents[0].verdict,
                CompatibilityVerdict::CanNeverFire
            );
            assert_eq!(
                other.documents[0].reasons[0].code,
                ReasonCode::UnknownLogsource
            );
        }
    }

    #[test]
    fn missing_correlation_dependency_is_reported() {
        let report = report(
            r#"title: Missing dependency
correlation:
  type: event_count
  rules:
    - absent-rule
  timespan: 5m
  condition:
    gte: 2
"#,
            Platform::Linux,
        );
        assert_eq!(report.documents[0].kind, DocumentKind::Correlation);
        assert_eq!(
            report.documents[0].reasons[0].code,
            ReasonCode::MissingReference
        );
    }

    #[test]
    fn untargeted_filter_can_never_fire() {
        let report = report(
            r#"title: Suppress everything
logsource:
  category: process_creation
filter:
  rules: any
  selection:
    Image|exists: true
  condition: not selection
"#,
            Platform::Linux,
        );
        let filter = &report.documents[0];
        assert_eq!(filter.kind, DocumentKind::Filter);
        assert_eq!(filter.verdict, CompatibilityVerdict::CanNeverFire);
        assert_eq!(filter.reasons[0].code, ReasonCode::UntargetedFilter);
    }
}
