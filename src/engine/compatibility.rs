//! Per-document Sigma compatibility diagnostics.
//!
//! The analyzer is deliberately separate from rule loading. It inspects every
//! parsed document, including documents that the runtime would filter out,
//! and evaluates detection conditions against the field shapes the selected
//! platform can actually emit.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rsigma_parser::{
    ArrayQuantifier, ConditionExpr, CorrelationCondition, CorrelationRule, CorrelationType,
    Detection, DetectionItem, Detections, FilterRule, FilterRuleTarget, Modifier, Quantifier,
    SelectorPattern, SigmaRule, SigmaValue,
};
use serde::Serialize;

use crate::config::AppConfig;
use crate::field_availability::{Availability, EventFieldContract, FIELD_AVAILABILITY};
use crate::models::{Fidelity, FieldViewName};
use crate::sensor::{Platform, SensorAction};

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
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompatibilityReason {
    pub code: ReasonCode,
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
            message: message.into(),
            field: None,
            reference: None,
        }
    }

    fn field(code: ReasonCode, field: &str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            field: Some(field.to_string()),
            reference: None,
        }
    }

    fn reference(code: ReasonCode, reference: &str, message: impl Into<String>) -> Self {
        Self {
            code,
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
                CompatibilityVerdict::CanFire => summary.verdicts.can_fire += 1,
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
        let report = analyze_detection(source, rule, platform, field_view, config, &engine);
        let index = reports.len();
        add_detection_identity(&mut identities, rule, index);
        let contracts = contracts_for_logsource(
            platform,
            field_view,
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
        field_view,
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
    field_view: FieldViewName,
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

    let contracts = contracts_for_logsource(platform, field_view, &key);
    if contracts.is_empty() {
        report.reasons.push(CompatibilityReason::new(
            ReasonCode::NoPlatformTelemetry,
            "no emitted event shape provides telemetry for this logsource",
        ));
        return report;
    }

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
        report.verdict = if report.reasons.is_empty() {
            CompatibilityVerdict::CanFire
        } else {
            CompatibilityVerdict::Degraded
        };
    } else if disabled_viable {
        report.reasons.push(CompatibilityReason::new(
            ReasonCode::CollectorDisabled,
            "the only compatible event shapes are disabled by configuration",
        ));
    } else {
        report.reasons = unavailable_reasons(&report.fields);
        if report.reasons.is_empty() {
            report.reasons.push(CompatibilityReason::new(
                ReasonCode::UnavailableField,
                "the condition cannot be satisfied by any emitted event shape",
            ));
        }
    }
    report
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
        verdict = CompatibilityVerdict::Degraded;
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
    field_view: FieldViewName,
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
        FilterRuleTarget::Any => Vec::new(),
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
        |key| contracts_for_logsource(context.platform, context.field_view, key),
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
            if !limitations.is_empty() || verdict == CompatibilityVerdict::Degraded {
                verdict = CompatibilityVerdict::Degraded;
                reasons.extend(limitations);
            }
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

    if let Some(invariant) = invariant_value(contract, field) {
        if item.field.modifiers.is_empty() {
            let matched = item
                .values
                .iter()
                .any(|value| value_matches(value, &invariant));
            return if matched { Truth::TRUE } else { Truth::FALSE };
        }
        if item.field.modifiers == [Modifier::Neq] {
            let matched = item
                .values
                .iter()
                .all(|value| !value_matches(value, &invariant));
            return if matched { Truth::TRUE } else { Truth::FALSE };
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
    contract
        .fields
        .iter()
        .find(|candidate| candidate.field == field || candidate.field == "*")
        .map(|candidate| candidate.availability)
        .unwrap_or(Availability::Never(
            "the field is not exposed by this event shape in the sysmon field view",
        ))
}

fn invariant_value(contract: &EventFieldContract, field: &str) -> Option<String> {
    if field == "EventID" {
        return contract.event_id.map(|event_id| event_id.to_string());
    }
    contract
        .fields
        .iter()
        .find(|candidate| candidate.field == field)
        .and_then(|candidate| candidate.value)
        .map(ToString::to_string)
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

fn contracts_for_logsource(
    platform: Platform,
    field_view: FieldViewName,
    logsource: &LogSourceKey,
) -> Vec<&'static EventFieldContract> {
    FIELD_AVAILABILITY
        .iter()
        .filter(|contract| contract.platform == platform)
        .filter(|contract| contract.view == field_view)
        .filter(|contract| contract_matches_logsource(contract, logsource))
        .collect()
}

fn contract_matches_logsource(contract: &EventFieldContract, logsource: &LogSourceKey) -> bool {
    if let Some(category) = logsource.category.as_deref() {
        let (mapped, action) = match category {
            "file_create" => ("file_event", Some(SensorAction::Create)),
            "file_delete" => ("file_event", Some(SensorAction::Delete)),
            "file_rename" => ("file_event", Some(SensorAction::Rename)),
            "file_change" => ("file_event", Some(SensorAction::Set)),
            "registry_add" => ("registry_event", Some(SensorAction::Create)),
            "registry_set" => ("registry_event", Some(SensorAction::Set)),
            "registry_delete" => ("registry_event", Some(SensorAction::Delete)),
            "network" if logsource.service.as_deref() == Some("connection") => {
                ("network_connection", None)
            }
            "network" | "dns" if logsource.service.as_deref() == Some("dns") => ("dns_query", None),
            other => (other, None),
        };
        if contract.category != mapped
            || action.is_some_and(|action| contract.action != Some(action))
        {
            return false;
        }
    }
    if logsource.category.is_none() {
        if let Some(service) = logsource.service.as_deref() {
            let categories: &[&str] = match service {
                "security" => &["security"],
                "system" => &["service_creation"],
                "taskscheduler" | "task scheduler" => &["task_creation"],
                "powershell" | "powershell-classic" | "microsoft-windows-powershell" => {
                    &["ps_script", "ps_module"]
                }
                "dns-client" | "dns" => &["dns_query"],
                "wmi" => &["wmi_event"],
                "connection" => &["network_connection"],
                "sysmon" => &[],
                _ => return false,
            };
            if !categories.is_empty() && !categories.contains(&contract.category) {
                return false;
            }
        }
    }
    true
}

fn collector_enabled_for_contract(config: &AppConfig, contract: &EventFieldContract) -> bool {
    if contract.platform == Platform::Windows
        && contract.category == "security"
        && matches!(contract.event_id, Some(5152 | 5156 | 5157))
    {
        return config.windows.security_filtering_platform_connections;
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
            FieldCompatibility {
                field,
                availability,
                reasons: usage.reasons.into_iter().collect(),
                fidelity: usage.fidelity.into_iter().collect(),
            }
        })
        .collect()
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

fn limitation_reasons(fields: &[FieldCompatibility]) -> Vec<CompatibilityReason> {
    let mut reasons = Vec::new();
    for field in fields {
        match field.availability {
            FieldCompatibilityStatus::Always => {}
            FieldCompatibilityStatus::Conditional => reasons.push(CompatibilityReason::field(
                ReasonCode::ConditionalField,
                &field.field,
                field.reasons.join("; "),
            )),
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
            reasons.push(CompatibilityReason::field(
                code,
                &field.field,
                format!(
                    "{} may be {} on this platform",
                    field.field,
                    fidelity_label(*fidelity)
                ),
            ));
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
        "Sigma compatibility\nPlatform: {}\nField view: {}\nRules: {}\nSummary: {} can fire, {} degraded, {} can never fire\n",
        report.platform,
        report.field_view,
        report.rules_path.display(),
        report.summary.verdicts.can_fire,
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
            output.push_str(&format!("  {}: {}\n", reason.code.as_str(), reason.message));
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
    fn derived_parent_image_is_degraded_on_linux() {
        let report = report(
            r#"title: Parent image fidelity
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    ParentImage|endswith: /bash
  condition: selection
"#,
            Platform::Linux,
        );
        assert_eq!(report.documents[0].verdict, CompatibilityVerdict::Degraded);
        assert!(report.documents[0].reasons.iter().any(|reason| {
            reason.code == ReasonCode::DerivedField
                && reason.field.as_deref() == Some("ParentImage")
        }));
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
}
