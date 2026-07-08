use std::{
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use chrono::{SecondsFormat, Utc};
use semver::{Prerelease, Version, VersionReq};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use zip::ZipArchive;

use crate::config::AppConfig;

pub const DEFAULT_CATALOG_URL: &str =
    "https://github.com/Karib0u/rustinel-rules/releases/latest/download/index.json";
const INDEX_SCHEMA: &str = "rustinel-rules/index@1";
const SUPPORTED_PACK_SCHEMA_VERSIONS: &[u32] = &[1, 2];
const MAX_CATALOG_BYTES: u64 = 2 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 50 * 1024 * 1024;
const MAX_EXTRACTED_BYTES: u64 = 250 * 1024 * 1024;

#[derive(Debug, Deserialize)]
pub struct Catalog {
    schema: String,
    release_version: String,
    packs: Vec<CatalogPack>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CatalogPack {
    pub id: String,
    pub name: String,
    pub os: String,
    pub level: String,
    pub version: String,
    #[serde(default)]
    pub default: bool,
    pub requires_rustinel: String,
    pub status: String,
    #[serde(default)]
    pub rule_count: u32,
    #[serde(default)]
    pub ioc_count: u32,
    pub artifact: String,
    pub sha256: String,
    #[serde(default)]
    engine: Option<CatalogEngine>,
}

#[derive(Debug, Clone, Deserialize)]
struct CatalogEngine {
    sigma_rules_path: String,
    yara_rules_path: String,
    hashes_path: String,
    ips_path: String,
    domains_path: String,
    paths_regex_path: String,
}

#[derive(Debug, Deserialize)]
struct PackManifest {
    name: String,
    id: String,
    description: String,
    os: String,
    level: String,
    pack_schema_version: u32,
    requires_rustinel: String,
    default: bool,
    status: String,
    extends: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RulesState {
    pub pack_id: String,
    pub version: String,
    pub sha256: String,
    pub installed_at: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct InstallOutcome {
    pub pack_id: String,
    pub version: String,
    pub current_dir: PathBuf,
}

impl Catalog {
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let catalog: Self = serde_json::from_slice(bytes).context("parse rules catalog")?;
        catalog.validate()?;
        Ok(catalog)
    }

    pub fn compatible_packs(&self) -> Vec<&CatalogPack> {
        let os = current_os();
        self.packs
            .iter()
            .filter(|pack| pack.os == os)
            .collect::<Vec<_>>()
    }

    pub fn find_pack(&self, pack_id: &str) -> Option<&CatalogPack> {
        self.packs.iter().find(|pack| pack.id == pack_id)
    }

    fn validate(&self) -> Result<()> {
        if self.schema != INDEX_SCHEMA {
            bail!("unsupported catalog schema {}", self.schema);
        }
        if self.release_version.trim().is_empty() {
            bail!("catalog release_version is empty");
        }
        if self.packs.is_empty() {
            bail!("catalog has no packs");
        }
        for pack in &self.packs {
            validate_catalog_pack(pack)?;
        }
        Ok(())
    }
}

pub fn run_cli(command: crate::cli::RulesAction, config_path: Option<PathBuf>) -> Result<()> {
    match command {
        crate::cli::RulesAction::List {
            catalog_url,
            rules_dir,
        } => {
            let catalog_url = parse_release_url(&catalog_url)?;
            let catalog = fetch_catalog(&catalog_url)?;
            let rules_dir = resolve_rules_dir(config_path, rules_dir)?;
            print_pack_list(&catalog, &rules_dir);
            Ok(())
        }
        crate::cli::RulesAction::Install {
            pack,
            catalog_url,
            rules_dir,
        } => {
            let catalog_url = parse_release_url(&catalog_url)?;
            let catalog = fetch_catalog(&catalog_url)?;
            let selected = catalog
                .find_pack(&pack)
                .with_context(|| format!("pack {pack} was not found in the catalog"))?;
            validate_pack_installable(selected)?;
            let artifact_url = resolve_artifact_url(&catalog_url, selected)?;
            validate_release_url(&artifact_url)?;
            let archive = fetch_url_bytes(&artifact_url, MAX_ARTIFACT_BYTES)
                .with_context(|| format!("download {}", selected.artifact))?;
            let rules_dir = resolve_rules_dir(config_path, rules_dir)?;
            let outcome = install_pack_archive_bytes(&catalog, &pack, &rules_dir, &archive)?;
            println!(
                "Installed {} {} into {}",
                outcome.pack_id,
                outcome.version,
                outcome.current_dir.display()
            );
            Ok(())
        }
    }
}

pub fn install_pack_archive_bytes(
    catalog: &Catalog,
    pack_id: &str,
    rules_dir: &Path,
    archive: &[u8],
) -> Result<InstallOutcome> {
    if archive.len() as u64 > MAX_ARTIFACT_BYTES {
        bail!("artifact exceeds maximum download size");
    }

    let pack = catalog
        .find_pack(pack_id)
        .with_context(|| format!("pack {pack_id} was not found in the catalog"))?
        .clone();
    validate_pack_installable(&pack)?;
    verify_sha256(archive, &pack.sha256)?;

    fs::create_dir_all(rules_dir)
        .with_context(|| format!("create rules directory {}", rules_dir.display()))?;
    let staging_dir = rules_dir.join("staging");
    fs::create_dir_all(&staging_dir)
        .with_context(|| format!("create staging directory {}", staging_dir.display()))?;
    let work_dir = staging_dir.join(format!(
        "install-{}-{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    recreate_dir(&work_dir)?;
    let _cleanup = WorkDirCleanup(work_dir.clone());

    let archive_path = work_dir.join("artifact.zip");
    fs::write(&archive_path, archive)
        .with_context(|| format!("write staged artifact {}", archive_path.display()))?;

    let extracted_dir = work_dir.join("extracted");
    fs::create_dir_all(&extracted_dir)?;
    extract_zip_safely(&archive_path, &extracted_dir)?;
    validate_extracted_pack(&extracted_dir, &pack)?;

    let next_current = work_dir.join("current-next");
    prepare_current_dir(&extracted_dir, &next_current)?;

    let state = RulesState {
        pack_id: pack.id.clone(),
        version: pack.version.clone(),
        sha256: pack.sha256.clone(),
        installed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    };
    let state_next = work_dir.join("state-next.json");
    let state_json = serde_json::to_vec_pretty(&state)?;
    fs::write(&state_next, state_json)?;

    let current_dir = rules_dir.join("current");
    atomic_replace_active(rules_dir, &staging_dir, &next_current, &state_next)?;
    Ok(InstallOutcome {
        pack_id: pack.id,
        version: pack.version,
        current_dir,
    })
}

pub fn download_and_install_pack(
    catalog_url: &Url,
    catalog: &Catalog,
    pack_id: &str,
    rules_dir: &Path,
) -> Result<InstallOutcome> {
    let selected = catalog
        .find_pack(pack_id)
        .with_context(|| format!("pack {pack_id} was not found in the catalog"))?;
    validate_pack_installable(selected)?;
    let artifact_url = resolve_artifact_url(catalog_url, selected)?;
    validate_release_url(&artifact_url)?;
    let archive = fetch_url_bytes(&artifact_url, MAX_ARTIFACT_BYTES)
        .with_context(|| format!("download {}", selected.artifact))?;
    install_pack_archive_bytes(catalog, pack_id, rules_dir, &archive)
}

pub fn read_state(rules_dir: &Path) -> Option<RulesState> {
    let state_path = rules_dir.join("state.json");
    let bytes = fs::read(state_path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn fetch_catalog(catalog_url: &Url) -> Result<Catalog> {
    let bytes = fetch_url_bytes(catalog_url, MAX_CATALOG_BYTES)
        .with_context(|| format!("download catalog {catalog_url}"))?;
    Catalog::from_slice(&bytes)
}

pub fn fetch_url_bytes(url: &Url, max_bytes: u64) -> Result<Vec<u8>> {
    let response = reqwest::blocking::get(url.as_str())?.error_for_status()?;
    if let Some(length) = response.content_length() {
        if length > max_bytes {
            bail!("download is too large: {length} bytes");
        }
    }

    let mut limited = response.take(max_bytes + 1);
    let mut bytes = Vec::new();
    limited.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        bail!("download exceeds maximum size");
    }
    Ok(bytes)
}

fn print_pack_list(catalog: &Catalog, rules_dir: &Path) {
    let active = read_state(rules_dir).map(|state| state.pack_id);
    println!("Available rules packs for {}:", current_os());
    println!(
        "{:<22} {:<10} {:<10} {:>5} {:>5} {:<14} ACTIVE",
        "ID", "VERSION", "LEVEL", "RULES", "IOC", "STATUS"
    );
    for pack in catalog.compatible_packs() {
        let marker = if active.as_deref() == Some(pack.id.as_str()) {
            "*"
        } else {
            ""
        };
        println!(
            "{:<22} {:<10} {:<10} {:>5} {:>5} {:<14} {}",
            pack.id, pack.version, pack.level, pack.rule_count, pack.ioc_count, pack.status, marker
        );
    }
}

fn resolve_rules_dir(
    config_path: Option<PathBuf>,
    override_dir: Option<PathBuf>,
) -> Result<PathBuf> {
    if let Some(path) = override_dir {
        return Ok(path);
    }

    let cfg = AppConfig::from_config_path(config_path).context("load configuration")?;
    Ok(infer_rules_dir(&cfg))
}

fn infer_rules_dir(cfg: &AppConfig) -> PathBuf {
    let sigma = &cfg.scanner.sigma_rules_path;
    if sigma.file_name().and_then(|name| name.to_str()) == Some("sigma") {
        if let Some(parent) = sigma.parent() {
            if parent.file_name().and_then(|name| name.to_str()) == Some("current") {
                if let Some(root) = parent.parent() {
                    return root.to_path_buf();
                }
            }
            return parent.to_path_buf();
        }
    }
    PathBuf::from("rules")
}

fn validate_catalog_pack(pack: &CatalogPack) -> Result<()> {
    if pack.id.trim().is_empty() {
        bail!("catalog pack has empty id");
    }
    if pack.name.trim().is_empty() {
        bail!("catalog pack {} has empty name", pack.id);
    }
    match pack.os.as_str() {
        "windows" | "linux" | "macos" => {}
        _ => bail!("catalog pack {} has unsupported os {}", pack.id, pack.os),
    }
    if pack.artifact.trim().is_empty() {
        bail!("catalog pack {} has empty artifact", pack.id);
    }
    parse_sha256(&pack.sha256)
        .with_context(|| format!("catalog pack {} has invalid sha256", pack.id))?;
    VersionReq::parse(&pack.requires_rustinel)
        .with_context(|| format!("catalog pack {} has invalid requires_rustinel", pack.id))?;
    if let Some(engine) = &pack.engine {
        validate_engine_paths(&pack.id, engine)?;
    }
    Ok(())
}

fn validate_engine_paths(pack_id: &str, engine: &CatalogEngine) -> Result<()> {
    for (value, suffix) in [
        (&engine.sigma_rules_path, "rules/sigma"),
        (&engine.yara_rules_path, "rules/yara"),
        (&engine.hashes_path, "rules/ioc/hashes.txt"),
        (&engine.ips_path, "rules/ioc/ips.txt"),
        (&engine.domains_path, "rules/ioc/domains.txt"),
        (&engine.paths_regex_path, "rules/ioc/paths_regex.txt"),
    ] {
        let path = safe_catalog_path(value)
            .with_context(|| format!("catalog pack {pack_id} has unsafe engine path {value}"))?;
        let normalized = path.to_string_lossy().replace('\\', "/");
        if !normalized.ends_with(suffix) {
            bail!("catalog pack {pack_id} engine path {value} does not end with {suffix}");
        }
    }
    Ok(())
}

fn safe_catalog_path(value: &str) -> Result<PathBuf> {
    if value.is_empty() || value.contains('\\') {
        bail!("unsafe path");
    }
    let path = Path::new(value);
    let mut safe = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => safe.push(value),
            _ => bail!("unsafe path"),
        }
    }
    if safe.as_os_str().is_empty() {
        bail!("unsafe path");
    }
    Ok(safe)
}

pub fn validate_pack_installable(pack: &CatalogPack) -> Result<()> {
    if pack.os != current_os() {
        bail!(
            "pack {} targets {}, but this binary runs on {}",
            pack.id,
            pack.os,
            current_os()
        );
    }

    let req = VersionReq::parse(&pack.requires_rustinel)?;
    let current = Version::parse(env!("CARGO_PKG_VERSION").trim_start_matches('v'))?;
    if !rustinel_version_matches_requirement(&req, &current) {
        bail!(
            "pack {} requires Rustinel {}, but this binary is {}",
            pack.id,
            pack.requires_rustinel,
            current
        );
    }
    Ok(())
}

pub(crate) fn rustinel_version_matches_requirement(req: &VersionReq, current: &Version) -> bool {
    if req.matches(current) {
        return true;
    }

    if current.pre.is_empty() {
        return false;
    }

    let mut release_version = current.clone();
    release_version.pre = Prerelease::EMPTY;
    req.matches(&release_version)
}

fn verify_sha256(bytes: &[u8], expected: &str) -> Result<()> {
    let expected = parse_sha256(expected)?;
    let actual = Sha256::digest(bytes);
    if expected.as_slice() != actual.as_slice() {
        bail!("artifact SHA-256 mismatch");
    }
    Ok(())
}

fn parse_sha256(value: &str) -> Result<Vec<u8>> {
    let bytes = hex::decode(value)?;
    if bytes.len() != 32 {
        bail!("SHA-256 must be 32 bytes");
    }
    Ok(bytes)
}

fn extract_zip_safely(archive_path: &Path, destination: &Path) -> Result<()> {
    let file = fs::File::open(archive_path)
        .with_context(|| format!("open artifact {}", archive_path.display()))?;
    let mut archive = ZipArchive::new(file).context("read artifact zip")?;
    let mut total_size = 0u64;

    for index in 0..archive.len() {
        let mut file = archive.by_index(index)?;
        let relative = safe_zip_path(file.name())?;
        if is_symlink_entry(file.unix_mode()) {
            bail!("zip entry {} is a symlink", file.name());
        }
        total_size = total_size
            .checked_add(file.size())
            .context("zip extracted size overflow")?;
        if total_size > MAX_EXTRACTED_BYTES {
            bail!("zip exceeds maximum extracted size");
        }

        let output_path = destination.join(relative);
        if file.is_dir() {
            fs::create_dir_all(&output_path)?;
            continue;
        }

        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut output = fs::File::create(&output_path)?;
        std::io::copy(&mut file, &mut output)?;
    }
    Ok(())
}

fn safe_zip_path(name: &str) -> Result<PathBuf> {
    if name.is_empty() || name.contains('\\') {
        bail!("unsafe zip entry {}", name);
    }
    let path = Path::new(name);
    let mut safe = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => safe.push(value),
            _ => bail!("unsafe zip entry {}", name),
        }
    }
    if safe.as_os_str().is_empty() {
        bail!("unsafe zip entry {}", name);
    }
    Ok(safe)
}

fn is_symlink_entry(mode: Option<u32>) -> bool {
    mode.map(|mode| mode & 0o170000 == 0o120000)
        .unwrap_or(false)
}

fn validate_extracted_pack(extracted_dir: &Path, pack: &CatalogPack) -> Result<()> {
    let manifest_path = extracted_dir.join("pack.yml");
    let manifest_bytes = fs::read(&manifest_path)
        .with_context(|| format!("read manifest {}", manifest_path.display()))?;
    let manifest: PackManifest =
        serde_yaml::from_slice(&manifest_bytes).context("parse pack manifest")?;
    validate_manifest(&manifest, pack)?;

    for path in [
        extracted_dir.join("rules").join("sigma"),
        extracted_dir.join("rules").join("yara"),
        extracted_dir.join("rules").join("ioc"),
    ] {
        if !path.is_dir() {
            bail!("pack is missing expected directory {}", path.display());
        }
    }

    for file in ["hashes.txt", "ips.txt", "domains.txt", "paths_regex.txt"] {
        let path = extracted_dir.join("rules").join("ioc").join(file);
        if !path.is_file() {
            bail!("pack is missing expected IOC file {}", path.display());
        }
    }
    Ok(())
}

fn validate_manifest(manifest: &PackManifest, pack: &CatalogPack) -> Result<()> {
    if !SUPPORTED_PACK_SCHEMA_VERSIONS.contains(&manifest.pack_schema_version) {
        bail!(
            "unsupported pack manifest schema {}",
            manifest.pack_schema_version
        );
    }
    if manifest.id != pack.id {
        bail!(
            "manifest id {} does not match catalog id {}",
            manifest.id,
            pack.id
        );
    }
    if manifest.os != pack.os {
        bail!(
            "manifest os {} does not match catalog os {}",
            manifest.os,
            pack.os
        );
    }
    if manifest.requires_rustinel != pack.requires_rustinel {
        bail!("manifest requires_rustinel does not match catalog");
    }
    if manifest.name.trim().is_empty()
        || manifest.description.trim().is_empty()
        || manifest.level.trim().is_empty()
        || manifest.status.trim().is_empty()
    {
        bail!("manifest has empty required fields");
    }
    let _ = manifest.default;
    let _ = &manifest.extends;
    Ok(())
}

struct WorkDirCleanup(PathBuf);

impl Drop for WorkDirCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn prepare_current_dir(extracted_dir: &Path, next_current: &Path) -> Result<()> {
    recreate_dir(next_current)?;
    fs::copy(
        extracted_dir.join("pack.yml"),
        next_current.join("pack.yml"),
    )?;
    for dir in ["sigma", "yara", "ioc"] {
        fs::rename(
            extracted_dir.join("rules").join(dir),
            next_current.join(dir),
        )?;
    }
    Ok(())
}

fn atomic_replace_active(
    rules_dir: &Path,
    staging_dir: &Path,
    next_current: &Path,
    next_state: &Path,
) -> Result<()> {
    let current = rules_dir.join("current");
    let state = rules_dir.join("state.json");
    let previous_current = staging_dir.join("previous-current");
    let previous_state = staging_dir.join("previous-state.json");
    let _ = fs::remove_dir_all(&previous_current);
    let _ = fs::remove_file(&previous_state);

    if current.exists() {
        fs::rename(&current, &previous_current)
            .with_context(|| format!("move current rules {}", current.display()))?;
    }
    if state.exists() {
        fs::rename(&state, &previous_state)
            .with_context(|| format!("move current state {}", state.display()))?;
    }

    if let Err(err) = fs::rename(next_current, &current) {
        restore_previous(&current, &state, &previous_current, &previous_state);
        return Err(err).context("activate staged rules");
    }

    if let Err(err) = fs::rename(next_state, &state) {
        let _ = fs::remove_dir_all(&current);
        restore_previous(&current, &state, &previous_current, &previous_state);
        return Err(err).context("activate rules state");
    }

    let _ = fs::remove_dir_all(previous_current);
    let _ = fs::remove_file(previous_state);
    Ok(())
}

fn restore_previous(current: &Path, state: &Path, previous_current: &Path, previous_state: &Path) {
    if previous_current.exists() {
        let _ = fs::rename(previous_current, current);
    }
    if previous_state.exists() {
        let _ = fs::rename(previous_state, state);
    }
}

fn recreate_dir(path: &Path) -> Result<()> {
    if path.exists() {
        fs::remove_dir_all(path)?;
    }
    fs::create_dir_all(path)?;
    Ok(())
}

pub fn parse_release_url(value: &str) -> Result<Url> {
    let url = Url::parse(value).with_context(|| format!("parse URL {value}"))?;
    validate_release_url(&url)?;
    Ok(url)
}

fn validate_release_url(url: &Url) -> Result<()> {
    if url.scheme() != "https" {
        bail!("rules catalog trust model requires HTTPS release URLs");
    }
    if url.host_str() != Some("github.com") {
        bail!("rules catalog trust model requires github.com release URLs");
    }
    if !url.path().contains("/releases/") {
        bail!("rules catalog trust model requires GitHub release assets");
    }
    Ok(())
}

pub fn resolve_artifact_url(catalog_url: &Url, pack: &CatalogPack) -> Result<Url> {
    catalog_url
        .join(&pack.artifact)
        .with_context(|| format!("resolve artifact URL {}", pack.artifact))
}

fn current_os() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    use zip::{write::SimpleFileOptions, ZipWriter};

    #[test]
    fn install_pack_replaces_current_and_writes_state() {
        let temp = tempfile::tempdir().expect("tempdir");
        let archive = pack_zip(current_os(), "demo-pack");
        let catalog = catalog_for("demo-pack", current_os(), &archive);

        let outcome =
            install_pack_archive_bytes(&catalog, "demo-pack", temp.path(), &archive).unwrap();

        assert_eq!(outcome.pack_id, "demo-pack");
        assert!(temp.path().join("current").join("pack.yml").is_file());
        assert!(temp
            .path()
            .join("current")
            .join("sigma")
            .join("demo.yml")
            .is_file());
        let state = read_state(temp.path()).expect("state");
        assert_eq!(state.pack_id, "demo-pack");
    }

    #[test]
    fn install_rejects_wrong_os() {
        let temp = tempfile::tempdir().expect("tempdir");
        let wrong_os = if current_os() == "linux" {
            "windows"
        } else {
            "linux"
        };
        let archive = pack_zip(wrong_os, "wrong-pack");
        let catalog = catalog_for("wrong-pack", wrong_os, &archive);

        let err = install_pack_archive_bytes(&catalog, "wrong-pack", temp.path(), &archive)
            .expect_err("wrong os should fail");

        assert!(err.to_string().contains("targets"));
    }

    #[test]
    fn install_accepts_released_schema_v1_manifest() {
        let temp = tempfile::tempdir().expect("tempdir");
        let archive = pack_zip_with_schema(current_os(), "schema-one-pack", 1);
        let catalog = catalog_for("schema-one-pack", current_os(), &archive);

        let outcome =
            install_pack_archive_bytes(&catalog, "schema-one-pack", temp.path(), &archive)
                .expect("schema v1 should install");

        assert_eq!(outcome.pack_id, "schema-one-pack");
    }

    #[test]
    fn unsafe_zip_entry_is_rejected_before_current_is_replaced() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(temp.path().join("current").join("sigma")).unwrap();
        fs::write(
            temp.path().join("current").join("pack.yml"),
            b"previous: true\n",
        )
        .unwrap();
        let archive = unsafe_pack_zip();
        let catalog = catalog_for("demo-pack", current_os(), &archive);

        let err = install_pack_archive_bytes(&catalog, "demo-pack", temp.path(), &archive)
            .expect_err("unsafe zip should fail");

        assert!(err.to_string().contains("unsafe zip entry"));
        assert_eq!(
            fs::read(temp.path().join("current").join("pack.yml")).unwrap(),
            b"previous: true\n"
        );
    }

    #[test]
    fn catalog_filters_compatible_packs() {
        let archive = pack_zip(current_os(), "demo-pack");
        let mut catalog = catalog_for("demo-pack", current_os(), &archive);
        catalog.packs.push(CatalogPack {
            os: if current_os() == "linux" {
                "windows".to_string()
            } else {
                "linux".to_string()
            },
            id: "other-pack".to_string(),
            name: "Other Pack".to_string(),
            level: "essential".to_string(),
            version: "0.1.0".to_string(),
            default: false,
            requires_rustinel: ">=1.0.0".to_string(),
            status: "test".to_string(),
            rule_count: 1,
            ioc_count: 0,
            artifact: "other.zip".to_string(),
            sha256: sha256_hex(&archive),
            engine: None,
        });

        let packs = catalog.compatible_packs();

        assert_eq!(packs.len(), 1);
        assert_eq!(packs[0].id, "demo-pack");
    }

    #[test]
    fn prerelease_version_satisfies_release_floor_requirement() {
        let req = VersionReq::parse(">=1.0.0").unwrap();
        let current = Version::parse("1.2.0-rc.1").unwrap();

        assert!(rustinel_version_matches_requirement(&req, &current));
    }

    #[test]
    fn prerelease_version_rejects_future_release_requirement() {
        let req = VersionReq::parse(">1.2.0").unwrap();
        let current = Version::parse("1.2.0-rc.1").unwrap();

        assert!(!rustinel_version_matches_requirement(&req, &current));
    }

    fn catalog_for(id: &str, os: &str, archive: &[u8]) -> Catalog {
        Catalog {
            schema: INDEX_SCHEMA.to_string(),
            release_version: "0.1.0".to_string(),
            packs: vec![CatalogPack {
                id: id.to_string(),
                name: "Demo Pack".to_string(),
                os: os.to_string(),
                level: "essential".to_string(),
                version: "0.1.0".to_string(),
                default: true,
                requires_rustinel: ">=1.0.0".to_string(),
                status: "test".to_string(),
                rule_count: 1,
                ioc_count: 4,
                artifact: "demo.zip".to_string(),
                sha256: sha256_hex(archive),
                engine: Some(CatalogEngine {
                    sigma_rules_path: format!("{id}/rules/sigma"),
                    yara_rules_path: format!("{id}/rules/yara"),
                    hashes_path: format!("{id}/rules/ioc/hashes.txt"),
                    ips_path: format!("{id}/rules/ioc/ips.txt"),
                    domains_path: format!("{id}/rules/ioc/domains.txt"),
                    paths_regex_path: format!("{id}/rules/ioc/paths_regex.txt"),
                }),
            }],
        }
    }

    fn pack_zip(os: &str, id: &str) -> Vec<u8> {
        pack_zip_with_schema(os, id, 2)
    }

    fn pack_zip_with_schema(os: &str, id: &str, schema_version: u32) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut zip = ZipWriter::new(&mut cursor);
            let options = SimpleFileOptions::default();
            zip.start_file("pack.yml", options).unwrap();
            zip.write_all(manifest(os, id, schema_version).as_bytes())
                .unwrap();
            zip.start_file("rules/sigma/demo.yml", options).unwrap();
            zip.write_all(b"title: Demo\n").unwrap();
            zip.start_file("rules/yara/demo.yar", options).unwrap();
            zip.write_all(b"rule demo { condition: true }\n").unwrap();
            for file in ["hashes.txt", "ips.txt", "domains.txt", "paths_regex.txt"] {
                zip.start_file(format!("rules/ioc/{file}"), options)
                    .unwrap();
                zip.write_all(b"\n").unwrap();
            }
            zip.finish().unwrap();
        }
        cursor.into_inner()
    }

    fn unsafe_pack_zip() -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut zip = ZipWriter::new(&mut cursor);
            let options = SimpleFileOptions::default();
            zip.start_file("../pack.yml", options).unwrap();
            zip.write_all(b"bad: true\n").unwrap();
            zip.finish().unwrap();
        }
        cursor.into_inner()
    }

    fn manifest(os: &str, id: &str, schema_version: u32) -> String {
        format!(
            r#"name: Demo Pack
id: {id}
description: Demo rules
os: {os}
level: essential
pack_schema_version: {schema_version}
requires_rustinel: ">=1.0.0"
default: true
status: test
extends: []
"#
        )
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }
}
