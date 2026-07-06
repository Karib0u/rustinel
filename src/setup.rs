use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::cli::{ServiceAction, SetupPack};
use crate::config::{ConfigLoadOptions, InstallLayout, InstallPlatform};
use crate::doctor::{self, DiagnosticStatus};
use crate::rules::{self, Catalog, CatalogPack, InstallOutcome};
use crate::service::{ManagedServicePaths, ServiceCommandResult, ServiceStatus};

pub struct SetupOptions {
    pub pack: Option<SetupPack>,
    pub yes: bool,
    pub no_start: bool,
    pub force: bool,
    pub catalog_url: String,
}

pub fn run_cli(options: SetupOptions) -> Result<()> {
    let layout = InstallLayout::managed_current();
    let service_paths = ManagedServicePaths::current();

    println!("Preparing managed setup for Rustinel.");
    create_managed_directories(&layout, &service_paths)?;
    prepare_config(&layout, options.force)?;

    let catalog_url = rules::parse_release_url(&options.catalog_url)?;
    let catalog = rules::fetch_catalog(&catalog_url)?;
    let pack = select_pack(&catalog, options.pack, options.yes)?;
    let rules_outcome =
        install_rules_with_recovery(&catalog_url, &catalog, &layout.rules_dir, pack)?;

    install_binary(&service_paths.binary_path)?;
    install_service(&layout, &service_paths)?;

    let service_status = if options.no_start {
        status_or_unknown()
    } else {
        start_service(&layout, &service_paths)?
    };

    let health_status = run_health_checks(&layout)?;
    print_summary(
        &layout,
        &service_paths,
        rules_outcome.as_ref(),
        service_status,
    );
    print_macos_privacy_warning(layout.platform);

    if health_status == DiagnosticStatus::Fail {
        bail!("setup completed, but health checks failed");
    }

    Ok(())
}

fn create_managed_directories(
    layout: &InstallLayout,
    service_paths: &ManagedServicePaths,
) -> Result<()> {
    for path in managed_directories(layout, service_paths) {
        fs::create_dir_all(&path)
            .with_context(|| format!("create managed directory {}", path.display()))?;
    }
    Ok(())
}

fn managed_directories(
    layout: &InstallLayout,
    service_paths: &ManagedServicePaths,
) -> Vec<PathBuf> {
    let mut dirs = vec![
        layout.rules_dir.clone(),
        layout.logs_dir.clone(),
        layout.alerts_dir.clone(),
        service_paths.working_dir.clone(),
    ];
    if let Some(parent) = layout.config_file.parent() {
        dirs.push(parent.to_path_buf());
    }
    if let Some(parent) = service_paths.binary_path.parent() {
        dirs.push(parent.to_path_buf());
    }
    dirs
}

fn prepare_config(layout: &InstallLayout, force: bool) -> Result<()> {
    if layout.config_file.exists() && !force {
        validate_existing_config(&layout.config_file)?;
        println!(
            "Preserved existing configuration at {}",
            layout.config_file.display()
        );
        return Ok(());
    }

    let contents = managed_config_toml(layout);
    fs::write(&layout.config_file, contents).with_context(|| {
        format!(
            "write managed configuration {}",
            layout.config_file.display()
        )
    })?;
    println!(
        "Wrote managed configuration to {}",
        layout.config_file.display()
    );
    Ok(())
}

fn validate_existing_config(config_file: &Path) -> Result<()> {
    crate::config::AppConfig::from_options(ConfigLoadOptions {
        explicit_config: Some(config_file.to_path_buf()),
        env_config: None,
        managed_config: config_file.to_path_buf(),
        exe_config: None,
        cwd_config: PathBuf::from("config.toml"),
    })
    .with_context(|| {
        format!(
            "existing configuration at {} is not valid enough for setup; rerun with --force to replace it",
            config_file.display()
        )
    })?;
    Ok(())
}

fn managed_config_toml(layout: &InstallLayout) -> String {
    let cfg = layout.managed_config();
    format!(
        "[scanner]\n\
sigma_rules_path = {}\n\
yara_rules_path = {}\n\
\n\
[logging]\n\
directory = {}\n\
\n\
[alerts]\n\
directory = {}\n\
\n\
[ioc]\n\
hashes_path = {}\n\
ips_path = {}\n\
domains_path = {}\n\
paths_regex_path = {}\n",
        toml_string(&cfg.scanner.sigma_rules_path),
        toml_string(&cfg.scanner.yara_rules_path),
        toml_string(&cfg.logging.directory),
        toml_string(&cfg.alerts.directory),
        toml_string(&cfg.ioc.hashes_path),
        toml_string(&cfg.ioc.ips_path),
        toml_string(&cfg.ioc.domains_path),
        toml_string(&cfg.ioc.paths_regex_path),
    )
}

fn toml_string(path: &Path) -> String {
    let value = path.to_string_lossy();
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn select_pack(catalog: &Catalog, requested: Option<SetupPack>, yes: bool) -> Result<CatalogPack> {
    let choice = match requested {
        Some(pack) => pack,
        None if yes || !io::stdin().is_terminal() => SetupPack::Essential,
        None => prompt_pack_choice()?,
    };

    select_pack_by_level(catalog, choice)
}

fn prompt_pack_choice() -> Result<SetupPack> {
    print!("Select rules pack [1] Essential [2] Advanced (default 1): ");
    io::stdout().flush().context("flush setup prompt")?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .context("read setup prompt")?;

    match input.trim().to_ascii_lowercase().as_str() {
        "" | "1" | "essential" | "e" => Ok(SetupPack::Essential),
        "2" | "advanced" | "a" => Ok(SetupPack::Advanced),
        other => bail!("unknown pack selection {other}"),
    }
}

fn select_pack_by_level(catalog: &Catalog, choice: SetupPack) -> Result<CatalogPack> {
    let level = choice.level();
    let mut candidates = catalog
        .compatible_packs()
        .into_iter()
        .filter(|pack| pack.level.eq_ignore_ascii_case(level))
        .collect::<Vec<_>>();
    candidates.sort_by_key(|pack| (!pack.default, pack.id.clone()));
    candidates
        .into_iter()
        .next()
        .cloned()
        .with_context(|| format!("catalog has no compatible {level} pack for this platform"))
}

fn install_rules_with_recovery(
    catalog_url: &url::Url,
    catalog: &Catalog,
    rules_dir: &Path,
    pack: CatalogPack,
) -> Result<Option<InstallOutcome>> {
    match rules::download_and_install_pack(catalog_url, catalog, &pack.id, rules_dir) {
        Ok(outcome) => {
            println!(
                "Installed rules pack {} {} into {}",
                outcome.pack_id,
                outcome.version,
                outcome.current_dir.display()
            );
            Ok(Some(outcome))
        }
        Err(err) if active_rules_are_valid(rules_dir) => {
            println!(
                "Warning: could not install rules pack {}: {err}. Preserving existing active rules.",
                pack.id
            );
            Ok(None)
        }
        Err(err) => Err(err).with_context(|| {
            format!(
                "install rules pack {}; no valid active rules were available to preserve",
                pack.id
            )
        }),
    }
}

fn active_rules_are_valid(rules_dir: &Path) -> bool {
    let current = rules_dir.join("current");
    rules::read_state(rules_dir).is_some()
        && current.join("pack.yml").is_file()
        && current.join("sigma").is_dir()
        && current.join("yara").is_dir()
        && current.join("ioc").is_dir()
        && ["hashes.txt", "ips.txt", "domains.txt", "paths_regex.txt"]
            .into_iter()
            .all(|file| current.join("ioc").join(file).is_file())
}

fn install_binary(binary_path: &Path) -> Result<()> {
    let current_exe = std::env::current_exe().context("locate current executable")?;
    if same_file_best_effort(&current_exe, binary_path) {
        println!("Managed binary already points to {}", binary_path.display());
        return Ok(());
    }

    fs::copy(&current_exe, binary_path).with_context(|| {
        format!(
            "copy executable from {} to {}",
            current_exe.display(),
            binary_path.display()
        )
    })?;
    set_executable_permissions(binary_path)?;
    println!("Installed managed binary to {}", binary_path.display());
    Ok(())
}

fn same_file_best_effort(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

#[cfg(unix)]
fn set_executable_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_executable_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn install_service(layout: &InstallLayout, service_paths: &ManagedServicePaths) -> Result<()> {
    crate::platform::run_service_action(ServiceAction::Install).inspect_err(|err| {
        print_service_install_recovery(layout, service_paths, err);
    })?;
    println!("Registered native service.");
    Ok(())
}

fn start_service(
    layout: &InstallLayout,
    service_paths: &ManagedServicePaths,
) -> Result<ServiceStatus> {
    if let Err(err) = crate::platform::run_service_action(ServiceAction::Start) {
        let status = status_or_unknown();
        print_service_start_recovery(layout, service_paths, status, &err);
        return Err(err);
    }

    let status = status_or_unknown();
    println!("Started native service with status {status}.");
    Ok(status)
}

fn status_or_unknown() -> ServiceStatus {
    match crate::platform::run_service_action(ServiceAction::Status) {
        Ok(ServiceCommandResult::Status(status)) => status,
        _ => ServiceStatus::Unknown,
    }
}

fn run_health_checks(layout: &InstallLayout) -> Result<DiagnosticStatus> {
    let report = doctor::inspect(Some(layout.config_file.clone()));
    println!("Health checks: {}", report.status);
    for result in &report.results {
        println!("  [{}] {}: {}", result.status, result.id, result.message);
        if let Some(detail) = &result.detail {
            println!("      {detail}");
        }
    }
    Ok(report.status)
}

fn print_service_install_recovery(
    layout: &InstallLayout,
    service_paths: &ManagedServicePaths,
    err: &anyhow::Error,
) {
    println!("Service install failed: {err}");
    println!("Configuration and rules were left in place.");
    println!(
        "Recovery: {}",
        recovery_command(
            layout.platform,
            &service_paths.binary_path,
            "service install"
        )
    );
}

fn print_service_start_recovery(
    layout: &InstallLayout,
    service_paths: &ManagedServicePaths,
    status: ServiceStatus,
    err: &anyhow::Error,
) {
    println!("Service start failed: {err}");
    println!("Service status: {status}");
    println!(
        "Diagnostics: {}",
        recovery_command(layout.platform, &service_paths.binary_path, "doctor")
    );
    println!(
        "Restart: {}",
        recovery_command(
            layout.platform,
            &service_paths.binary_path,
            "service restart"
        )
    );
}

fn recovery_command(platform: InstallPlatform, binary: &Path, args: &str) -> String {
    match platform {
        InstallPlatform::Windows => format!("\"{}\" {args}", binary.display()),
        InstallPlatform::Linux | InstallPlatform::Macos => {
            format!("sudo \"{}\" {args}", binary.display())
        }
    }
}

fn print_summary(
    layout: &InstallLayout,
    service_paths: &ManagedServicePaths,
    rules_outcome: Option<&InstallOutcome>,
    service_status: ServiceStatus,
) {
    println!("Setup summary:");
    println!("  configuration: {}", layout.config_file.display());
    println!("  rules: {}", layout.rules_dir.display());
    if let Some(outcome) = rules_outcome {
        println!("  active pack: {} {}", outcome.pack_id, outcome.version);
    } else {
        println!("  active pack: existing");
    }
    println!("  logs: {}", layout.logs_dir.display());
    println!("  alerts: {}", layout.alerts_dir.display());
    println!("  service binary: {}", service_paths.binary_path.display());
    println!("  service status: {service_status}");
}

fn print_macos_privacy_warning(platform: InstallPlatform) {
    if platform == InstallPlatform::Macos {
        println!(
            "Warning: macOS may still require Full Disk Access and Endpoint Security approval for Rustinel.app."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_config_contains_managed_paths() {
        let layout = InstallLayout::managed(InstallPlatform::Linux);
        let contents = managed_config_toml(&layout);

        assert!(contents.contains("sigma_rules_path = \"/var/lib/rustinel/rules/current/sigma\""));
        assert!(contents.contains("directory = \"/var/log/rustinel\""));
        assert!(
            contents.contains("hashes_path = \"/var/lib/rustinel/rules/current/ioc/hashes.txt\"")
        );
    }

    #[test]
    fn toml_string_escapes_windows_paths() {
        let value = toml_string(Path::new(r#"C:\ProgramData\Rustinel\config "main".toml"#));

        assert_eq!(
            value,
            r#""C:\\ProgramData\\Rustinel\\config \"main\".toml""#
        );
    }

    #[test]
    fn active_rules_require_state_and_expected_files() {
        let temp = tempfile::tempdir().expect("tempdir");
        let current = temp.path().join("current");
        fs::create_dir_all(current.join("sigma")).expect("sigma");
        fs::create_dir_all(current.join("yara")).expect("yara");
        fs::create_dir_all(current.join("ioc")).expect("ioc");
        fs::write(current.join("pack.yml"), "name: test\n").expect("pack");
        for file in ["hashes.txt", "ips.txt", "domains.txt", "paths_regex.txt"] {
            fs::write(current.join("ioc").join(file), "\n").expect("ioc file");
        }
        fs::write(
            temp.path().join("state.json"),
            r#"{"pack_id":"linux-essential","version":"1","sha256":"00","installed_at":"now"}"#,
        )
        .expect("state");

        assert!(active_rules_are_valid(temp.path()));
    }
}
