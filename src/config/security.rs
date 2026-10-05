//! Explicit integration access, anchored in administrator-owned filesystem metadata.

use std::path::{Path, PathBuf};

use config::ConfigError;
use serde::{Deserialize, Serialize};

use crate::utils::trust::RuleTrust;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct SecurityConfig {
    pub integration_group: Option<String>,
    pub integration_rules_directory: Option<PathBuf>,
    #[serde(skip)]
    pub(crate) integration_gid: Option<u32>,
    #[serde(skip)]
    pub(crate) rule_trust: Option<RuleTrust>,
}

impl SecurityConfig {
    pub(crate) fn log_group(&self) -> Option<u32> {
        self.integration_gid
    }

    pub(crate) fn rules(&self) -> Option<&RuleTrust> {
        self.rule_trust.as_ref()
    }
}

fn error(err: impl std::fmt::Display) -> ConfigError {
    ConfigError::Message(err.to_string())
}

pub(super) fn load_config(
    path: Option<&Path>,
) -> Result<(config::Config, SecurityConfig), ConfigError> {
    let Some(path) = path else {
        return Ok((config::Config::default(), SecurityConfig::default()));
    };
    let ordinary_trust = crate::utils::trust::verify_input(path);
    // Before parsing an otherwise refused file, require a root-controlled file
    // and parents. Only its group-write bit can be delegated by its contents.
    if let Err(ref ordinary_error) = ordinary_trust {
        verify_integration_config(path).map_err(|err| {
            error(format!(
                "{ordinary_error:#}; integration access refused: {err:#}"
            ))
        })?;
    }
    let source = config::Config::builder()
        .add_source(config::File::from(path).required(true))
        .build()
        .map_err(super::redact_config_error)?;
    let mut security = match source.get::<SecurityConfig>("security") {
        Ok(security) => security,
        Err(ConfigError::NotFound(_)) => SecurityConfig::default(),
        Err(err) => return Err(super::redact_config_error(err)),
    };
    if let Some(name) = &security.integration_group {
        let gid = verify_integration_config(path).map_err(error)?;
        if resolve_group(name).map_err(error)? != gid {
            return Err(error(
                "security.integration_group must match the config file's filesystem group",
            ));
        }
        security.integration_gid = Some(gid);
        if let Some(directory) = &security.integration_rules_directory {
            security.rule_trust = Some(RuleTrust::new(directory, gid).map_err(error)?);
        }
    } else {
        if security.integration_rules_directory.is_some() {
            return Err(error(
                "security.integration_rules_directory requires integration_group",
            ));
        }
        ordinary_trust.map_err(|err| error(format!("{err:#}")))?;
    }
    Ok((source, security))
}

#[cfg(unix)]
fn verify_integration_config(path: &Path) -> anyhow::Result<u32> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.nlink() == 1
            && metadata.mode() & 0o007 == 0,
        "integration config must be a root-owned regular file, without links or access for others"
    );
    crate::utils::trust::verify_root_controlled_parents(path)?;
    Ok(metadata.gid())
}

#[cfg(not(unix))]
fn verify_integration_config(_path: &Path) -> anyhow::Result<u32> {
    anyhow::bail!("security.integration_group is supported only on Unix")
}

#[cfg(unix)]
fn resolve_group(name: &str) -> anyhow::Result<u32> {
    let name = std::ffi::CString::new(name)?;
    anyhow::ensure!(
        !name.as_bytes().is_empty(),
        "integration group must not be empty"
    );
    let mut buffer = vec![0 as libc::c_char; 64 * 1024];
    let mut group: libc::group = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    let status = unsafe {
        libc::getgrnam_r(
            name.as_ptr(),
            &mut group,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        )
    };
    anyhow::ensure!(
        status == 0 && !result.is_null(),
        "integration group does not exist or could not be resolved"
    );
    Ok(group.gr_gid)
}

#[cfg(not(unix))]
fn resolve_group(_name: &str) -> anyhow::Result<u32> {
    anyhow::bail!("security.integration_group is supported only on Unix")
}

#[cfg(all(test, unix))]
pub(crate) mod test_support {
    use std::ffi::{CStr, CString};
    use std::fs;
    use std::os::unix::{fs::PermissionsExt, process::CommandExt};
    use std::path::Path;
    use std::process::Command;

    pub(crate) struct Fixture {
        pub root: tempfile::TempDir,
        pub gid: u32,
        pub group: String,
        uid: u32,
    }

    impl Fixture {
        pub fn new() -> Self {
            assert_eq!(unsafe { libc::geteuid() }, 0, "run this test as root");
            let name = CString::new("nobody").unwrap();
            let (uid, gid, group) = unsafe {
                let account = libc::getpwnam(name.as_ptr());
                assert!(!account.is_null());
                let (uid, gid) = ((*account).pw_uid, (*account).pw_gid);
                let group = libc::getgrgid(gid);
                assert!(!group.is_null());
                (
                    uid,
                    gid,
                    CStr::from_ptr((*group).gr_name)
                        .to_str()
                        .unwrap()
                        .to_owned(),
                )
            };
            let root = tempfile::Builder::new()
                .prefix("rustinel-integration-")
                .tempdir_in("/tmp")
                .unwrap();
            let fixture = Self {
                root,
                gid,
                group,
                uid,
            };
            fixture.permissions(fixture.root.path(), 0o750);
            fixture
        }

        pub fn permissions(&self, path: &Path, mode: u32) {
            let name = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
            assert_eq!(unsafe { libc::chown(name.as_ptr(), 0, self.gid) }, 0);
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }

        pub fn config(&self, extra: &str) -> super::super::AppConfig {
            let path = self.root.path().join("config.toml");
            fs::write(&path, self.body(extra)).unwrap();
            self.permissions(&path, 0o660);
            self.load().unwrap()
        }

        pub fn body(&self, extra: &str) -> String {
            format!("[security]\nintegration_group = {:?}\n{extra}", self.group)
        }

        pub fn load(&self) -> Result<super::super::AppConfig, config::ConfigError> {
            super::super::AppConfig::from_options_with_environment(
                super::super::ConfigLoadOptions {
                    explicit_config: Some(self.root.path().join("config.toml")),
                    env_config: None,
                    managed_config: self.root.path().join("missing"),
                    exe_config: None,
                    cwd_config: self.root.path().join("missing"),
                },
                Some(config::Map::new()),
            )
        }

        pub fn wrapper(&self, script: &str) -> Command {
            let mut command = Command::new("/bin/sh");
            command
                .args(["-c", script])
                .env("FIXTURE", self.root.path());
            let (uid, gid) = (self.uid, self.gid);
            unsafe {
                command.pre_exec(move || {
                    if libc::setgroups(0, std::ptr::null()) != 0
                        || libc::setgid(gid) != 0
                        || libc::setuid(uid) != 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            command
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::test_support::Fixture;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[test]
    #[ignore = "requires root; exercised by Unix CI"]
    fn integration_group_config_allows_in_place_updates_only() {
        let fixture = Fixture::new();
        let cfg = fixture.config("");
        assert_eq!(cfg.security.log_group(), Some(fixture.gid));
        assert!(cfg.security.rules().is_none());
        let path = fixture.root.path().join("config.toml");
        let before = fs::metadata(&path).unwrap().ino();
        let output = fixture
            .wrapper("printf '%s' \"$CONFIG_BODY\" > \"$FIXTURE/config.toml\"")
            .env("CONFIG_BODY", fixture.body("[response]\nenabled = true\n"))
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(fixture.load().unwrap().response.enabled);
        assert_eq!(fs::metadata(&path).unwrap().ino(), before);
        assert!(!fixture
            .wrapper("rm \"$FIXTURE/config.toml\"")
            .output()
            .unwrap()
            .status
            .success());
        assert!(!fixture
            .wrapper("chmod 666 \"$FIXTURE/config.toml\"")
            .output()
            .unwrap()
            .status
            .success());

        fs::write(
            &path,
            "[security]\nintegration_group = 'nonexistent-rustinel-group'\n",
        )
        .unwrap();
        assert!(fixture.load().is_err());
        fs::write(&path, "[security]\nintegration_group = 'root'\n").unwrap();
        assert!(fixture.load().is_err());
        fs::write(&path, "").unwrap();
        assert!(
            fixture.load().is_err(),
            "shared group write requires opt-in"
        );
        fixture.config("");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(fixture.load().is_err());
        fixture.config("");
        fs::set_permissions(fixture.root.path(), fs::Permissions::from_mode(0o770)).unwrap();
        assert!(
            fixture.load().is_err(),
            "config parent must not be writable"
        );
        fixture.permissions(fixture.root.path(), 0o750);
        fs::hard_link(&path, fixture.root.path().join("hard-link")).unwrap();
        assert!(fixture.load().is_err());
        fs::remove_file(fixture.root.path().join("hard-link")).unwrap();
        fs::rename(&path, fixture.root.path().join("target")).unwrap();
        std::os::unix::fs::symlink(fixture.root.path().join("target"), &path).unwrap();
        assert!(fixture.load().is_err());
    }

    #[test]
    #[ignore = "requires root; exercised by Unix CI"]
    fn integration_group_rules_are_scoped_and_accept_wrapper_owned_files() {
        let fixture = Fixture::new();
        let root = fixture.root.path().join("rules");
        fs::create_dir(&root).unwrap();
        fixture.permissions(&root, 0o2770);
        let cfg = fixture.config(&format!("integration_rules_directory = {:?}\n", root));
        let output = fixture.wrapper("mkdir \"$FIXTURE/rules/current\" && printf '%s\\n' 'rule example { condition: true }' > \"$FIXTURE/rules/current/test.yar\"").output().unwrap();
        assert!(output.status.success(), "{output:?}");
        let rules = root.join("current");
        let file = rules.join("test.yar");
        assert_ne!(fs::metadata(&file).unwrap().uid(), 0);
        assert!(crate::scanner::Scanner::new(&rules).is_err());
        crate::scanner::Scanner::new_with_trust(&rules, cfg.security.rules()).unwrap();
        let output = fixture.wrapper("printf '%s\\n' 'rule updated { condition: false }' > \"$FIXTURE/rules/current/next.yar\" && mv \"$FIXTURE/rules/current/next.yar\" \"$FIXTURE/rules/current/test.yar\"").output().unwrap();
        assert!(output.status.success(), "{output:?}");
        crate::scanner::Scanner::new_with_trust(&rules, cfg.security.rules()).unwrap();
        // The rules exception cannot be reused for configuration or outside inputs.
        assert!(crate::utils::trust::verify_input(&file).is_err());
        let outside = fixture.root.path().join("outside.yar");
        fs::write(&outside, "rule outside { condition: true }").unwrap();
        fixture.permissions(&outside, 0o660);
        assert!(crate::utils::trust::verify_rule_input(&outside, cfg.security.rules()).is_err());
        std::os::unix::fs::symlink(&outside, rules.join("link.yar")).unwrap();
        assert!(crate::scanner::Scanner::new_with_trust(&rules, cfg.security.rules()).is_err());
        fs::remove_file(rules.join("link.yar")).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(crate::scanner::Scanner::new_with_trust(&rules, cfg.security.rules()).is_err());
        fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
        fs::hard_link(&file, rules.join("hard-link.yar")).unwrap();
        assert!(crate::scanner::Scanner::new_with_trust(&rules, cfg.security.rules()).is_err());
    }
    #[tokio::test]
    #[ignore = "requires root; exercised by Unix CI"]
    async fn integration_group_hot_reload_keeps_the_startup_policy() {
        use crate::models::MatchDebugLevel;
        use crate::reload::{spawn_reload_worker, ReloadTarget};
        use crate::{
            engine::{DetectorStore, Engine},
            ioc::IocEngine,
            scanner::Scanner,
        };
        use std::sync::Arc;
        let fixture = Fixture::new();
        let rules = fixture.root.path().join("rules");
        fs::create_dir(&rules).unwrap();
        fixture.permissions(&rules, 0o2770);
        let extra = format!("integration_rules_directory = {rules:?}\n");
        let mut cfg = fixture.config(&extra);
        cfg.scanner.sigma_rules_path = rules.clone();
        cfg.scanner.yara_rules_path = rules.clone();
        cfg.ioc.hashes_path = rules.join("hashes.txt");
        cfg.ioc.ips_path = rules.join("ips.txt");
        cfg.ioc.domains_path = rules.join("domains.txt");
        cfg.ioc.paths_regex_path = rules.join("paths.txt");
        let output = fixture.wrapper("printf '%s' \"$SIGMA_RULE\" > \"$FIXTURE/rules/test.yml\"; printf '%s' 'rule test { condition: true }' > \"$FIXTURE/rules/test.yar\"; printf '%s' 'example.test' > \"$FIXTURE/rules/domains.txt\"; printf '%s' \"$CONFIG_BODY\" > \"$FIXTURE/config.toml\"")
            .env("SIGMA_RULE", "title: Integration\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    Image|exists: true\n  condition: selection\n")
            .env("CONFIG_BODY", fixture.body(&format!("{extra}[response]\nenabled = true\n")))
            .output().unwrap();
        assert!(output.status.success(), "{output:?}");
        let store = DetectorStore::new(
            Arc::new(Engine::new()),
            Arc::new(Scanner::empty()),
            Arc::new(IocEngine::disabled()),
        );
        let response = Arc::new(arc_swap::ArcSwap::from_pointee(cfg.response.clone()));
        for allowed in [true, false] {
            let previous_sigma = store.sigma();
            let previous_yara = store.yara();
            let previous_ioc = store.ioc();
            if !allowed {
                for path in [
                    rules.join("test.yml"),
                    rules.join("test.yar"),
                    rules.join("domains.txt"),
                    fixture.root.path().join("config.toml"),
                ] {
                    fs::set_permissions(path, fs::Permissions::from_mode(0o666)).unwrap();
                }
            }
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            let worker = spawn_reload_worker(
                Arc::clone(&store),
                cfg.scanner.clone(),
                cfg.ioc.clone(),
                cfg.reload.clone(),
                MatchDebugLevel::Off,
                cfg.security.rules().cloned(),
                Some(fixture.root.path().join("config.toml")),
                Arc::clone(&response),
                None,
                rx,
            );
            for target in [
                ReloadTarget::Sigma,
                ReloadTarget::Yara,
                ReloadTarget::Ioc,
                ReloadTarget::Config,
            ] {
                tx.send(target).unwrap();
            }
            drop(tx);
            worker.await.unwrap();
            assert_eq!(!Arc::ptr_eq(&previous_sigma, &store.sigma()), allowed);
            assert_eq!(!Arc::ptr_eq(&previous_yara, &store.yara()), allowed);
            assert_eq!(!Arc::ptr_eq(&previous_ioc, &store.ioc()), allowed);
            assert!(response.load().enabled);
        }
    }
}
