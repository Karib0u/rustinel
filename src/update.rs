//! Operator-triggered binary updates from published release archives.
use anyhow::{bail, Context, Result};
use reqwest::blocking::Client;
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::Duration;

const RELEASE_URL: &str = "https://api.github.com/repos/Karib0u/rustinel/releases/latest";
const MANUAL_UPDATE: &str = "Could not replace Rustinel. Check installation permissions. If a running service blocks replacement, run `rustinel service stop`, then `rustinel update`, then `rustinel service start`.";

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

impl Release {
    fn asset(&self, name: &str) -> Result<&str> {
        self.assets
            .iter()
            .find(|asset| asset.name == name)
            .map(|asset| asset.browser_download_url.as_str())
            .with_context(|| format!("Latest release has no supported artifact: {name}"))
    }
}

fn package(version: &Version, os: &str, arch: &str) -> Result<(String, String)> {
    let target = match (os, arch) {
        ("linux", "x86_64") => "x86_64-unknown-linux-musl",
        ("linux", "aarch64") => "aarch64-unknown-linux-musl",
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        _ => bail!("Unsupported update platform: {os}/{arch}"),
    };
    let stem = format!("rustinel-{version}-{target}");
    let (extension, binary) = match os {
        "windows" => ("zip", "rustinel.exe"),
        "macos" => ("tar.gz", "Rustinel.app/Contents/MacOS/rustinel"),
        _ => ("tar.gz", "rustinel"),
    };
    Ok((format!("{stem}.{extension}"), format!("{stem}/{binary}")))
}

fn verify(archive: &mut File, checksums: &str, name: &str) -> Result<()> {
    let hashes: Vec<_> = checksums
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let hash = fields.next()?;
            let filename = fields.next()?.trim_start_matches('*');
            (filename == name && fields.next().is_none()).then_some(hash)
        })
        .collect();
    anyhow::ensure!(
        hashes.len() == 1,
        "Missing or duplicate SHA256 checksum for {name}"
    );
    let expected = hex::decode(hashes[0]).context("Invalid SHA256 checksum")?;
    anyhow::ensure!(expected.len() == 32, "Invalid SHA256 checksum length");
    archive.rewind()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let count = archive.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    anyhow::ensure!(
        hasher.finalize().as_slice() == expected,
        "SHA256 mismatch for {name}; binary was not replaced"
    );
    archive.rewind()?;
    Ok(())
}

fn extract(archive: &mut File, name: &str, binary: &str, output: &mut File) -> Result<()> {
    if name.ends_with(".zip") {
        let mut zip = zip::ZipArchive::new(archive)?;
        let mut entry = zip
            .by_name(binary)
            .context("Release archive is missing its binary")?;
        anyhow::ensure!(
            entry.is_file() && !entry.is_symlink(),
            "Release binary is not a regular file"
        );
        std::io::copy(&mut entry, output)?;
    } else {
        let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(archive));
        let mut found = false;
        for entry in tar.entries()? {
            let mut entry = entry?;
            if entry.path()?.as_ref() == Path::new(binary) {
                anyhow::ensure!(
                    !found && entry.header().entry_type().is_file(),
                    "Invalid release binary entry"
                );
                std::io::copy(&mut entry, output)?;
                found = true;
            }
        }
        anyhow::ensure!(found, "Release archive is missing its binary");
    }
    anyhow::ensure!(output.metadata()?.len() > 0, "Release binary is empty");
    output.flush()?;
    output.sync_all()?;
    Ok(())
}

fn update(
    release: Release,
    current: &Version,
    os: &str,
    arch: &str,
    mut download: impl FnMut(&str, &mut File) -> Result<()>,
    install: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    let latest = Version::parse(release.tag_name.trim_start_matches('v'))
        .context("Invalid release version")?;
    println!("Current version: {current}\nLatest version:  {latest}");
    if latest <= *current {
        println!("Rustinel is already up to date.");
        return Ok(());
    }
    let (name, binary) = package(&latest, os, arch)?;
    let archive_url = release.asset(&name)?;
    let checksum_url = release.asset(&format!("rustinel-{latest}-checksums-sha256.txt"))?;
    let mut checksum_file = tempfile::tempfile()?;
    download(checksum_url, &mut checksum_file)?;
    checksum_file.seek(SeekFrom::Start(0))?;
    let mut checksums = String::new();
    checksum_file
        .take(1024 * 1024)
        .read_to_string(&mut checksums)?;
    println!("\nDownloading {name}...");
    let mut archive = tempfile::NamedTempFile::new()?;
    download(archive_url, archive.as_file_mut())?;
    verify(archive.as_file_mut(), &checksums, &name)?;
    println!("SHA256 verified");
    let mut executable = tempfile::NamedTempFile::new()?;
    extract(
        archive.as_file_mut(),
        &name,
        &binary,
        executable.as_file_mut(),
    )?;
    #[cfg(target_os = "macos")]
    let bundle = if os == "macos" {
        Some(stage_macos_bundle(archive.path(), &binary)?)
    } else {
        None
    };
    #[cfg(target_os = "macos")]
    let source = bundle
        .as_ref()
        .map(|(_, path)| path.as_path())
        .unwrap_or(executable.path());
    #[cfg(not(target_os = "macos"))]
    let source = executable.path();
    install(source).context(MANUAL_UPDATE)?;
    println!("Updated Rustinel to {latest}\n\nRestart Rustinel to use the new version. For a managed service, run `rustinel service restart`.");
    Ok(())
}

// Use the platform archive tool to preserve the signed bundle's extended
// attributes, including its stapled notarization ticket.
#[cfg(target_os = "macos")]
fn stage_macos_bundle(
    archive: &Path,
    binary: &str,
) -> Result<(tempfile::TempDir, std::path::PathBuf)> {
    let bundle = binary
        .strip_suffix("/Contents/MacOS/rustinel")
        .context("Invalid app bundle path")?;
    let staging = tempfile::tempdir()?;
    let status = std::process::Command::new("/usr/bin/tar")
        .arg("-xzf")
        .arg(archive)
        .arg("-C")
        .arg(staging.path())
        .arg(bundle)
        .status()?;
    anyhow::ensure!(status.success(), "Could not extract signed app bundle");
    let path = staging.path().join(bundle);
    let status = std::process::Command::new("/usr/bin/codesign")
        .args(["--verify", "--deep", "--strict"])
        .arg(&path)
        .status()?;
    anyhow::ensure!(
        status.success(),
        "Release app bundle signature verification failed"
    );
    Ok((staging, path))
}

#[cfg(target_os = "macos")]
fn install_macos_bundle(source: &Path) -> Result<()> {
    let executable = std::env::current_exe()?.canonicalize()?;
    let bundle = executable.parent().and_then(Path::parent).and_then(Path::parent)
        .filter(|path| path.extension().is_some_and(|ext| ext == "app"))
        .context("The macOS updater requires an installed Rustinel.app bundle; install the latest release bundle manually")?;
    replace_macos_bundle(source, bundle)
}

#[cfg(target_os = "macos")]
fn replace_macos_bundle(source: &Path, bundle: &Path) -> Result<()> {
    let staging = tempfile::tempdir_in(bundle.parent().context("App bundle has no parent")?)?;
    let replacement = staging.path().join("Rustinel.app");
    let status = std::process::Command::new("/usr/bin/ditto")
        .arg(source)
        .arg(&replacement)
        .status()?;
    anyhow::ensure!(status.success(), "Could not stage replacement app bundle");
    let previous = staging.path().join("previous.app");
    std::fs::rename(bundle, &previous)?;
    if let Err(error) = std::fs::rename(&replacement, bundle) {
        if let Err(restore) = std::fs::rename(&previous, bundle) {
            let recovery = staging.keep();
            bail!("Update failed: {error}; restoring the app failed: {restore}. Original app retained at {}", recovery.join("previous.app").display());
        }
        return Err(error.into());
    }
    Ok(())
}

pub fn run_cli() -> Result<()> {
    let client = Client::builder()
        .user_agent(concat!("rustinel/", env!("CARGO_PKG_VERSION")))
        .https_only(true)
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(600))
        .build()?;
    let release = serde_json::from_reader(client.get(RELEASE_URL).send()?.error_for_status()?)
        .context("Could not read latest GitHub Release")?;
    update(
        release,
        &Version::parse(env!("CARGO_PKG_VERSION"))?,
        std::env::consts::OS,
        std::env::consts::ARCH,
        |url, file| {
            client.get(url).send()?.error_for_status()?.copy_to(file)?;
            Ok(())
        },
        |path| {
            #[cfg(target_os = "macos")]
            if path.is_dir() {
                return install_macos_bundle(path);
            }
            self_replace::self_replace(path)?;
            Ok(())
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn release() -> Release {
        let (name, _) = package(&Version::new(9, 0, 0), "linux", "x86_64").unwrap();
        Release {
            tag_name: "v9.0.0".into(),
            assets: vec![
                Asset {
                    name,
                    browser_download_url: "archive".into(),
                },
                Asset {
                    name: "rustinel-9.0.0-checksums-sha256.txt".into(),
                    browser_download_url: "checksum".into(),
                },
            ],
        }
    }

    #[test]
    fn cli_and_current_version() {
        assert!(matches!(
            crate::cli::Cli::try_parse_from(["rustinel", "update"])
                .unwrap()
                .command,
            Some(crate::cli::Commands::Update)
        ));
        for current in [Version::new(9, 0, 0), Version::new(10, 0, 0)] {
            update(
                release(),
                &current,
                "linux",
                "x86_64",
                |_, _| panic!("must not download"),
                |_| panic!("must not install"),
            )
            .unwrap();
        }
    }

    #[test]
    fn platform_artifacts() {
        for (os, arch, target) in [
            ("linux", "x86_64", "x86_64-unknown-linux-musl"),
            ("linux", "aarch64", "aarch64-unknown-linux-musl"),
            ("windows", "x86_64", "x86_64-pc-windows-msvc"),
            ("macos", "aarch64", "aarch64-apple-darwin"),
            ("macos", "x86_64", "x86_64-apple-darwin"),
        ] {
            let (name, binary) = package(&Version::new(9, 0, 0), os, arch).unwrap();
            assert!(name.contains(target));
            assert!(binary.starts_with(&format!("rustinel-9.0.0-{target}/")));
        }
        assert!(package(&Version::new(9, 0, 0), "windows", "aarch64").is_err());
        let mut missing = release();
        missing.assets.clear();
        assert!(update(
            missing,
            &Version::new(1, 0, 0),
            "linux",
            "x86_64",
            |_, _| panic!(),
            |_| panic!()
        )
        .is_err());
    }

    #[test]
    fn verified_update_and_checksum_failure() {
        let (name, binary) = package(&Version::new(9, 0, 0), "linux", "x86_64").unwrap();
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        let mut header = tar::Header::new_gnu();
        header.set_size(3);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, binary, &b"new"[..])
            .unwrap();
        let archive = builder.into_inner().unwrap().finish().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let installed = directory.path().join("rustinel");
        let config = directory.path().join("config.toml");
        std::fs::write(&config, "preserved").unwrap();
        for (valid, blocked) in [(false, false), (true, false), (true, true)] {
            std::fs::write(&installed, "old").unwrap();
            let hash = if valid {
                hex::encode(Sha256::digest(&archive))
            } else {
                "00".repeat(32)
            };
            let result = update(
                release(),
                &Version::new(1, 0, 0),
                "linux",
                "x86_64",
                |url, file| {
                    if url == "archive" {
                        file.write_all(&archive)?;
                    } else {
                        writeln!(file, "{hash}  {name}")?;
                    }
                    Ok(())
                },
                |path| {
                    if blocked {
                        bail!("file is in use");
                    }
                    std::fs::copy(path, &installed)?;
                    Ok(())
                },
            );
            assert_eq!(result.is_ok(), valid && !blocked);
            if blocked {
                let message = result.unwrap_err().to_string();
                assert!(message.contains("rustinel service stop"));
                assert!(message.contains("rustinel update"));
                assert!(message.contains("rustinel service start"));
            }
            assert_eq!(
                std::fs::read_to_string(&installed).unwrap(),
                if valid && !blocked { "new" } else { "old" }
            );
            assert_eq!(std::fs::read_to_string(&config).unwrap(), "preserved");
        }
    }

    #[test]
    fn replaces_running_executable_in_child_process() {
        const CHILD: &str = "RUSTINEL_UPDATE_TEST_REPLACEMENT";
        if let Some(replacement) = std::env::var_os(CHILD) {
            self_replace::self_replace(replacement).unwrap();
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join(if cfg!(windows) {
            "updater.exe"
        } else {
            "updater"
        });
        let replacement = directory.path().join("replacement");
        std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        std::fs::write(&replacement, b"replacement binary").unwrap();
        let status = std::process::Command::new(&executable)
            .args([
                "--exact",
                "update::tests::replaces_running_executable_in_child_process",
            ])
            .env(CHILD, &replacement)
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(std::fs::read(&executable).unwrap(), b"replacement binary");
    }

    #[test]
    fn malformed_checksums_and_missing_binary() {
        let mut archive = tempfile::tempfile().unwrap();
        archive.write_all(b"data").unwrap();
        for checksum in [
            "",
            "bad  artifact",
            "00  artifact",
            "00  artifact\n00  artifact",
        ] {
            assert!(verify(&mut archive, checksum, "artifact").is_err());
        }
        let mut zip = zip::ZipWriter::new(tempfile::tempfile().unwrap());
        zip.start_file("config.toml", zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"unrelated").unwrap();
        let mut archive = zip.finish().unwrap();
        archive.rewind().unwrap();
        let mut output = tempfile::tempfile().unwrap();
        assert!(extract(&mut archive, "package.zip", "rustinel.exe", &mut output).is_err());
        assert_eq!(output.metadata().unwrap().len(), 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn replaces_bundle_and_preserves_adjacent_data() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.app");
        let installed = directory.path().join("Rustinel.app");
        for bundle in [&source, &installed] {
            std::fs::create_dir_all(bundle.join("Contents/MacOS")).unwrap();
        }
        std::fs::write(source.join("Contents/MacOS/rustinel"), "new").unwrap();
        std::fs::write(source.join("Contents/Info.plist"), "new metadata").unwrap();
        std::fs::write(installed.join("Contents/MacOS/rustinel"), "old").unwrap();
        std::fs::write(directory.path().join("config.toml"), "preserved").unwrap();
        replace_macos_bundle(&source, &installed).unwrap();
        assert_eq!(
            std::fs::read_to_string(installed.join("Contents/MacOS/rustinel")).unwrap(),
            "new"
        );
        assert_eq!(
            std::fs::read_to_string(installed.join("Contents/Info.plist")).unwrap(),
            "new metadata"
        );
        assert_eq!(
            std::fs::read_to_string(directory.path().join("config.toml")).unwrap(),
            "preserved"
        );
    }

    #[test]
    fn zip_binary_extraction() {
        let mut archive = tempfile::tempfile().unwrap();
        {
            let mut zip = zip::ZipWriter::new(&mut archive);
            zip.start_file(
                "package/rustinel.exe",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
            zip.write_all(b"executable").unwrap();
            zip.finish().unwrap();
        }
        archive.rewind().unwrap();
        let mut output = tempfile::tempfile().unwrap();
        extract(
            &mut archive,
            "package.zip",
            "package/rustinel.exe",
            &mut output,
        )
        .unwrap();
        output.rewind().unwrap();
        let mut contents = String::new();
        output.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "executable");
    }
}
