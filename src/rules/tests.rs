use super::*;
use std::io::{Cursor, Write};

use zip::{write::SimpleFileOptions, ZipWriter};

#[test]
fn install_pack_replaces_current_and_writes_state() {
    let temp = tempfile::tempdir().expect("tempdir");
    let archive = pack_zip(current_os(), "demo-pack");
    let catalog = catalog_for("demo-pack", current_os(), &archive);

    let outcome = install_pack_archive_bytes(&catalog, "demo-pack", temp.path(), &archive).unwrap();

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

    let outcome = install_pack_archive_bytes(&catalog, "schema-one-pack", temp.path(), &archive)
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
fn catalog_accepts_pack_relative_engine_paths() {
    let archive = pack_zip(current_os(), "demo-pack");
    let catalog = catalog_for("demo-pack", current_os(), &archive);

    catalog.validate().expect("catalog should validate");
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
                sigma_rules_path: format!("{id}/sigma"),
                yara_rules_path: format!("{id}/yara"),
                hashes_path: format!("{id}/ioc/hashes.txt"),
                ips_path: format!("{id}/ioc/ips.txt"),
                domains_path: format!("{id}/ioc/domains.txt"),
                paths_regex_path: format!("{id}/ioc/paths_regex.txt"),
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
        zip.start_file("sigma/demo.yml", options).unwrap();
        zip.write_all(b"title: Demo\n").unwrap();
        zip.start_file("yara/demo.yar", options).unwrap();
        zip.write_all(b"rule demo { condition: true }\n").unwrap();
        for file in ["hashes.txt", "ips.txt", "domains.txt", "paths_regex.txt"] {
            zip.start_file(format!("ioc/{file}"), options).unwrap();
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

#[test]
fn update_current_or_older_catalog_skips_download_and_restart() {
    let temp = tempfile::tempdir().unwrap();
    let archive = pack_zip(current_os(), "demo-pack");
    let mut catalog = catalog_for("demo-pack", current_os(), &archive);
    install_pack_archive_bytes(&catalog, "demo-pack", temp.path(), &archive).unwrap();
    let state = load_update_state(temp.path()).unwrap();
    let before = fs::read(temp.path().join("state.json")).unwrap();
    for version in ["0.1.0", "0.0.9", "0.1.0+build.2"] {
        catalog.packs[0].version = version.into();
        let result = update_active_pack(&catalog, &state, temp.path(), |_| {
            panic!("no-op must not download")
        })
        .unwrap();
        assert_eq!(result, None);
        let message = update_message(&state, result.as_ref());
        assert!(message.contains("up to date"));
        assert!(message.contains("No restart required"));
        assert_eq!(fs::read(temp.path().join("state.json")).unwrap(), before);
    }
}

#[test]
fn update_installs_active_pack_and_requires_restart() {
    let temp = tempfile::tempdir().unwrap();
    let archive = pack_zip(current_os(), "demo-pack");
    let mut catalog = catalog_for("demo-pack", current_os(), &archive);
    install_pack_archive_bytes(&catalog, "demo-pack", temp.path(), &archive).unwrap();
    let state = load_update_state(temp.path()).unwrap();
    fs::write(temp.path().join("current/obsolete.yml"), b"old").unwrap();
    catalog.packs[0].version = "v0.2.0".into();
    let outcome = update_active_pack(&catalog, &state, temp.path(), |pack| {
        assert_eq!(pack.id, state.pack_id);
        Ok(archive.clone())
    })
    .unwrap()
    .unwrap();
    assert_eq!(read_state(temp.path()).unwrap().version, "v0.2.0");
    assert!(!temp.path().join("current/obsolete.yml").exists());
    assert!(temp.path().join("current/sigma/demo.yml").is_file());
    let message = update_message(&state, Some(&outcome));
    assert!(message.contains("rustinel service restart"));
    assert!(message.contains("even when hot reload is enabled"));
}

#[test]
fn update_rejects_incompatible_missing_or_invalid_versions_before_download() {
    let temp = tempfile::tempdir().unwrap();
    let archive = pack_zip(current_os(), "demo-pack");
    let catalog = catalog_for("demo-pack", current_os(), &archive);
    install_pack_archive_bytes(&catalog, "demo-pack", temp.path(), &archive).unwrap();
    let state = load_update_state(temp.path()).unwrap();
    for case in ["os", "engine", "missing", "version"] {
        let mut candidate = catalog_for("demo-pack", current_os(), &archive);
        candidate.packs[0].version = "0.2.0".into();
        match case {
            "os" => candidate.packs[0].os = "unsupported".into(),
            "engine" => candidate.packs[0].requires_rustinel = ">=999.0.0".into(),
            "missing" => candidate.packs[0].id = "other-pack".into(),
            "version" => candidate.packs[0].version = "invalid".into(),
            _ => unreachable!(),
        }
        assert!(update_active_pack(&candidate, &state, temp.path(), |_| {
            panic!("invalid candidate must not download")
        })
        .is_err());
        assert_eq!(read_state(temp.path()).unwrap(), state);
    }
}

#[test]
fn failed_updates_preserve_previous_pack_and_state() {
    let temp = tempfile::tempdir().unwrap();
    let archive = pack_zip(current_os(), "demo-pack");
    let catalog = catalog_for("demo-pack", current_os(), &archive);
    install_pack_archive_bytes(&catalog, "demo-pack", temp.path(), &archive).unwrap();
    let state = load_update_state(temp.path()).unwrap();
    let state_bytes = fs::read(temp.path().join("state.json")).unwrap();
    let manifest = fs::read(temp.path().join("current/pack.yml")).unwrap();
    for case in ["download", "checksum", "unsafe", "manifest"] {
        let candidate_archive = match case {
            "unsafe" => unsafe_pack_zip(),
            "manifest" => pack_zip_with_schema(current_os(), "demo-pack", 999),
            _ => archive.clone(),
        };
        let mut candidate = catalog_for("demo-pack", current_os(), &candidate_archive);
        candidate.packs[0].version = "0.2.0".into();
        if case == "checksum" {
            candidate.packs[0].sha256 = "00".repeat(32);
        }
        assert!(update_active_pack(&candidate, &state, temp.path(), |_| {
            if case == "download" {
                bail!("simulated download failure");
            }
            Ok(candidate_archive)
        })
        .is_err());
        assert_eq!(
            fs::read(temp.path().join("state.json")).unwrap(),
            state_bytes
        );
        assert_eq!(
            fs::read(temp.path().join("current/pack.yml")).unwrap(),
            manifest
        );
    }
}

#[test]
fn update_requires_readable_state_and_installed_pack() {
    let temp = tempfile::tempdir().unwrap();
    assert!(load_update_state(temp.path()).is_err());
    fs::write(temp.path().join("state.json"), b"invalid").unwrap();
    assert!(load_update_state(temp.path()).is_err());
    let archive = pack_zip(current_os(), "demo-pack");
    let catalog = catalog_for("demo-pack", current_os(), &archive);
    install_pack_archive_bytes(&catalog, "demo-pack", temp.path(), &archive).unwrap();
    fs::remove_dir_all(temp.path().join("current")).unwrap();
    assert!(load_update_state(temp.path()).is_err());
}

#[test]
fn activation_failures_restore_previous_pack_and_state() {
    for fail_state in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let archive = pack_zip(current_os(), "demo-pack");
        let catalog = catalog_for("demo-pack", current_os(), &archive);
        install_pack_archive_bytes(&catalog, "demo-pack", temp.path(), &archive).unwrap();
        let previous_state = fs::read(temp.path().join("state.json")).unwrap();
        let next = temp.path().join("next");
        if fail_state {
            fs::create_dir(&next).unwrap();
        }
        assert!(atomic_replace_active(
            temp.path(),
            &temp.path().join("staging"),
            &next,
            &temp.path().join("missing-state"),
        )
        .is_err());
        assert!(temp.path().join("current/sigma/demo.yml").is_file());
        assert_eq!(
            fs::read(temp.path().join("state.json")).unwrap(),
            previous_state
        );
    }
}

#[test]
fn state_backup_failure_restores_current_directory() {
    let temp = tempfile::tempdir().unwrap();
    let archive = pack_zip(current_os(), "demo-pack");
    let catalog = catalog_for("demo-pack", current_os(), &archive);
    install_pack_archive_bytes(&catalog, "demo-pack", temp.path(), &archive).unwrap();
    let previous_state = fs::read(temp.path().join("state.json")).unwrap();
    // A nonempty directory cannot be removed as a file or replaced by state.json.
    let blocked = temp.path().join("staging/previous-state.json");
    fs::create_dir(&blocked).unwrap();
    fs::write(blocked.join("blocker"), b"blocker").unwrap();
    assert!(install_pack_archive_bytes(&catalog, "demo-pack", temp.path(), &archive).is_err());
    assert!(temp.path().join("current/sigma/demo.yml").is_file());
    assert_eq!(
        fs::read(temp.path().join("state.json")).unwrap(),
        previous_state
    );
}

#[test]
fn rules_operations_reject_concurrent_writers_and_stale_update_state() {
    let temp = tempfile::tempdir().unwrap();
    let archive = pack_zip(current_os(), "demo-pack");
    let mut catalog = catalog_for("demo-pack", current_os(), &archive);
    install_pack_archive_bytes(&catalog, "demo-pack", temp.path(), &archive).unwrap();
    let state = load_update_state(temp.path()).unwrap();
    let lock = lock_rules_dir(temp.path()).unwrap();
    assert!(install_pack_archive_bytes(&catalog, "demo-pack", temp.path(), &archive).is_err());
    assert!(update_active_pack(&catalog, &state, temp.path(), |_| panic!("locked")).is_err());
    drop(lock);
    catalog.packs[0].version = "0.2.0".into();
    install_pack_archive_bytes(&catalog, "demo-pack", temp.path(), &archive).unwrap();
    let error = update_active_pack(&catalog, &state, temp.path(), |_| panic!("stale")).unwrap_err();
    assert!(error.to_string().contains("state changed"), "{error:#}");
}
