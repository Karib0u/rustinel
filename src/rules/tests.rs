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
