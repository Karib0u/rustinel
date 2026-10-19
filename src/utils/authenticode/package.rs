//! AppX and MSIX package verification for files under `WindowsApps`.
//!
//! These files carry no embedded signature and no catalog entry. The package
//! is signed instead: `AppxSignature.p7x` signs a digest of
//! `AppxBlockMap.xml`, and the block map lists a SHA-256 for every 64 KiB
//! block of every file. A file is therefore valid when the package signature
//! verifies, the block map is the one that signature covers, and the file's
//! own blocks match the block map.
//!
//! The package result is cached per package root and revalidated against the
//! signature and block map files' size and modification time, so a package
//! update or removal is noticed on the next load.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;

use sha2::{Digest, Sha256};

use super::{verify_signature_file, TrustOutcome};
use crate::vocab::{SignatureFault, SignatureVerdict};

const BLOCK_BYTES: usize = 64 * 1024;
const PACKAGE_CACHE_ENTRIES: usize = 64;

/// A package root and the path of a file inside it.
pub(super) struct PackageFile {
    pub root: PathBuf,
    /// Lower-case, backslash separated, relative to `root`.
    pub relative: String,
}

/// Split `path` into its `WindowsApps` package root and the member path.
pub(super) fn locate(path: &Path) -> Option<PackageFile> {
    let mut components = path.components().peekable();
    let mut root = PathBuf::new();
    while let Some(component) = components.next() {
        root.push(component.as_os_str());
        let is_windows_apps = component
            .as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case("WindowsApps");
        if is_windows_apps {
            root.push(components.next()?.as_os_str());
            let relative: Vec<String> = components
                .map(|part| part.as_os_str().to_string_lossy().to_lowercase())
                .collect();
            if relative.is_empty() {
                return None;
            }
            return Some(PackageFile {
                root,
                relative: relative.join("\\"),
            });
        }
    }
    None
}

struct BlockEntry {
    size: u64,
    hashes: Vec<[u8; 32]>,
}

struct Package {
    signature_state: (u64, Option<SystemTime>),
    block_map_state: (u64, Option<SystemTime>),
    verdict: PackageVerdict,
    files: HashMap<String, BlockEntry>,
}

#[derive(Clone)]
enum PackageVerdict {
    Valid {
        signer: Option<String>,
    },
    Invalid {
        fault: SignatureFault,
        signer: Option<String>,
    },
    Unusable,
}

fn cache() -> &'static Mutex<HashMap<PathBuf, Arc<Package>>> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, Arc<Package>>>> = OnceLock::new();
    CACHE.get_or_init(Mutex::default)
}

fn state(path: &Path) -> Option<(u64, Option<SystemTime>)> {
    let metadata = std::fs::metadata(path).ok()?;
    Some((metadata.len(), metadata.modified().ok()))
}

fn load(root: &Path) -> Option<Arc<Package>> {
    let signature_path = root.join("AppxSignature.p7x");
    let block_map_path = root.join("AppxBlockMap.xml");
    let signature_state = state(&signature_path)?;
    let block_map_state = state(&block_map_path)?;
    {
        let cached = cache().lock().unwrap_or_else(|p| p.into_inner());
        if let Some(package) = cached.get(root) {
            if package.signature_state == signature_state
                && package.block_map_state == block_map_state
            {
                return Some(Arc::clone(package));
            }
        }
    }
    let (outcome, signer) = verify_signature_file(&signature_path);
    let verdict = match outcome {
        TrustOutcome::Valid => PackageVerdict::Valid { signer },
        TrustOutcome::Fault(fault) => PackageVerdict::Invalid { fault, signer },
        TrustOutcome::NotSigned | TrustOutcome::Inconclusive => PackageVerdict::Unusable,
    };
    let files = match std::fs::read_to_string(&block_map_path) {
        Ok(text) => parse_block_map(&text).unwrap_or_default(),
        Err(_) => HashMap::new(),
    };
    let package = Arc::new(Package {
        signature_state,
        block_map_state,
        verdict,
        files,
    });
    let mut cached = cache().lock().unwrap_or_else(|p| p.into_inner());
    if cached.len() >= PACKAGE_CACHE_ENTRIES {
        cached.clear();
    }
    cached.insert(root.to_path_buf(), Arc::clone(&package));
    Some(package)
}

/// Verify one file of an installed package, or `None` when the package or
/// the file cannot be judged (so the caller reports unknown).
pub(super) fn verify_member(file: &File, path: &Path) -> Option<SignatureVerdict> {
    let located = locate(path)?;
    let package = load(&located.root)?;
    let (fault, signer) = match &package.verdict {
        PackageVerdict::Valid { signer } => (None, signer.clone()),
        PackageVerdict::Invalid { fault, signer } => (Some(*fault), signer.clone()),
        PackageVerdict::Unusable => return None,
    };
    // A file the signed block map does not list has no integrity claim.
    let entry = package.files.get(&located.relative)?;
    if !matches_blocks(file, entry)? {
        return Some(SignatureVerdict::Invalid {
            fault: SignatureFault::Invalid,
            signer,
        });
    }
    Some(match fault {
        None => SignatureVerdict::Valid { signer },
        Some(fault) => SignatureVerdict::Invalid { fault, signer },
    })
}

/// Whether the file's 64 KiB blocks hash to the block map. `None` when the
/// file could not be read.
fn matches_blocks(file: &File, entry: &BlockEntry) -> Option<bool> {
    let mut reader = file;
    reader.seek(SeekFrom::Start(0)).ok()?;
    let mut buffer = vec![0u8; BLOCK_BYTES];
    let mut total = 0u64;
    let mut index = 0usize;
    loop {
        let mut filled = 0;
        while filled < BLOCK_BYTES {
            match reader.read(&mut buffer[filled..]) {
                Ok(0) => break,
                Ok(read) => filled += read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return None,
            }
        }
        if filled == 0 {
            break;
        }
        total += filled as u64;
        let expected = entry.hashes.get(index);
        if expected
            .is_none_or(|hash| hash.as_slice() != Sha256::digest(&buffer[..filled]).as_slice())
        {
            return Some(false);
        }
        index += 1;
        if filled < BLOCK_BYTES {
            break;
        }
    }
    Some(total == entry.size && index == entry.hashes.len())
}

/// Files of an `AppxBlockMap.xml` by lower-case relative path. `None` for a
/// document this reader does not understand.
fn parse_block_map(text: &str) -> Option<HashMap<String, BlockEntry>> {
    let document = roxmltree::Document::parse(text).ok()?;
    let root = document.root_element();
    if root.tag_name().name() != "BlockMap" {
        return None;
    }
    if !root
        .attribute("HashMethod")
        .is_some_and(|method| method.ends_with("#sha256"))
    {
        return None;
    }
    let mut files = HashMap::new();
    for file in root.children().filter(|n| n.tag_name().name() == "File") {
        let name = percent_decode(file.attribute("Name")?).to_lowercase();
        let size: u64 = file.attribute("Size")?.parse().ok()?;
        let mut hashes = Vec::new();
        for block in file.children().filter(|n| n.tag_name().name() == "Block") {
            // A block `Size` is the compressed size inside the package; the
            // hash is of the uncompressed block, which is what is on disk.
            hashes.push(decode_hash(block.attribute("Hash")?)?);
        }
        files.insert(name, BlockEntry { size, hashes });
    }
    Some(files)
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(value) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
            {
                out.push(value);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Decode a standard base64 SHA-256.
fn decode_hash(text: &str) -> Option<[u8; 32]> {
    let mut out = Vec::with_capacity(33);
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for byte in text.bytes().take_while(|byte| *byte != b'=') {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    out.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_member_path_splits_into_package_root_and_relative_file() {
        let located = locate(Path::new(
            r"C:\Program Files\WindowsApps\Microsoft.Paint_1_x64__abc\PaintApp\Foo.DLL",
        ))
        .expect("located");
        assert_eq!(
            located.root,
            PathBuf::from(r"C:\Program Files\WindowsApps\Microsoft.Paint_1_x64__abc")
        );
        assert_eq!(located.relative, r"paintapp\foo.dll");
        assert!(locate(Path::new(r"C:\Windows\System32\a.dll")).is_none());
        assert!(locate(Path::new(r"C:\Program Files\WindowsApps\Pkg")).is_none());
    }

    #[test]
    fn hashes_decode_from_base64() {
        // SHA-256 of the empty string.
        let hash = decode_hash("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=").expect("hash");
        assert_eq!(hash[0], 0xe3);
        assert_eq!(hash[31], 0x55);
        assert!(decode_hash("not base64!").is_none());
        assert!(decode_hash("AAAA").is_none());
    }

    #[test]
    fn names_are_percent_decoded() {
        assert_eq!(percent_decode("a%20b%5Cc.dll"), "a b\\c.dll");
        assert_eq!(percent_decode("100%"), "100%");
    }

    #[test]
    fn a_file_is_checked_block_by_block_against_the_map() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.bin");
        let mut bytes = vec![7u8; BLOCK_BYTES + 10];
        std::fs::write(&path, &bytes).unwrap();
        let entry = BlockEntry {
            size: bytes.len() as u64,
            hashes: vec![
                Sha256::digest(&bytes[..BLOCK_BYTES]).into(),
                Sha256::digest(&bytes[BLOCK_BYTES..]).into(),
            ],
        };
        assert_eq!(
            matches_blocks(&File::open(&path).unwrap(), &entry),
            Some(true)
        );
        bytes[BLOCK_BYTES + 3] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(
            matches_blocks(&File::open(&path).unwrap(), &entry),
            Some(false)
        );
        let short = BlockEntry {
            size: entry.size,
            hashes: vec![entry.hashes[0]],
        };
        assert_eq!(
            matches_blocks(&File::open(&path).unwrap(), &short),
            Some(false)
        );
    }

    #[test]
    fn block_sizes_are_ignored_because_hashes_cover_uncompressed_blocks() {
        let xml = r#"<BlockMap xmlns="x" HashMethod="http://www.w3.org/2001/04/xmlenc#sha256">
            <File Name="A%20b.dll" Size="3"><Block Hash="47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=" Size="2"/></File></BlockMap>"#;
        let files = parse_block_map(xml).expect("parsed");
        assert_eq!(files["a b.dll"].hashes.len(), 1);
        assert_eq!(files["a b.dll"].size, 3);
        assert!(parse_block_map("<Other/>").is_none());
    }

    fn copy_tree(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).unwrap();
        for entry in std::fs::read_dir(from).unwrap().flatten() {
            let target = to.join(entry.file_name());
            if entry.path().is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), target).unwrap();
            }
        }
    }

    /// Needs read access to an installed package, so run it as SYSTEM with
    /// `RUSTINEL_PACKAGE_DIR` naming one package folder.
    #[test]
    #[ignore = "reads an installed package named by RUSTINEL_PACKAGE_DIR"]
    fn an_installed_package_verifies_and_tampering_is_caught() {
        let Ok(source) = std::env::var("RUSTINEL_PACKAGE_DIR") else {
            return;
        };
        let source = PathBuf::from(source);
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("WindowsApps").join("Pkg_1_x64__abc");
        copy_tree(&source, &root);

        let manifest = root.join("AppxManifest.xml");
        let verdict = verify_member(&File::open(&manifest).unwrap(), &manifest);
        eprintln!("manifest: {verdict:?}");
        assert!(matches!(verdict, Some(SignatureVerdict::Valid { .. })));

        // Not in the signed block map: no integrity claim.
        let stray = root.join("stray.dll");
        std::fs::write(&stray, b"x").unwrap();
        assert_eq!(verify_member(&File::open(&stray).unwrap(), &stray), None);

        // A changed member no longer matches the block map.
        let mut bytes = std::fs::read(&manifest).unwrap();
        bytes[0] ^= 1;
        std::fs::write(&manifest, bytes).unwrap();
        let verdict = verify_member(&File::open(&manifest).unwrap(), &manifest);
        eprintln!("tampered manifest: {verdict:?}");
        assert!(matches!(
            verdict,
            Some(SignatureVerdict::Invalid {
                fault: SignatureFault::Invalid,
                ..
            })
        ));
    }
}
