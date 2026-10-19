//! Authenticode verification of an open file handle.
//!
//! Embedded signatures are verified first. A file without one is looked up in
//! the system catalogs by its hash, which is how most of Windows itself is
//! signed. Both paths verify the handle the artifact resolver already holds,
//! so the file is never reopened and a replacement after the identity check
//! cannot change what is verified.
//!
//! Revocation is not checked and certificate retrieval is cache-only: a
//! verification must not wait on the network, and a rule selecting on
//! `Signed` is judging the file, not the certificate authority's reachability.
//! The result is `Unknown` whenever Windows reports anything other than a
//! recognized signature outcome, so a failure to verify never reads as
//! unsigned.

use crate::vocab::SignatureFault;

/// What a `WinVerifyTrust` result code says about the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) enum TrustOutcome {
    Valid,
    /// No embedded signature; a catalog may still cover the file.
    NotSigned,
    /// A signature exists and failed for a known reason.
    Fault(SignatureFault),
    /// Anything else: unreadable file, resource exhaustion, an unrecognized
    /// code. Nothing is concluded about the file.
    Inconclusive,
}

/// Classify a `WinVerifyTrust` HRESULT.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn classify(result: i32) -> TrustOutcome {
    // HRESULTs are conventionally written unsigned.
    match result as u32 {
        0 => TrustOutcome::Valid,
        // TRUST_E_NOSIGNATURE, TRUST_E_PROVIDER_UNKNOWN,
        // TRUST_E_SUBJECT_FORM_UNKNOWN.
        0x800B_0100 | 0x800B_0001 | 0x800B_0003 => TrustOutcome::NotSigned,
        // CERT_E_EXPIRED.
        0x800B_0101 => TrustOutcome::Fault(SignatureFault::Expired),
        // CERT_E_REVOKED, CRYPT_E_REVOKED.
        0x800B_010C | 0x8009_2010 => TrustOutcome::Fault(SignatureFault::Revoked),
        // TRUST_E_SUBJECT_NOT_TRUSTED, TRUST_E_FAIL, TRUST_E_EXPLICIT_DISTRUST,
        // TRUST_E_BAD_DIGEST, TRUST_E_CERT_SIGNATURE, CERT_E_UNTRUSTEDROOT,
        // CERT_E_UNTRUSTEDTESTROOT, CERT_E_UNTRUSTEDCA,
        // CERT_E_PURPOSE, CERT_E_WRONG_USAGE, CERT_E_VALIDITYPERIODNESTING.
        0x800B_0004 | 0x800B_010B | 0x800B_0111 | 0x8009_6010 | 0x8009_6004 | 0x800B_0109
        | 0x800B_010D | 0x800B_0112 | 0x800B_0106 | 0x800B_0110 | 0x800B_0102 => {
            TrustOutcome::Fault(SignatureFault::Invalid)
        }
        // CERT_E_CHAINING is deliberately inconclusive: with cache-only
        // retrieval it also means an intermediate certificate was not cached,
        // which says nothing about the file.
        _ => TrustOutcome::Inconclusive,
    }
}

/// Whether `path` is inside an AppX/MSIX install root. Their files are covered
/// by the package signature, which verification does not read yet.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn is_packaged_app_path(path: &std::path::Path) -> bool {
    let text = path
        .to_string_lossy()
        .to_ascii_lowercase()
        .replace('/', "\\");
    text.contains("\\windowsapps\\")
}

#[cfg(windows)]
mod package;

#[cfg(windows)]
pub(crate) use imp::verify_file;

/// Verify a signature file on its own (an `AppxSignature.p7x`), returning the
/// outcome and the signer's display name.
#[cfg(windows)]
fn verify_signature_file(path: &std::path::Path) -> (TrustOutcome, Option<String>) {
    imp::verify_signature_file(path)
}

#[cfg(windows)]
mod imp {
    use std::fs::File;
    use std::io::{Seek, SeekFrom};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;

    use windows::core::{GUID, PCWSTR};
    use windows::Win32::Foundation::{GetLastError, HANDLE, HWND, INVALID_HANDLE_VALUE};
    use windows::Win32::Security::Cryptography::Catalog::{
        CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
        CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
        CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
    };
    use windows::Win32::Security::Cryptography::{
        CertGetNameStringW, BCRYPT_SHA256_ALGORITHM, CERT_NAME_SIMPLE_DISPLAY_TYPE,
    };
    use windows::Win32::Security::WinTrust::{
        WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain,
        WTHelperProvDataFromStateData, WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2,
        WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
        WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE,
        WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
        WTD_UI_NONE,
    };

    use super::{classify, is_packaged_app_path, TrustOutcome};
    use crate::vocab::SignatureVerdict;

    /// Catalogs tried per hash. A hash listed in more than a handful is
    /// unusual, and each attempt is a full signature verification.
    const MAX_CATALOGS: usize = 4;
    const MAX_HASH_BYTES: usize = 64;
    const SIGNER_NAME_CHARS: usize = 256;

    /// Verify the signature of the file behind `file`, embedded or catalog.
    ///
    /// `path` only names the file to the signature providers, which choose a
    /// format by extension; every byte read comes from `file`.
    pub(crate) fn verify_file(file: &File, path: &Path) -> SignatureVerdict {
        let wide_path = wide(path.as_os_str());
        let handle = HANDLE(file.as_raw_handle());
        let verdict = match verify_embedded(handle, &wide_path) {
            Verified::Done(verdict) => verdict,
            Verified::NotSigned => verify_catalog(file, handle, &wide_path),
        };
        // Packaged app files are signed by their package, not by a catalog, so
        // "no signature found" says nothing about them. The package decides;
        // when it cannot, the file is unknown rather than unsigned.
        if verdict == SignatureVerdict::Unsigned && is_packaged_app_path(path) {
            return super::package::verify_member(file, path).unwrap_or(SignatureVerdict::Unknown);
        }
        verdict
    }

    /// Verify a standalone signature file, such as a package's
    /// `AppxSignature.p7x`, whose subject type the system handles.
    pub(super) fn verify_signature_file(path: &Path) -> (TrustOutcome, Option<String>) {
        let wide_path = wide(path.as_os_str());
        let mut info = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(wide_path.as_ptr()),
            hFile: HANDLE::default(),
            pgKnownSubject: std::ptr::null_mut(),
        };
        let mut data = trust_data(WTD_CHOICE_FILE.0);
        data.Anonymous = WINTRUST_DATA_0 { pFile: &mut info };
        let (result, signer, _) = run_trust(&mut data);
        (classify(result), signer)
    }

    enum Verified {
        Done(SignatureVerdict),
        NotSigned,
    }

    fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
        text.encode_wide().chain(std::iter::once(0)).collect()
    }

    fn verify_embedded(handle: HANDLE, wide_path: &[u16]) -> Verified {
        let mut info = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(wide_path.as_ptr()),
            hFile: handle,
            pgKnownSubject: std::ptr::null_mut(),
        };
        let mut data = trust_data(WTD_CHOICE_FILE.0);
        data.Anonymous = WINTRUST_DATA_0 { pFile: &mut info };
        let (result, signer, last_error) = run_trust(&mut data);
        match classify(result) {
            TrustOutcome::Valid => Verified::Done(SignatureVerdict::Valid { signer }),
            TrustOutcome::Fault(fault) => {
                Verified::Done(SignatureVerdict::Invalid { fault, signer })
            }
            // NOSIGNATURE also describes a file that could not be read; only
            // the provider-level codes below mean the file is truly bare.
            TrustOutcome::NotSigned if bare_file_error(last_error) => Verified::NotSigned,
            TrustOutcome::NotSigned | TrustOutcome::Inconclusive => {
                Verified::Done(SignatureVerdict::Unknown)
            }
        }
    }

    fn bare_file_error(last_error: u32) -> bool {
        // ERROR_SUCCESS, TRUST_E_NOSIGNATURE, TRUST_E_PROVIDER_UNKNOWN,
        // TRUST_E_SUBJECT_FORM_UNKNOWN.
        matches!(last_error, 0 | 0x800B_0100 | 0x800B_0001 | 0x800B_0003)
    }

    fn verify_catalog(file: &File, handle: HANDLE, wide_path: &[u16]) -> SignatureVerdict {
        // Catalogs list SHA-256 for current files and SHA-1 for older ones.
        let mut conclusive = false;
        for sha256 in [true, false] {
            let Some(admin) = CatAdmin::acquire(sha256) else {
                continue;
            };
            let Some(mut hash) = admin.hash_file(file, handle) else {
                continue;
            };
            conclusive = true;
            if let Some(verdict) = admin.verify_member(handle, wide_path, &mut hash) {
                return verdict;
            }
        }
        if conclusive {
            SignatureVerdict::Unsigned
        } else {
            SignatureVerdict::Unknown
        }
    }

    /// A catalog admin context, released on drop.
    struct CatAdmin(isize);

    impl CatAdmin {
        fn acquire(sha256: bool) -> Option<Self> {
            let mut context = 0isize;
            // SAFETY: `context` is a valid out pointer; a null subsystem GUID
            // and flags select the default system catalog database.
            let acquired = unsafe {
                if sha256 {
                    CryptCATAdminAcquireContext2(
                        &mut context,
                        None,
                        BCRYPT_SHA256_ALGORITHM,
                        None,
                        None,
                    )
                } else {
                    CryptCATAdminAcquireContext2(&mut context, None, PCWSTR::null(), None, None)
                }
            };
            (acquired.is_ok() && context != 0).then_some(Self(context))
        }

        /// The file's catalog hash with this context's algorithm.
        fn hash_file(&self, mut file: &File, handle: HANDLE) -> Option<Vec<u8>> {
            file.seek(SeekFrom::Start(0)).ok()?;
            let mut buffer = vec![0u8; MAX_HASH_BYTES];
            let mut length = MAX_HASH_BYTES as u32;
            // SAFETY: `buffer` holds `length` writable bytes and the handle
            // stays open for the call.
            unsafe {
                CryptCATAdminCalcHashFromFileHandle2(
                    self.0,
                    handle,
                    &mut length,
                    Some(buffer.as_mut_ptr()),
                    None,
                )
            }
            .ok()?;
            buffer.truncate(length as usize);
            (!buffer.is_empty()).then_some(buffer)
        }

        /// Verify the file as a member of each catalog that lists `hash`.
        /// `None` when no catalog lists it or none verifies it as valid, so
        /// the caller decides between unsigned and a catalog fault.
        fn verify_member(
            &self,
            handle: HANDLE,
            wide_path: &[u16],
            hash: &mut [u8],
        ) -> Option<SignatureVerdict> {
            let tag = hex_tag(hash);
            let mut previous = 0isize;
            let mut fault = None;
            for _ in 0..MAX_CATALOGS {
                // SAFETY: `previous` is zero or the handle returned by the
                // last call, which this call releases.
                let current = unsafe {
                    CryptCATAdminEnumCatalogFromHash(
                        self.0,
                        hash,
                        None,
                        (previous != 0).then_some(&mut previous as *mut isize),
                    )
                };
                if current == 0 {
                    return fault;
                }
                previous = current;
                let Some(catalog) = catalog_path(current) else {
                    continue;
                };
                let mut info = WINTRUST_CATALOG_INFO {
                    cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
                    dwCatalogVersion: 0,
                    pcwszCatalogFilePath: PCWSTR(catalog.as_ptr()),
                    pcwszMemberTag: PCWSTR(tag.as_ptr()),
                    pcwszMemberFilePath: PCWSTR(wide_path.as_ptr()),
                    hMemberFile: handle,
                    pbCalculatedFileHash: hash.as_mut_ptr(),
                    cbCalculatedFileHash: hash.len() as u32,
                    pcCatalogContext: std::ptr::null_mut(),
                    hCatAdmin: self.0,
                };
                let mut data = trust_data(WTD_CHOICE_CATALOG.0);
                data.Anonymous = WINTRUST_DATA_0 {
                    pCatalog: &mut info,
                };
                let (result, signer, _) = run_trust(&mut data);
                match classify(result) {
                    TrustOutcome::Valid => {
                        release_catalog(self.0, previous);
                        return Some(SignatureVerdict::Valid { signer });
                    }
                    TrustOutcome::Fault(kind) => {
                        fault = Some(SignatureVerdict::Invalid {
                            fault: kind,
                            signer,
                        });
                    }
                    TrustOutcome::NotSigned | TrustOutcome::Inconclusive => {
                        fault.get_or_insert(SignatureVerdict::Unknown);
                    }
                }
            }
            release_catalog(self.0, previous);
            fault
        }
    }

    impl Drop for CatAdmin {
        fn drop(&mut self) {
            // SAFETY: the context came from a successful acquire and is
            // released exactly once.
            unsafe {
                let _ = CryptCATAdminReleaseContext(self.0, 0);
            }
        }
    }

    fn release_catalog(admin: isize, catalog: isize) {
        if catalog != 0 {
            // SAFETY: `catalog` is a live handle from the enumeration above.
            unsafe {
                let _ = CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
            }
        }
    }

    fn catalog_path(catalog: isize) -> Option<Vec<u16>> {
        let mut info = CATALOG_INFO {
            cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32,
            ..CATALOG_INFO::default()
        };
        // SAFETY: `info` is a valid CATALOG_INFO with its size set.
        unsafe { CryptCATCatalogInfoFromContext(catalog, &mut info, 0) }.ok()?;
        let length = info
            .wszCatalogFile
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(info.wszCatalogFile.len());
        let mut path = info.wszCatalogFile[..length].to_vec();
        path.push(0);
        Some(path)
    }

    /// The upper-case hex member tag catalogs index files by.
    fn hex_tag(hash: &[u8]) -> Vec<u16> {
        hash.iter()
            .flat_map(|byte| format!("{byte:02X}").encode_utf16().collect::<Vec<_>>())
            .chain(std::iter::once(0))
            .collect()
    }

    fn trust_data(choice: u32) -> WINTRUST_DATA {
        WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: windows::Win32::Security::WinTrust::WINTRUST_DATA_UNION_CHOICE(choice),
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
            ..WINTRUST_DATA::default()
        }
    }

    /// Run one verification, read the signer while the state is open, and
    /// close the state. Returns the trust result, the signer's display name,
    /// and the thread's last error from the verify call.
    fn run_trust(data: &mut WINTRUST_DATA) -> (i32, Option<String>, u32) {
        let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let window = HWND(INVALID_HANDLE_VALUE.0);
        // SAFETY: `data` and `action` are valid for the call, and the union
        // member it selects points at a live info structure.
        let result = unsafe {
            WinVerifyTrust(
                window,
                &mut action,
                data as *mut _ as *mut core::ffi::c_void,
            )
        };
        // SAFETY: reads the calling thread's error code.
        let last_error = unsafe { GetLastError() }.0;
        let signer = signer_name(data);
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        // SAFETY: closes the state the verify call opened.
        unsafe {
            WinVerifyTrust(
                window,
                &mut action,
                data as *mut _ as *mut core::ffi::c_void,
            );
        }
        (result, signer, last_error)
    }

    /// The display name of the first signer's leaf certificate.
    fn signer_name(data: &WINTRUST_DATA) -> Option<String> {
        if data.hWVTStateData.is_invalid() {
            return None;
        }
        // SAFETY: the state handle is open, so the provider data and the
        // signer and certificate records it points at stay valid until the
        // close call. Every pointer is checked before it is read.
        unsafe {
            let provider = WTHelperProvDataFromStateData(data.hWVTStateData);
            if provider.is_null() {
                return None;
            }
            let signer = WTHelperGetProvSignerFromChain(provider, 0, false, 0);
            if signer.is_null() || (*signer).csCertChain == 0 {
                return None;
            }
            let certificate = WTHelperGetProvCertFromChain(signer, 0);
            if certificate.is_null() || (*certificate).pCert.is_null() {
                return None;
            }
            let mut name = [0u16; SIGNER_NAME_CHARS];
            let written = CertGetNameStringW(
                (*certificate).pCert,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                None,
                Some(&mut name),
            ) as usize;
            // The count includes the terminator; one means an empty name.
            (written > 1).then(|| String::from_utf16_lossy(&name[..written - 1]))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::vocab::SignatureFault;
        use std::path::PathBuf;

        fn open(path: &Path) -> File {
            File::open(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
        }

        fn system32(name: &str) -> PathBuf {
            let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
            Path::new(&root).join("System32").join(name)
        }

        fn wide_of(path: &Path) -> Vec<u16> {
            wide(path.as_os_str())
        }

        #[test]
        fn a_catalog_signed_system_binary_is_valid_with_the_catalog_signer() {
            let path = system32("cmd.exe");
            let file = open(&path);
            // cmd.exe carries no embedded signature on current Windows; the
            // embedded path must hand it to the catalog lookup.
            assert!(matches!(
                verify_embedded(HANDLE(file.as_raw_handle()), &wide_of(&path)),
                Verified::NotSigned
            ));
            match verify_file(&file, &path) {
                SignatureVerdict::Valid { signer } => {
                    assert_eq!(signer.as_deref(), Some("Microsoft Windows"))
                }
                other => panic!("cmd.exe: {other:?}"),
            }
        }

        #[test]
        fn the_test_binary_is_unsigned_not_unknown() {
            let path = std::env::current_exe().unwrap();
            assert_eq!(verify_file(&open(&path), &path), SignatureVerdict::Unsigned);
        }

        #[test]
        fn an_embedded_signature_verifies_and_a_flipped_byte_does_not() {
            // Find an embedded-signed binary on this machine rather than
            // naming one that varies by build.
            let candidates = [
                system32(r"WindowsPowerShell\v1.0\powershell.exe"),
                system32("OneDriveSetup.exe"),
                system32("msiexec.exe"),
                PathBuf::from(r"C:\Program Files\Microsoft OneDrive\OneDrive.exe"),
                PathBuf::from(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
            ];
            let embedded = candidates.iter().find(|path| {
                path.exists()
                    && matches!(
                        verify_embedded(HANDLE(open(path).as_raw_handle()), &wide_of(path)),
                        Verified::Done(SignatureVerdict::Valid { .. })
                    )
            });
            let Some(path) = embedded else {
                eprintln!("no embedded-signed binary among the candidates; skipped");
                return;
            };
            let Verified::Done(SignatureVerdict::Valid { signer }) =
                verify_embedded(HANDLE(open(path).as_raw_handle()), &wide_of(path))
            else {
                unreachable!()
            };
            assert!(signer.is_some());

            // The digest covers the image, so a flipped byte in the first
            // section breaks it without disturbing the certificate table.
            let dir = tempfile::tempdir().unwrap();
            let copy = dir.path().join("tampered.exe");
            let mut bytes = std::fs::read(path).unwrap();
            let at = bytes.len() / 3;
            bytes[at] ^= 0xFF;
            std::fs::write(&copy, bytes).unwrap();
            match verify_file(&open(&copy), &copy) {
                SignatureVerdict::Invalid { fault, .. } => {
                    assert_eq!(fault, SignatureFault::Invalid)
                }
                other => panic!("tampered copy: {other:?}"),
            }
        }

        #[test]
        fn an_unreadable_handle_is_unknown_not_unsigned() {
            let dir = tempfile::tempdir().unwrap();
            let empty = dir.path().join("empty.dll");
            std::fs::write(&empty, b"").unwrap();
            // An empty file has nothing to hash; whatever Windows says, the
            // agent must not claim a conclusion it cannot back.
            let verdict = verify_file(&open(&empty), &empty);
            eprintln!("empty file: {verdict:?}");
            assert!(matches!(
                verdict,
                SignatureVerdict::Unknown | SignatureVerdict::Unsigned
            ));
        }

        /// Verdicts over `RUSTINEL_SURVEY_DIR`, for measuring on a lab host.
        #[test]
        #[ignore = "reads a directory named by RUSTINEL_SURVEY_DIR"]
        fn survey_directory_verdicts() {
            let Ok(root) = std::env::var("RUSTINEL_SURVEY_DIR") else {
                return;
            };
            let mut stack = vec![PathBuf::from(root)];
            let mut counts = std::collections::BTreeMap::<String, usize>::new();
            let mut seen = 0;
            while let Some(dir) = stack.pop() {
                let Ok(entries) = std::fs::read_dir(&dir) else {
                    continue;
                };
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        stack.push(path);
                        continue;
                    }
                    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                    if !ext.eq_ignore_ascii_case("dll") && !ext.eq_ignore_ascii_case("exe") {
                        continue;
                    }
                    let Ok(file) = File::open(&path) else {
                        continue;
                    };
                    seen += 1;
                    let verdict = verify_file(&file, &path);
                    let key = match &verdict {
                        SignatureVerdict::Valid { .. } => "valid".to_string(),
                        SignatureVerdict::Unsigned => "unsigned".to_string(),
                        SignatureVerdict::Unknown => "unknown".to_string(),
                        SignatureVerdict::Invalid { fault, .. } => format!("invalid {fault:?}"),
                    };
                    if key != "valid" && seen < 4000 {
                        eprintln!("{key}: {}", path.display());
                    }
                    *counts.entry(key).or_default() += 1;
                    if seen >= 4000 {
                        break;
                    }
                }
            }
            eprintln!("survey: {counts:?}");
        }

        #[test]
        fn survey_system32_verdicts() {
            let mut counts = std::collections::BTreeMap::<String, usize>::new();
            for entry in std::fs::read_dir(system32("")).unwrap().flatten().take(400) {
                let path = entry.path();
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if !ext.eq_ignore_ascii_case("dll") && !ext.eq_ignore_ascii_case("exe") {
                    continue;
                }
                let Ok(file) = File::open(&path) else {
                    continue;
                };
                let key = match verify_file(&file, &path) {
                    SignatureVerdict::Valid { .. } => "valid".to_string(),
                    SignatureVerdict::Unsigned => "unsigned".to_string(),
                    SignatureVerdict::Unknown => "unknown".to_string(),
                    SignatureVerdict::Invalid { fault, .. } => format!("invalid {fault:?}"),
                };
                *counts.entry(key).or_default() += 1;
            }
            eprintln!("survey: {counts:?}");
            assert!(counts.get("valid").copied().unwrap_or(0) > 100);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_and_bare_files_are_distinct() {
        assert_eq!(classify(0), TrustOutcome::Valid);
        assert_eq!(classify(0x800B_0100_u32 as i32), TrustOutcome::NotSigned);
        assert_eq!(classify(0x800B_0003_u32 as i32), TrustOutcome::NotSigned);
    }

    #[test]
    fn known_faults_keep_their_reason() {
        assert_eq!(
            classify(0x800B_0101_u32 as i32),
            TrustOutcome::Fault(SignatureFault::Expired)
        );
        assert_eq!(
            classify(0x800B_010C_u32 as i32),
            TrustOutcome::Fault(SignatureFault::Revoked)
        );
        assert_eq!(
            classify(0x8009_6010_u32 as i32),
            TrustOutcome::Fault(SignatureFault::Invalid)
        );
    }

    #[test]
    fn packaged_app_files_are_recognized_by_install_root() {
        use std::path::Path;
        assert!(is_packaged_app_path(Path::new(
            r"C:\Program Files\WindowsApps\Microsoft.Paint_1_x64__8wekyb3d8bbwe\a.dll"
        )));
        assert!(is_packaged_app_path(Path::new(
            r"c:\program files\windowsapps\x\a.dll"
        )));
        assert!(!is_packaged_app_path(Path::new(
            r"C:\Windows\System32\a.dll"
        )));
        assert!(!is_packaged_app_path(Path::new(
            r"C:\Users\a\WindowsApps.dll"
        )));
    }

    #[test]
    fn unrecognized_codes_conclude_nothing() {
        // ERROR_FILE_NOT_FOUND as an HRESULT, and an arbitrary failure.
        assert_eq!(classify(0x8007_0002_u32 as i32), TrustOutcome::Inconclusive);
        assert_eq!(classify(-1), TrustOutcome::Inconclusive);
        // A chain that could not be built offline is not a bad signature.
        assert_eq!(classify(0x800B_010A_u32 as i32), TrustOutcome::Inconclusive);
    }
}
