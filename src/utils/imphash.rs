//! Import hash (imphash) of a PE image.
//!
//! The algorithm is pefile's `get_imphash`, which Sysmon, YARA, and VirusTotal
//! all reproduce: for every entry of the import directory, in file order, emit
//! `library.function` in lowercase, with a trailing `.dll`, `.sys`, or `.ocx`
//! removed from the library and ordinal imports named from pefile's frozen
//! imphash tables or as `ordN`. The MD5 of those entries joined by commas is
//! the imphash. Delay-load imports are not part of it.

use std::borrow::Cow;

use digest::Digest;
use goblin::pe::import::SyntheticImportLookupTableEntry;
use goblin::pe::options::{ParseMode, ParseOptions};
use goblin::pe::PE;
use md5::Md5;

mod ordinals;

/// Compute the lowercase hex imphash of a PE32 or PE32+ image.
///
/// Returns `None` for bytes that are not a parseable PE and for an image that
/// imports nothing, so an absent value never looks like a real digest.
pub(crate) fn imphash_bytes(bytes: &[u8]) -> Option<String> {
    let mut options = ParseOptions::default()
        .with_parse_mode(ParseMode::Permissive)
        .with_parse_resources(false)
        .with_parse_tls_data(false);
    // Certificates and resources play no part in the import table, so a
    // malformed one must not cost the image its imphash.
    options.parse_attribute_certificates = false;
    let pe = PE::parse_with_opts(bytes, &options).ok()?;
    let import_data = pe.import_data.as_ref()?;

    let mut entries: Vec<String> = Vec::new();
    for directory in &import_data.import_data {
        let Some(lookup_table) = &directory.import_lookup_table else {
            continue;
        };
        let dll = directory.name.to_lowercase();
        let library = strip_library_extension(&dll);
        let ordinal_names = ordinal_table(&dll);
        for import in lookup_table {
            let function = match import {
                SyntheticImportLookupTableEntry::OrdinalNumber(ordinal) => {
                    ordinal_name(ordinal_names, *ordinal)
                }
                SyntheticImportLookupTableEntry::HintNameTableRVA((_, entry)) => {
                    Cow::Borrowed(entry.name)
                }
            };
            if function.is_empty() {
                continue;
            }
            entries.push(format!("{library}.{}", function.to_lowercase()));
        }
    }

    if entries.is_empty() {
        return None;
    }
    Some(hex::encode(Md5::digest(entries.join(",").as_bytes())))
}

/// pefile removes only the last extension, and only these three.
fn strip_library_extension(dll: &str) -> &str {
    match dll.rsplit_once('.') {
        Some((stem, "dll" | "sys" | "ocx")) => stem,
        _ => dll,
    }
}

fn ordinal_table(dll: &str) -> Option<&'static [(u16, &'static str)]> {
    match dll {
        // The original implementation maps wsock32 to the ws2_32 table.
        "ws2_32.dll" | "wsock32.dll" => Some(ordinals::WS2_32),
        "oleaut32.dll" => Some(ordinals::OLEAUT32),
        _ => None,
    }
}

fn ordinal_name(table: Option<&'static [(u16, &'static str)]>, ordinal: u16) -> Cow<'static, str> {
    table
        .and_then(|table| {
            table
                .binary_search_by_key(&ordinal, |(number, _)| *number)
                .ok()
                .map(|index| table[index].1)
        })
        .map(Cow::Borrowed)
        .unwrap_or_else(|| Cow::Owned(format!("ord{ordinal}")))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// One import descriptor for the synthetic image builder.
    pub(crate) enum Thunk {
        Name(&'static str),
        Ordinal(u16),
    }

    const SECTION_RVA: u32 = 0x1000;
    const SECTION_OFFSET: usize = 0x200;

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    /// Build a minimal PE32 or PE32+ image whose only section holds an import
    /// directory with the given libraries, in order.
    pub(crate) fn pe_with_imports(pe32_plus: bool, libraries: &[(&str, &[Thunk])]) -> Vec<u8> {
        let thunk_size = if pe32_plus { 8 } else { 4 };
        let descriptors = (libraries.len() + 1) * 20;

        // Section layout: descriptors, then per library its lookup table,
        // address table, name, and hint/name entries.
        let mut section = vec![0u8; descriptors];
        let mut descriptor_fields = Vec::new();
        for (dll, thunks) in libraries {
            let lookup_rva = SECTION_RVA + section.len() as u32;
            section.resize(section.len() + (thunks.len() + 1) * thunk_size, 0);
            let address_rva = SECTION_RVA + section.len() as u32;
            section.resize(section.len() + (thunks.len() + 1) * thunk_size, 0);
            let name_rva = SECTION_RVA + section.len() as u32;
            section.extend_from_slice(dll.as_bytes());
            section.push(0);

            for (index, thunk) in thunks.iter().enumerate() {
                let value: u64 = match thunk {
                    Thunk::Ordinal(ordinal) => {
                        let flag = if pe32_plus { 1u64 << 63 } else { 1u64 << 31 };
                        flag | u64::from(*ordinal)
                    }
                    Thunk::Name(name) => {
                        let hint_rva = SECTION_RVA + section.len() as u32;
                        section.extend_from_slice(&[0, 0]);
                        section.extend_from_slice(name.as_bytes());
                        section.push(0);
                        if section.len() % 2 == 1 {
                            section.push(0);
                        }
                        u64::from(hint_rva)
                    }
                };
                for table_rva in [lookup_rva, address_rva] {
                    let offset = (table_rva - SECTION_RVA) as usize + index * thunk_size;
                    if pe32_plus {
                        put_u64(&mut section, offset, value);
                    } else {
                        put_u32(&mut section, offset, value as u32);
                    }
                }
            }
            descriptor_fields.push((lookup_rva, name_rva, address_rva));
        }
        for (index, (lookup_rva, name_rva, address_rva)) in
            descriptor_fields.into_iter().enumerate()
        {
            let offset = index * 20;
            put_u32(&mut section, offset, lookup_rva);
            put_u32(&mut section, offset + 12, name_rva);
            put_u32(&mut section, offset + 16, address_rva);
        }

        let raw_size = section.len().div_ceil(0x200) * 0x200;
        let mut image = vec![0u8; SECTION_OFFSET + raw_size];
        image[SECTION_OFFSET..SECTION_OFFSET + section.len()].copy_from_slice(&section);

        image[0..2].copy_from_slice(b"MZ");
        put_u32(&mut image, 0x3c, 0x80);
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        let optional_size: u16 = if pe32_plus { 0xf0 } else { 0xe0 };
        put_u16(&mut image, coff, if pe32_plus { 0x8664 } else { 0x014c });
        put_u16(&mut image, coff + 2, 1);
        put_u16(&mut image, coff + 16, optional_size);
        put_u16(&mut image, coff + 18, 0x0102);

        let optional = coff + 20;
        put_u16(
            &mut image,
            optional,
            if pe32_plus { 0x020b } else { 0x010b },
        );
        put_u32(&mut image, optional + 32, 0x1000);
        put_u32(&mut image, optional + 36, 0x200);
        let directories = if pe32_plus {
            put_u64(&mut image, optional + 24, 0x1_4000_0000);
            optional + 112
        } else {
            put_u32(&mut image, optional + 28, 0x0040_0000);
            optional + 96
        };
        put_u16(&mut image, optional + 40, 6);
        put_u16(&mut image, optional + 48, 6);
        put_u32(&mut image, optional + 56, SECTION_RVA + raw_size as u32);
        put_u32(&mut image, optional + 60, SECTION_OFFSET as u32);
        put_u16(&mut image, optional + 68, 3);
        put_u32(&mut image, directories - 4, 16);
        // Data directory 1 is the import table.
        put_u32(&mut image, directories + 8, SECTION_RVA);
        put_u32(&mut image, directories + 12, descriptors as u32);

        let section_header = optional + optional_size as usize;
        image[section_header..section_header + 6].copy_from_slice(b".idata");
        put_u32(&mut image, section_header + 8, raw_size as u32);
        put_u32(&mut image, section_header + 12, SECTION_RVA);
        put_u32(&mut image, section_header + 16, raw_size as u32);
        put_u32(&mut image, section_header + 20, SECTION_OFFSET as u32);
        put_u32(&mut image, section_header + 36, 0xc000_0040);
        image
    }

    fn sample_libraries() -> Vec<(&'static str, &'static [Thunk])> {
        vec![
            (
                "KERNEL32.dll",
                &[Thunk::Name("CreateFileW"), Thunk::Name("ReadFile")],
            ),
            (
                "WS2_32.dll",
                &[Thunk::Ordinal(115), Thunk::Ordinal(1), Thunk::Ordinal(9999)],
            ),
            ("OLEAUT32.dll", &[Thunk::Ordinal(2)]),
            ("Wsock32.DLL", &[Thunk::Ordinal(3)]),
            (
                "custom.drv",
                &[Thunk::Ordinal(7), Thunk::Name("Mixed_Case")],
            ),
        ]
    }

    /// The joined string pefile hashes for [`sample_libraries`].
    const SAMPLE_IMPORT_STRING: &str = "kernel32.createfilew,kernel32.readfile,ws2_32.wsastartup,ws2_32.accept,ws2_32.ord9999,oleaut32.sysallocstring,wsock32.closesocket,custom.drv.ord7,custom.drv.mixed_case";

    #[test]
    fn pe32_and_pe32_plus_hash_the_same_normalized_imports() {
        let expected = hex::encode(Md5::digest(SAMPLE_IMPORT_STRING.as_bytes()));
        for pe32_plus in [false, true] {
            let image = pe_with_imports(pe32_plus, &sample_libraries());
            assert_eq!(
                imphash_bytes(&image).as_deref(),
                Some(expected.as_str()),
                "pe32_plus = {pe32_plus}"
            );
        }
    }

    #[test]
    fn non_pe_bytes_and_import_free_images_have_no_imphash() {
        assert_eq!(imphash_bytes(b"not a PE at all"), None);
        assert_eq!(imphash_bytes(&pe_with_imports(false, &[])), None);
    }

    #[test]
    fn ordinal_tables_are_sorted_for_binary_search() {
        for table in [ordinals::WS2_32, ordinals::OLEAUT32] {
            assert!(table.windows(2).all(|pair| pair[0].0 < pair[1].0));
        }
        assert_eq!(ordinal_name(Some(ordinals::WS2_32), 115), "WSAStartup");
        assert_eq!(ordinal_name(None, 115), "ord115");
    }
}
