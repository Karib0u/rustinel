//! Version contract between the userspace decoder and the embedded eBPF object.

use anyhow::{bail, Context, Result};
use object::{Object, ObjectSection, ObjectSymbol};

/// Bump this whenever a ring-buffer event layout or loader-patched global changes.
pub(crate) const LINUX_EBPF_ABI_VERSION: u32 = 1;

const ABI_SYMBOL: &str = "RUSTINEL_ABI_VERSION";

/// Read and validate the ABI version embedded in an eBPF ELF object.
pub(super) fn validate_object_abi(bytes: &[u8]) -> Result<()> {
    validate_version(object_abi_version(bytes)?)
}

fn validate_version(actual: u32) -> Result<()> {
    if actual != LINUX_EBPF_ABI_VERSION {
        bail!(
            "Linux eBPF ABI mismatch: loader expects {}, object provides {}; rebuild the eBPF object and userspace binary together",
            LINUX_EBPF_ABI_VERSION,
            actual
        );
    }
    Ok(())
}

fn object_abi_version(bytes: &[u8]) -> Result<u32> {
    let object = object::File::parse(bytes).context("failed to parse eBPF object ELF")?;
    let symbol = object
        .symbols()
        .find(|symbol| symbol.name() == Ok(ABI_SYMBOL))
        .with_context(|| format!("eBPF object does not declare {ABI_SYMBOL}"))?;
    let section_index = symbol
        .section_index()
        .with_context(|| format!("{ABI_SYMBOL} has no data section"))?;
    let section = object
        .section_by_index(section_index)
        .context("failed to locate eBPF ABI data section")?;
    let data = section
        .data()
        .context("failed to read eBPF ABI data section")?;
    let offset = symbol
        .address()
        .checked_sub(section.address())
        .context("eBPF ABI symbol address precedes its section")? as usize;
    let raw = data
        .get(offset..offset + std::mem::size_of::<u32>())
        .context("eBPF ABI symbol is truncated")?;
    Ok(u32::from_le_bytes(raw.try_into().expect("four-byte slice")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_abi_is_nonzero() {
        assert_ne!(LINUX_EBPF_ABI_VERSION, 0);
    }

    #[test]
    fn embedded_object_declares_expected_abi() {
        validate_object_abi(super::super::EBPF_BYTES).unwrap();
    }

    #[test]
    fn mismatch_fails_with_both_versions() {
        let err = validate_version(LINUX_EBPF_ABI_VERSION + 1).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("ABI mismatch"));
        assert!(message.contains(&LINUX_EBPF_ABI_VERSION.to_string()));
        assert!(message.contains(&(LINUX_EBPF_ABI_VERSION + 1).to_string()));
    }
}
