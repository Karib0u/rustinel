use anyhow::{Context, Result};
use minisign_verify::{PublicKey, Signature};

const RELEASE_KEY: &str = include_str!("../release-minisign.pub");

pub(crate) fn verify(bytes: &[u8], signature: &[u8]) -> Result<()> {
    let key = PublicKey::decode(RELEASE_KEY).context("invalid embedded release public key")?;
    let signature =
        std::str::from_utf8(signature).context("invalid Minisign signature encoding")?;
    let signature = Signature::decode(signature).context("invalid Minisign signature")?;
    key.verify(bytes, &signature, false)
        .context("release signature verification failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_untampered_data_from_trusted_key() {
        let checksums = include_bytes!("../tests/fixtures/update-checksums.txt");
        let signature = include_bytes!("../tests/fixtures/update-checksums.txt.minisig");
        let wrong_key = include_bytes!("../tests/fixtures/update-checksums-wrong-key.minisig");

        assert!(verify(checksums, signature).is_ok());
        assert!(verify(checksums, wrong_key).is_err());
        assert!(verify(b"modified checksums", signature).is_err());
        assert!(verify(checksums, b"").is_err());
    }
}
