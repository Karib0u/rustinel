//! Shared DNS wire-format parsing used by platform sensors.
//!
//! Both the Linux eBPF sensor and the macOS `/dev/bpf` sensor observe raw DNS
//! query payloads and need to extract the queried name. This module holds the
//! single, defensive parser they share.

/// DNS message header length in bytes.
pub(crate) const HEADER_LEN: usize = 12;
/// Top two bits of a label length byte mark a compression pointer.
const LABEL_POINTER_MASK: u8 = 0xc0;
/// Maximum length of a single DNS label.
const LABEL_MAX_LEN: usize = 63;

/// Parse the first question (QNAME and QTYPE) from a raw DNS query payload.
///
/// Returns `None` for responses (QR bit set), empty question sections,
/// truncated payloads, or names that use compression pointers (which do not
/// appear in the question section of a well-formed query). The parser never
/// follows pointers, keeping it bounded and safe against malformed input. The
/// QTYPE is `0` when the payload is truncated right after the name.
pub(crate) fn parse_question(payload: &[u8]) -> Option<(String, u16)> {
    if payload.len() < HEADER_LEN {
        return None;
    }

    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if flags & 0x8000 != 0 || qdcount == 0 {
        return None;
    }

    let mut pos = HEADER_LEN;
    let mut labels: Vec<String> = Vec::new();
    while pos < payload.len() {
        let label_len = payload[pos];
        pos += 1;

        if label_len == 0 {
            let name = if labels.is_empty() {
                ".".to_string()
            } else {
                labels.join(".")
            };
            let qtype = match (payload.get(pos), payload.get(pos + 1)) {
                (Some(hi), Some(lo)) => u16::from_be_bytes([*hi, *lo]),
                _ => 0,
            };
            return Some((name, qtype));
        }

        if label_len & LABEL_POINTER_MASK != 0 {
            return None;
        }

        let label_len = usize::from(label_len);
        if label_len > LABEL_MAX_LEN || pos + label_len > payload.len() {
            return None;
        }

        labels.push(String::from_utf8_lossy(&payload[pos..pos + label_len]).into_owned());
        pos += label_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal single-question DNS query payload for `name`.
    fn query_payload(name: &str) -> Vec<u8> {
        let mut payload = vec![0u8; HEADER_LEN];
        payload[5] = 1; // qdcount = 1
        for label in name.split('.') {
            payload.push(label.len() as u8);
            payload.extend_from_slice(label.as_bytes());
        }
        payload.push(0); // root label
        payload.extend_from_slice(&1u16.to_be_bytes()); // qtype = A
        payload.extend_from_slice(&1u16.to_be_bytes()); // qclass = IN
        payload
    }

    fn query_name(payload: &[u8]) -> Option<String> {
        parse_question(payload).map(|(name, _qtype)| name)
    }

    #[test]
    fn parses_simple_query_name() {
        let payload = query_payload("sub.example.test");
        assert_eq!(query_name(&payload).as_deref(), Some("sub.example.test"));
    }

    #[test]
    fn parses_question_name_and_qtype() {
        let payload = query_payload("example.test");
        let (name, qtype) = parse_question(&payload).expect("question should parse");
        assert_eq!(name, "example.test");
        assert_eq!(qtype, 1); // A
    }

    #[test]
    fn rejects_short_payload() {
        assert_eq!(parse_question(&[0u8; HEADER_LEN - 1]), None);
    }

    #[test]
    fn rejects_response_messages() {
        let mut payload = query_payload("example.test");
        payload[2] = 0x80; // set QR bit
        assert_eq!(parse_question(&payload), None);
    }

    #[test]
    fn rejects_zero_question_count() {
        let mut payload = query_payload("example.test");
        payload[4] = 0;
        payload[5] = 0;
        assert_eq!(parse_question(&payload), None);
    }

    #[test]
    fn rejects_compression_pointer() {
        let mut payload = vec![0u8; HEADER_LEN];
        payload[5] = 1;
        payload.push(LABEL_POINTER_MASK); // pointer instead of a label length
        payload.push(0x00);
        assert_eq!(parse_question(&payload), None);
    }

    #[test]
    fn rejects_truncated_label() {
        let mut payload = vec![0u8; HEADER_LEN];
        payload[5] = 1;
        payload.push(10); // claims a 10-byte label
        payload.extend_from_slice(b"abc"); // but only 3 bytes follow
        assert_eq!(parse_question(&payload), None);
    }
}
