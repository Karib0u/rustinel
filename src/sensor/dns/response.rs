//! DNS response decoding: the first question plus A, AAAA, and CNAME answers.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::{read_question_name, HEADER_LEN, LABEL_MAX_LEN, LABEL_POINTER_MASK, QR_RESPONSE};

/// Maximum length of an encoded domain name.
const NAME_MAX_LEN: usize = 255;
/// Compression pointers followed while decoding one name. Every hop must
/// point strictly backwards, so this only bounds long legitimate chains.
const MAX_POINTER_HOPS: usize = 16;
/// Answer records inspected in one response.
const MAX_ANSWERS: usize = 64;

const RCODE_MASK: u16 = 0x000f;
const CLASS_IN: u16 = 1;
const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_AAAA: u16 = 28;

/// One decoded answer record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DnsAnswer {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
}

/// The parts of a DNS response a sensor event carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsResponse {
    /// Name from the first question.
    pub name: String,
    /// Type from the first question.
    pub qtype: u16,
    /// Response code (RCODE): 0 is success, 3 is NXDOMAIN.
    pub rcode: u8,
    /// A, AAAA, and CNAME answers, in message order. Other types are skipped.
    pub answers: Vec<DnsAnswer>,
}

/// Parse the first question and the A, AAAA, and CNAME answers of a response.
///
/// Returns `None` for queries, responses without a question, and a question
/// that does not parse. A message cut short inside the answer section keeps
/// every answer that was complete, since the sensor copies a bounded prefix
/// of large responses.
pub(crate) fn parse_response(payload: &[u8]) -> Option<DnsResponse> {
    if payload.len() < HEADER_LEN {
        return None;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    let ancount = u16::from_be_bytes([payload[6], payload[7]]);
    if flags & QR_RESPONSE == 0 || qdcount == 0 {
        return None;
    }

    let (name, mut pos) = read_question_name(payload, HEADER_LEN)?;
    let qtype = u16::from_be_bytes([*payload.get(pos)?, *payload.get(pos + 1)?]);
    pos = pos.checked_add(4)?;
    let mut response = DnsResponse {
        name,
        qtype,
        rcode: (flags & RCODE_MASK) as u8,
        answers: Vec::new(),
    };

    for _ in 1..qdcount {
        let Some(next) = skip_name(payload, pos).and_then(|end| end.checked_add(4)) else {
            return Some(response);
        };
        pos = next;
    }

    for _ in 0..usize::from(ancount).min(MAX_ANSWERS) {
        let Some(header) = skip_name(payload, pos) else {
            break;
        };
        let Some(fixed) = payload.get(header..header + 10) else {
            break;
        };
        let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let class = u16::from_be_bytes([fixed[2], fixed[3]]);
        let rdlength = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        let rdata_start = header + 10;
        let Some(rdata) = payload.get(rdata_start..rdata_start + rdlength) else {
            break;
        };
        pos = rdata_start + rdlength;
        if class != CLASS_IN {
            continue;
        }
        let answer = match (rtype, rdata.len()) {
            (TYPE_A, 4) => DnsAnswer::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
            (TYPE_AAAA, 16) => DnsAnswer::Aaaa(Ipv6Addr::from(<[u8; 16]>::try_from(rdata).ok()?)),
            (TYPE_CNAME, _) => match read_name(payload, rdata_start) {
                Some(target) => DnsAnswer::Cname(target),
                None => continue,
            },
            _ => continue,
        };
        response.answers.push(answer);
    }

    Some(response)
}

/// Render answers the way the Windows DNS Client reports `QueryResults`:
/// `type:  5 <target>;` for a CNAME, the bare address for A and AAAA, each
/// terminated by `;`. `None` when there is nothing to report.
pub(crate) fn format_query_results(answers: &[DnsAnswer]) -> Option<String> {
    use std::fmt::Write;

    if answers.is_empty() {
        return None;
    }
    let mut out = String::new();
    for answer in answers {
        let _ = match answer {
            DnsAnswer::A(ip) => write!(out, "{ip};"),
            DnsAnswer::Aaaa(ip) => write!(out, "{ip};"),
            DnsAnswer::Cname(target) => write!(out, "type:  {TYPE_CNAME} {target};"),
        };
    }
    Some(out)
}

/// Return the offset just past a possibly compressed name at `pos`.
fn skip_name(payload: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let label_len = *payload.get(pos)?;
        if label_len == 0 {
            return Some(pos + 1);
        }
        if label_len & LABEL_POINTER_MASK == LABEL_POINTER_MASK {
            payload.get(pos + 1)?;
            return Some(pos + 2);
        }
        if label_len & LABEL_POINTER_MASK != 0 {
            return None;
        }
        pos += 1 + usize::from(label_len);
    }
}

/// Decode a possibly compressed name at `pos`, following pointers.
///
/// Every pointer must jump strictly backwards, which rules out loops, and the
/// hop count and decoded length are both capped.
fn read_name(payload: &[u8], mut pos: usize) -> Option<String> {
    let mut labels: Vec<String> = Vec::new();
    let mut encoded_len = 0usize;
    let mut hops = 0usize;
    loop {
        let label_len = *payload.get(pos)?;
        if label_len == 0 {
            return Some(if labels.is_empty() {
                ".".to_string()
            } else {
                labels.join(".")
            });
        }
        if label_len & LABEL_POINTER_MASK == LABEL_POINTER_MASK {
            let target =
                usize::from(u16::from_be_bytes([label_len, *payload.get(pos + 1)?]) & 0x3fff);
            hops += 1;
            if target >= pos || hops > MAX_POINTER_HOPS {
                return None;
            }
            pos = target;
            continue;
        }
        if label_len & LABEL_POINTER_MASK != 0 {
            return None;
        }
        let label_len = usize::from(label_len);
        encoded_len += label_len + 1;
        if label_len > LABEL_MAX_LEN || encoded_len > NAME_MAX_LEN {
            return None;
        }
        let label = payload.get(pos + 1..pos + 1 + label_len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos += 1 + label_len;
    }
}

#[cfg(test)]
mod tests {
    use super::super::parse_question;
    use super::super::tests::query_payload;
    use super::*;

    /// Build a response to `name`/`qtype` whose answers are `(type, rdata)`
    /// pairs. Owner names point back at the question, as resolvers encode them.
    fn response_payload(name: &str, qtype: u16, rcode: u8, answers: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut payload = query_payload(name);
        payload[1] = 0x2a;
        payload[2] = 0x81; // QR, RD
        payload[3] = 0x80 | rcode; // RA
        payload[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
        let qtype_at = payload.len() - 4;
        payload[qtype_at..qtype_at + 2].copy_from_slice(&qtype.to_be_bytes());
        for (rtype, rdata) in answers {
            payload.extend_from_slice(&[0xc0, HEADER_LEN as u8]);
            payload.extend_from_slice(&rtype.to_be_bytes());
            payload.extend_from_slice(&CLASS_IN.to_be_bytes());
            payload.extend_from_slice(&300u32.to_be_bytes());
            payload.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            payload.extend_from_slice(rdata);
        }
        payload
    }

    /// Encode `name` as labels, ending in a pointer to `suffix_at` if given.
    fn encoded_name(name: &str, suffix_at: Option<u16>) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.').filter(|label| !label.is_empty()) {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        match suffix_at {
            Some(offset) => out.extend_from_slice(&(0xc000 | offset).to_be_bytes()),
            None => out.push(0),
        }
        out
    }

    #[test]
    fn parses_a_and_aaaa_answers() {
        let payload = response_payload(
            "example.test",
            TYPE_A,
            0,
            &[
                (TYPE_A, vec![198, 51, 100, 10]),
                (
                    TYPE_AAAA,
                    "2001:db8::10"
                        .parse::<Ipv6Addr>()
                        .unwrap()
                        .octets()
                        .to_vec(),
                ),
            ],
        );
        let response = parse_response(&payload).expect("response should parse");
        assert_eq!(response.name, "example.test");
        assert_eq!(response.qtype, TYPE_A);
        assert_eq!(response.rcode, 0);
        assert_eq!(
            response.answers,
            vec![
                DnsAnswer::A(Ipv4Addr::new(198, 51, 100, 10)),
                DnsAnswer::Aaaa("2001:db8::10".parse().unwrap()),
            ]
        );
        assert_eq!(
            format_query_results(&response.answers).as_deref(),
            Some("198.51.100.10;2001:db8::10;")
        );
    }

    #[test]
    fn follows_compression_in_cname_targets() {
        // The CNAME target "edge.cdn" + pointer to "test" inside the question.
        let question_tld = (HEADER_LEN + 1 + "www".len() + 1 + "example".len()) as u16;
        let payload = response_payload(
            "www.example.test",
            TYPE_A,
            0,
            &[
                (TYPE_CNAME, encoded_name("edge.cdn", Some(question_tld))),
                (TYPE_A, vec![203, 0, 113, 7]),
            ],
        );
        let response = parse_response(&payload).expect("response should parse");
        assert_eq!(
            response.answers,
            vec![
                DnsAnswer::Cname("edge.cdn.test".to_string()),
                DnsAnswer::A(Ipv4Addr::new(203, 0, 113, 7)),
            ]
        );
        assert_eq!(
            format_query_results(&response.answers).as_deref(),
            Some("type:  5 edge.cdn.test;203.0.113.7;")
        );
    }

    #[test]
    fn keeps_complete_answers_from_a_truncated_capture() {
        let payload = response_payload(
            "example.test",
            TYPE_A,
            0,
            &[(TYPE_A, vec![192, 0, 2, 1]), (TYPE_A, vec![192, 0, 2, 2])],
        );
        let response = parse_response(&payload[..payload.len() - 1]).unwrap();
        assert_eq!(
            response.answers,
            vec![DnsAnswer::A(Ipv4Addr::new(192, 0, 2, 1))]
        );
    }

    #[test]
    fn nxdomain_reports_rcode_without_answers() {
        let payload = response_payload("missing.test", TYPE_AAAA, 3, &[]);
        let response = parse_response(&payload).unwrap();
        assert_eq!(response.rcode, 3);
        assert_eq!(response.qtype, TYPE_AAAA);
        assert!(response.answers.is_empty());
        assert_eq!(format_query_results(&response.answers), None);
    }

    #[test]
    fn skips_other_record_types_and_malformed_rdata() {
        let payload = response_payload(
            "example.test",
            TYPE_A,
            0,
            &[
                (16, b"\x05hello".to_vec()),     // TXT
                (TYPE_A, vec![192, 0, 2, 1, 9]), // A with a bad length
                (TYPE_A, vec![192, 0, 2, 3]),
            ],
        );
        let response = parse_response(&payload).unwrap();
        assert_eq!(
            response.answers,
            vec![DnsAnswer::A(Ipv4Addr::new(192, 0, 2, 3))]
        );
    }

    #[test]
    fn rejects_pointer_loops_and_forward_pointers() {
        let mut payload = response_payload("example.test", TYPE_CNAME, 0, &[]);
        payload[6..8].copy_from_slice(&1u16.to_be_bytes());
        let answer_at = payload.len() as u16;
        payload.extend_from_slice(&[0xc0, HEADER_LEN as u8]);
        payload.extend_from_slice(&TYPE_CNAME.to_be_bytes());
        payload.extend_from_slice(&CLASS_IN.to_be_bytes());
        payload.extend_from_slice(&300u32.to_be_bytes());
        payload.extend_from_slice(&2u16.to_be_bytes());
        // A pointer to itself: rdata starts at answer_at + 12.
        payload.extend_from_slice(&(0xc000 | (answer_at + 12)).to_be_bytes());
        let response = parse_response(&payload).unwrap();
        assert!(response.answers.is_empty());
    }

    #[test]
    fn response_parser_rejects_queries_and_parser_for_queries_rejects_responses() {
        let query = query_payload("example.test");
        assert_eq!(parse_response(&query), None);
        let response = response_payload("example.test", TYPE_A, 0, &[]);
        assert_eq!(parse_question(&response), None);
    }
}
