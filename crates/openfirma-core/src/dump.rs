//! Generic DER dumper that produces a normalized, diff friendly text tree.
//!
//! This is the tool behind the golden file comparison in docs/validation.md:
//! the same input signed by AutoFirma and by openfirma is dumped through here
//! and the two trees are diffed as text. Raw bytes cannot be compared because
//! timestamps differ, so what matters is the structure, the attribute set and
//! the encoding of each value.
//!
//! Certificates are summarized on one line instead of dumped, because their
//! DER is hundreds of bytes that would bury the interesting differences.

use core::fmt::Write as _;

use der::Decode;
use x509_cert::Certificate;

use crate::error::{Error, Result};

/// Digests and short values are printed in full, long ones are truncated so a
/// 2048 bit signature does not become a wall of hex in a diff.
const HEX_FULL_LIMIT: usize = 64;
const HEX_TRUNCATED: usize = 24;

const MAX_DEPTH: usize = 40;

pub fn der_dump(der: &[u8]) -> Result<String> {
    let mut out = String::new();
    let rest = dump_value(der, 0, &mut out)?;
    if !rest.is_empty() {
        writeln!(out, "TRAILING {} bytes {}", rest.len(), hex_preview(rest)).unwrap();
    }
    Ok(out)
}

struct Tlv<'a> {
    tag: u8,
    /// tag plus length octets, so the caller can slice exactly this value
    header_len: usize,
    content: &'a [u8],
    rest: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// Exactly the bytes of this value, no trailing siblings. Needed because
    /// `Decode::from_der` rejects trailing data, so parsing a certificate out
    /// of the remaining slice only ever works for the last one in a set.
    fn whole(&self, input: &'a [u8]) -> &'a [u8] {
        &input[..self.header_len + self.content.len()]
    }
}

fn parse_tlv(input: &[u8]) -> Result<Tlv<'_>> {
    if input.is_empty() {
        return Err(Error::other("truncated DER, expected a tag"));
    }
    let mut pos = 1usize;
    // long form tag: low five bits all set, then base 128 octets
    if input[0] & 0x1F == 0x1F {
        while pos < input.len() && input[pos] & 0x80 != 0 {
            pos += 1;
        }
        pos += 1;
    }
    if pos >= input.len() {
        return Err(Error::other("truncated DER, expected a length"));
    }
    let first_len = input[pos];
    pos += 1;
    let len = if first_len < 0x80 {
        first_len as usize
    } else if first_len == 0x80 {
        return Err(Error::other("indefinite length is not DER"));
    } else {
        let n = (first_len & 0x7F) as usize;
        if n > 8 || pos + n > input.len() {
            return Err(Error::other("DER length octets out of range"));
        }
        let mut value = 0usize;
        for b in &input[pos..pos + n] {
            value = (value << 8) | usize::from(*b);
        }
        pos += n;
        value
    };
    if pos + len > input.len() {
        return Err(Error::other(format!(
            "truncated DER, content claims {len} bytes but only {} are left",
            input.len() - pos
        )));
    }
    Ok(Tlv {
        tag: input[0],
        header_len: pos,
        content: &input[pos..pos + len],
        rest: &input[pos + len..],
    })
}

fn dump_value<'a>(bytes: &'a [u8], depth: usize, out: &mut String) -> Result<&'a [u8]> {
    if depth > MAX_DEPTH {
        return Err(Error::other("DER nesting deeper than the sanity limit"));
    }
    let t = parse_tlv(bytes)?;
    let indent = "  ".repeat(depth);
    let constructed = t.tag & 0x20 != 0;
    let class = t.tag >> 6;
    let number = t.tag & 0x1F;

    // A SEQUENCE that is actually a certificate is far more readable as one
    // line of identity than as forty lines of TBSCertificate fields.
    if class == 0 && number == 16 {
        if let Some(summary) = certificate_summary(t.whole(bytes)) {
            writeln!(out, "{indent}{summary}").unwrap();
            return Ok(t.rest);
        }
    }

    if !constructed {
        writeln!(out, "{indent}{}", primitive_line(t.tag, t.content)).unwrap();
        return Ok(t.rest);
    }

    let label = match (class, number) {
        (0, 16) => format!("SEQUENCE ({})", t.content.len()),
        (0, 17) => format!("SET ({})", t.content.len()),
        (2, n) => format!("[{n}] ({})", t.content.len()),
        (1, n) => format!("<app {n}> ({})", t.content.len()),
        (3, n) => format!("<priv {n}> ({})", t.content.len()),
        _ => format!("<tag {:02X}> ({})", t.tag, t.content.len()),
    };
    writeln!(out, "{indent}{label}").unwrap();

    let mut rest = t.content;
    while !rest.is_empty() {
        rest = dump_value(rest, depth + 1, out)?;
    }
    Ok(t.rest)
}

fn primitive_line(tag: u8, content: &[u8]) -> String {
    match tag {
        0x01 => match content {
            [0x00] => "BOOLEAN false".to_string(),
            [0xFF] => "BOOLEAN true".to_string(),
            other => format!("BOOLEAN <non canonical {}>", hex::encode_upper(other)),
        },
        0x02 => format!("INTEGER {}", integer_preview(content)),
        0x03 => format!(
            "BIT STRING {} bits {}",
            content.len().saturating_mul(8),
            hex_preview(&content[1.min(content.len())..])
        ),
        0x04 => format!("OCTET STRING {}", hex_preview(content)),
        0x05 => "NULL".to_string(),
        0x06 => oid_line(content),
        0x0C | 0x13 | 0x16 | 0x1E => format!(
            "{} \"{}\"",
            string_kind(tag),
            String::from_utf8_lossy(content).replace('\n', "\\n")
        ),
        0x17 | 0x18 => format!("{} {}", time_kind(tag), String::from_utf8_lossy(content)),
        other => format!("<prim {other:02X}> {}", hex_preview(content)),
    }
}

fn string_kind(tag: u8) -> &'static str {
    match tag {
        0x0C => "UTF8String",
        0x13 => "PrintableString",
        0x16 => "IA5String",
        _ => "T61String",
    }
}

fn time_kind(tag: u8) -> &'static str {
    if tag == 0x17 {
        "UTCTime"
    } else {
        "GeneralizedTime"
    }
}

fn oid_line(content: &[u8]) -> String {
    let dotted = encode_oid(content);
    let name = const_oid::ObjectIdentifier::from_bytes(content)
        .ok()
        .map(|o: const_oid::ObjectIdentifier| o.to_string())
        .filter(|n| *n != dotted);
    match name {
        Some(n) => format!("OID {dotted} {n}"),
        None => format!("OID {dotted}"),
    }
}

/// Decodes an OID body to dotted notation without allocating an ObjectIdentifier,
/// so malformed OIDs still show something instead of failing the whole dump.
fn encode_oid(content: &[u8]) -> String {
    let mut out = String::new();
    let mut arcs: Vec<u64> = Vec::new();
    let mut value: u64 = 0;
    for (i, byte) in content.iter().enumerate() {
        value = (value << 7) | u64::from(byte & 0x7F);
        if byte & 0x80 == 0 {
            arcs.push(value);
            value = 0;
        } else if i == content.len() - 1 {
            return format!("<malformed oid {}>", hex::encode(content));
        }
    }
    match arcs.split_first() {
        None => return "<empty oid>".to_string(),
        Some((&first, rest)) => {
            // the first body octet packs arcs 1 and 2 as 40*X + Y, X in 0..=2
            let x = (first / 40).min(2);
            write!(out, "{x}.{}", first - 40 * x).unwrap();
            for arc in rest {
                write!(out, ".{arc}").unwrap();
            }
        }
    }
    out
}

fn integer_preview(content: &[u8]) -> String {
    // Small non negative values read better in decimal, everything else in hex
    if content.len() <= 8 && content.first().copied().unwrap_or(0) & 0x80 == 0 {
        let mut v: u64 = 0;
        for b in content {
            v = (v << 8) | u64::from(*b);
        }
        return v.to_string();
    }
    if content.first().copied().unwrap_or(0) & 0x80 != 0 {
        return format!("<negative {} bytes>", content.len());
    }
    hex_preview(content)
}

fn hex_preview(bytes: &[u8]) -> String {
    if bytes.len() <= HEX_FULL_LIMIT {
        return hex::encode_upper(bytes);
    }
    format!(
        "{}...({} bytes)",
        hex::encode_upper(&bytes[..HEX_TRUNCATED]),
        bytes.len()
    )
}

fn certificate_summary(der: &[u8]) -> Option<String> {
    let cert = Certificate::from_der(der).ok()?;
    let tbs = cert.tbs_certificate();
    Some(format!(
        "CERTIFICATE serial={} subject=\"{}\" issuer=\"{}\"",
        hex::encode_upper(tbs.serial_number().as_bytes()),
        tbs.subject(),
        tbs.issuer()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_sequence_of_two_nulls() {
        let der = [0x30, 0x04, 0x05, 0x00, 0x05, 0x00];
        let dump = der_dump(&der).unwrap();
        assert!(dump.contains("SEQUENCE (4)"), "{dump}");
        assert_eq!(dump.matches("NULL").count(), 2, "{dump}");
    }

    #[test]
    fn long_form_length() {
        let mut der = vec![0x04, 0x81, 0x80];
        der.extend(vec![0xAB; 128]);
        let dump = der_dump(&der).unwrap();
        assert!(dump.contains("OCTET STRING"), "{dump}");
        assert!(dump.contains("128 bytes"), "{dump}");
    }

    #[test]
    fn rejects_indefinite_length() {
        assert!(der_dump(&[0x30, 0x80, 0x00, 0x00]).is_err());
    }

    #[test]
    fn rejects_truncated_content() {
        assert!(der_dump(&[0x04, 0x10, 0x01]).is_err());
    }

    #[test]
    fn oid_decoding() {
        // 1.2.840.113549.1.7.2, id-signedData
        let body = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
        let mut der = vec![0x06, body.len() as u8];
        der.extend_from_slice(&body);
        let dump = der_dump(&der).unwrap();
        assert!(dump.contains("1.2.840.113549.1.7.2"), "{dump}");
    }

    #[test]
    fn trailing_bytes_are_reported() {
        let der = [0x05, 0x00, 0xFF, 0xFF];
        assert!(der_dump(&der).unwrap().contains("TRAILING 2 bytes"));
    }
}
