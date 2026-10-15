//! Minimal DER assembly for the containers that the signature formats need.
//!
//! The `der` crate encodes leaves correctly, but the formats need byte exact
//! control over containers: IMPLICIT retagging, DER ordering of `SET OF`, and
//! keeping the encoded content of the signed attributes around so it can be
//! re-tagged as `SET OF` before the signature is computed. That last rule
//! cannot be expressed with derive macros, so containers are built here and
//! leaves go through `der`.

use core::cmp::Ordering;
use std::time::SystemTime;

use const_oid::ObjectIdentifier;
use der::Encode;
use der::asn1::{Any, OctetString, UtcTime};
use spki::AlgorithmIdentifierOwned;

use crate::error::Result;

pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_BIT_STRING: u8 = 0x03;
pub const TAG_OCTET_STRING: u8 = 0x04;
pub const TAG_NULL: u8 = 0x05;
pub const TAG_OID: u8 = 0x06;
pub const TAG_SEQUENCE: u8 = 0x30;
pub const TAG_SET: u8 = 0x31;
pub const TAG_UTC_TIME: u8 = 0x17;

/// DER definite length octets, always minimal form.
pub fn length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let be = len.to_be_bytes();
    let first_nonzero = be.iter().position(|b| *b != 0).unwrap_or(be.len() - 1);
    let significant = &be[first_nonzero..];
    let mut out = Vec::with_capacity(significant.len() + 1);
    out.push(0x80 | significant.len() as u8);
    out.extend_from_slice(significant);
    out
}

/// One tag-length-value.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 8);
    out.push(tag);
    out.extend(length(content.len()));
    out.extend_from_slice(content);
    out
}

/// SEQUENCE or SEQUENCE OF.
pub fn sequence(items: &[Vec<u8>]) -> Vec<u8> {
    tlv(TAG_SEQUENCE, &items.concat())
}

/// `SET OF` in DER order.
pub fn set_of(items: Vec<Vec<u8>>) -> Vec<u8> {
    tlv(TAG_SET, &set_of_content(items))
}

/// The concatenated, DER ordered elements of a `SET OF`, without the outer
/// tag. The signed attributes need this: the same bytes are tagged `[0]`
/// IMPLICIT inside `SignerInfo` and `SET OF` when they are hashed for the
/// signature.
pub fn set_of_content(mut items: Vec<Vec<u8>>) -> Vec<u8> {
    der_sort(&mut items);
    items.concat()
}

/// X.690 ordering for `SET OF`: lexicographic on the encoded elements, with
/// the shorter one padded with zero octets.
pub fn der_sort(items: &mut [Vec<u8>]) {
    items.sort_by(|a, b| {
        let n = a.len().max(b.len());
        for i in 0..n {
            let x = a.get(i).copied().unwrap_or(0);
            let y = b.get(i).copied().unwrap_or(0);
            if x != y {
                return x.cmp(&y);
            }
        }
        Ordering::Equal
    });
}

/// Context specific EXPLICIT, tag `0xA0 | n`.
pub fn explicit(tag_number: u8, inner: &[u8]) -> Vec<u8> {
    tlv(0xA0 | tag_number, inner)
}

/// Context specific IMPLICIT CONSTRUCTED, tag `0xA0 | n`. `content` is the
/// concatenation of the inner elements, with no inner tag of its own.
pub fn implicit_constructed(tag_number: u8, content: &[u8]) -> Vec<u8> {
    tlv(0xA0 | tag_number, content)
}

pub fn octet_string(bytes: &[u8]) -> Result<Vec<u8>> {
    Ok(OctetString::new(bytes.to_vec())?.to_der()?)
}

pub fn oid(o: &ObjectIdentifier) -> Result<Vec<u8>> {
    Ok(o.to_der()?)
}

pub fn null() -> Vec<u8> {
    vec![TAG_NULL, 0x00]
}

/// INTEGER holding a small non negative value, which covers every `version`
/// field in CMS.
pub fn integer_small(v: u8) -> Vec<u8> {
    debug_assert!(v < 0x80, "integer_small only encodes 0..=127");
    tlv(TAG_INTEGER, &[v])
}

pub fn utc_time(t: SystemTime) -> Result<Vec<u8>> {
    Ok(UtcTime::from_system_time(t)?.to_der()?)
}

pub fn algorithm_identifier(ai: &AlgorithmIdentifierOwned) -> Result<Vec<u8>> {
    Ok(ai.to_der()?)
}

pub fn any(a: &Any) -> Result<Vec<u8>> {
    Ok(a.to_der()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_length() {
        assert_eq!(length(0), vec![0x00]);
        assert_eq!(length(127), vec![0x7f]);
    }

    #[test]
    fn long_length() {
        assert_eq!(length(128), vec![0x81, 0x80]);
        assert_eq!(length(0x1234), vec![0x82, 0x12, 0x34]);
        assert_eq!(length(0x01_0203), vec![0x83, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn set_of_is_der_ordered() {
        // 0x05 0x00 (NULL) sorts before 0x06 0x01 0x2a (shorter OID), and a
        // prefix sorts before the longer value that extends it
        let a = vec![0x06, 0x01, 0x2a];
        let b = vec![0x05, 0x00];
        let c = vec![0x06, 0x01, 0x2a, 0x00];
        let encoded = set_of(vec![a.clone(), b.clone(), c.clone()]);
        assert_eq!(encoded[0], TAG_SET);
        assert_eq!(&encoded[2..], [&b[..], &a[..], &c[..]].concat());
    }
}
