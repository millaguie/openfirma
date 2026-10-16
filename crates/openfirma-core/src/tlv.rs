//! Minimal DER assembly for the containers that the signature formats need,
//! and the one cursor every DER reader shares.
//!
//! The `der` crate encodes leaves correctly, but the formats need byte exact
//! control over containers: IMPLICIT retagging, DER ordering of `SET OF`, and
//! keeping the encoded content of the signed attributes around so it can be
//! re-tagged as `SET OF` before the signature is computed. That last rule
//! cannot be expressed with derive macros, so containers are built here and
//! leaves go through `der`.
//!
//! Reading lives here too ([`Cursor`]). CMS/CAdES, the revocation data and
//! RFC 3161 tokens each grew a hand-rolled DER cursor once, with different
//! rules — one of them forgot a bounds check and panicked on three hostile
//! bytes from the network. A length field is attacker-controlled data; there
//! is exactly one place in this workspace allowed to slice by it.

use core::cmp::Ordering;
use std::time::SystemTime;

use const_oid::ObjectIdentifier;
use der::Encode;
use der::asn1::{Any, OctetString, UtcTime};
use spki::AlgorithmIdentifierOwned;

use crate::error::{Error, Result};

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

// ---------------------------------------------------------------------------
// reading

/// One DER value read from a [`Cursor`]: what it is, and both ways of seeing
/// its bytes. `whole` is tag, length and content — the exact bytes the value
/// occupies in the input, which is what a signature or digest is computed
/// over and what `der::Decode` re-parses certificates from; `content` alone
/// is neither.
#[derive(Clone, Copy, Debug)]
pub struct Value<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    pub whole: &'a [u8],
}

/// A cursor over a byte buffer read as DER, strict and bounds-checked on
/// every claim the data makes. These buffers come from the network (a TSA's
/// answer), from a document under verification and from files someone else
/// wrote; the contract of this type is that no byte pattern makes it panic —
/// every failure is an `Error::Other` naming what the bytes got wrong. It
/// checks, per value:
///
/// - the tag byte and the length octets are actually present;
/// - the length is definite (indefinite form is BER) and at most eight
///   octets wide, so it cannot overflow a `usize`;
/// - the content runs no further than the end of the buffer.
///
/// Callers who must also reject the multi-octet high tag form (CMS never
/// uses it) pass [`NO_HIGH_TAG`] to [`Cursor::with_options`].
#[derive(Clone)]
pub struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
    reject_high_tag: bool,
}

/// Cursor options: refuse the high tag number form (`xx1F` tags), which no
/// CMS/CAdES/OCSP/CRL/RFC 3161 field uses and which readers are entitled to
/// treat as an error.
pub const NO_HIGH_TAG: Options = Options {
    reject_high_tag: true,
};

/// [`Cursor`] options. The default accepts every single byte tag form, the
/// way the module-local cursors did before they were merged here.
#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    pub reject_high_tag: bool,
}

impl<'a> Cursor<'a> {
    /// A cursor over `b` with the default options.
    pub fn new(b: &'a [u8]) -> Self {
        Cursor {
            b,
            i: 0,
            reject_high_tag: false,
        }
    }

    /// A cursor with explicit options; pass [`NO_HIGH_TAG`] for the strict
    /// CMS-family behaviour.
    pub fn with_options(b: &'a [u8], opts: Options) -> Self {
        Cursor {
            b,
            i: 0,
            reject_high_tag: opts.reject_high_tag,
        }
    }

    /// True when every byte has been consumed.
    pub fn done(&self) -> bool {
        self.i >= self.b.len()
    }

    /// The current read position within the original buffer. Together with
    /// [`Cursor::buffer`] this lets a caller slice a composite value (the
    /// TSA's `ContentInfo` inside a `TimeStampResp`) out of the exact input.
    pub fn position(&self) -> usize {
        self.i
    }

    /// The whole buffer this cursor reads.
    pub fn buffer(&self) -> &'a [u8] {
        self.b
    }

    /// The tag of the next value without consuming it, `None` at the end.
    pub fn peek_tag(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    /// The next TLV, or an error naming why the bytes are not a DER value.
    pub fn value(&mut self) -> Result<Value<'a>> {
        let start = self.i;
        let tag = *self
            .b
            .get(start)
            .ok_or_else(|| Error::Other("the DER ends where a tag was expected".to_string()))?;
        if self.reject_high_tag && tag & 0x1F == 0x1F {
            return Err(Error::Other(format!(
                "tag {tag:#04x} uses the multi octet form, which no field of this format needs"
            )));
        }
        let mut len_start = start + 1;
        if tag & 0x1F == 0x1F {
            // High tag number form: the tag continues through the length
            // bytes, every but the last with the top bit set. Bounds-checked;
            // a module that refuses it passes NO_HIGH_TAG instead.
            let mut j = len_start;
            loop {
                let byte = *self.b.get(j).ok_or_else(|| {
                    Error::Other("the DER ends inside a multi octet tag".to_string())
                })?;
                j += 1;
                if byte & 0x80 == 0 {
                    break;
                }
            }
            len_start = j;
        }
        let (len, n) = self.read_len(len_start)?;
        let content_start = len_start + n;
        let end = content_start
            .checked_add(len)
            .ok_or_else(|| Error::Other("a DER length overflows the address space".to_string()))?;
        if end > self.b.len() {
            return Err(Error::Other(format!(
                "a value with tag {tag:#04x} claims {len} bytes but only {} are left",
                self.b.len().saturating_sub(content_start)
            )));
        }
        self.i = end;
        Ok(Value {
            tag,
            content: &self.b[content_start..end],
            whole: &self.b[start..end],
        })
    }

    /// Reads the length field at `at`. Returns `(content length, number of
    /// length octets)`, or an error for a truncated, indefinite, or absurdly
    /// wide length. Never indexes past the end of the buffer.
    fn read_len(&self, at: usize) -> Result<(usize, usize)> {
        let first = *self
            .b
            .get(at)
            .ok_or_else(|| Error::Other("the DER ends where a length was expected".to_string()))?;
        if first < 0x80 {
            return Ok((first as usize, 1));
        }
        let n = (first & 0x7f) as usize;
        if n == 0 {
            return Err(Error::Other(
                "indefinite length is BER, and these formats are DER".to_string(),
            ));
        }
        if n > 8 || self.b.len() < at + 1 + n {
            return Err(Error::Other(
                "a DER length that is overlong or runs past the input".to_string(),
            ));
        }
        let mut v = 0usize;
        for x in &self.b[at + 1..at + 1 + n] {
            v = (v << 8) | usize::from(*x);
        }
        Ok((v, n + 1))
    }

    /// The next value, which must carry `tag`; `what` names it in errors.
    pub fn expect(&mut self, tag: u8, what: &str) -> Result<Value<'a>> {
        let t = self.value()?;
        if t.tag != tag {
            return Err(Error::Other(format!(
                "expected {what} (tag {tag:#04x}), found tag {:#04x}",
                t.tag
            )));
        }
        Ok(t)
    }

    /// The next value as an OID, decoded; `what` names it in errors.
    pub fn oid(&mut self, what: &str) -> Result<ObjectIdentifier> {
        let t = self.expect(TAG_OID, what)?;
        ObjectIdentifier::from_bytes(t.content)
            .map_err(|e| Error::Other(format!("{what} is not a readable OID: {e}")))
    }

    /// The next value as an INTEGER holding `0..=u32::MAX` in minimal form,
    /// which covers every version field and enumerated code of these formats.
    pub fn small_uint(&mut self, what: &str) -> Result<u32> {
        let t = self.expect(TAG_INTEGER, what)?;
        Self::integer_u32(&t, what)
    }

    /// The next value as an INTEGER holding `0..=u32::MAX`, BER tolerant: a
    /// leading zero pad byte and any width that still fits are accepted. For
    /// reading someone else's data (revocation time codes); strict DER must
    /// use the minimal-form check above.
    pub fn loose_uint(&mut self, what: &str) -> Result<u32> {
        let t = self.expect(TAG_INTEGER, what)?;
        if t.content.len() > 4 || t.content.first().is_some_and(|b| b & 0x80 != 0) {
            return Err(Error::Other(format!(
                "{what} is negative or too large to read"
            )));
        }
        let mut v = 0u32;
        for b in t.content {
            v = (v << 8) | u32::from(*b);
        }
        Ok(v)
    }

    /// The next value as an INTEGER holding `0..=usize::MAX` in minimal
    /// form. The old tsp cursor truncated longer values silently; this one
    /// refuses them, because a field that size is not a count of anything.
    pub fn number(&mut self, what: &str) -> Result<usize> {
        let t = self.expect(TAG_INTEGER, what)?;
        let bytes = t.content;
        if bytes.is_empty()
            || bytes.len() > core::mem::size_of::<usize>()
            || (bytes[0] & 0x80 != 0)
            || (bytes[0] == 0 && bytes.get(1).is_some_and(|b| b & 0x80 == 0))
        {
            return Err(Error::Other(format!(
                "{what} is not a minimal non negative integer up to usize"
            )));
        }
        let mut n = 0usize;
        for b in bytes {
            n = (n << 8) | usize::from(*b);
        }
        Ok(n)
    }

    /// Checks an already-read value as an INTEGER holding `0..=u32::MAX` in
    /// minimal form (X.690 8.3: no leading zero byte unless the top bit
    /// needs it).
    pub fn integer_u32(v: &Value<'_>, what: &str) -> Result<u32> {
        if v.tag != TAG_INTEGER {
            return Err(Error::Other(format!(
                "expected {what} (tag {TAG_INTEGER:#04x}), found tag {:#04x}",
                v.tag
            )));
        }
        let bytes = v.content;
        // empty, or a leading zero that DER only allows in front of a byte
        // whose top bit would read as the sign
        let non_minimal = match bytes {
            [] => true,
            [0x00] => false,
            [0x00, rest @ ..] => rest[0] & 0x80 == 0,
            [first, ..] => *first & 0x80 != 0, // negative
        };
        if non_minimal || bytes.len() > 4 {
            return Err(Error::Other(format!(
                "{what} is not a minimal non negative integer up to u32"
            )));
        }
        let mut n = 0u32;
        for b in bytes {
            n = (n << 8) | u32::from(*b);
        }
        Ok(n)
    }

    /// The next value, which must be a SEQUENCE, as a cursor over its
    /// content.
    pub fn sequence(&mut self, what: &str) -> Result<Cursor<'a>> {
        Ok(Cursor {
            b: self.expect(TAG_SEQUENCE, what)?.content,
            i: 0,
            reject_high_tag: self.reject_high_tag,
        })
    }

    /// The next value, which must be the context specific EXPLICIT `[n]`.
    pub fn explicit(&mut self, n: u8, what: &str) -> Result<&'a [u8]> {
        Ok(self.expect(0xA0 | n, what)?.content)
    }

    /// The next value, which must be an OCTET STRING.
    pub fn octets(&mut self, what: &str) -> Result<&'a [u8]> {
        Ok(self.expect(TAG_OCTET_STRING, what)?.content)
    }
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

    #[test]
    fn cursor_reads_a_well_formed_value() {
        let bytes = tlv(TAG_SEQUENCE, &[0x05, 0x00]);
        let mut c = Cursor::new(&bytes);
        let v = c.value().unwrap();
        assert_eq!(v.tag, TAG_SEQUENCE);
        assert_eq!(v.content, &[0x05, 0x00]);
        assert_eq!(v.whole, &bytes[..]);
        assert!(c.done());
    }

    #[test]
    fn cursor_refuses_a_truncated_long_form_length() {
        // The exact hostile bytes of the tsp.rs panic: a length that claims
        // four more octets than the buffer holds, in two and three bytes.
        for bytes in [
            &[0x30u8, 0x84][..],
            &[0x30, 0x83][..],
            &[0x30, 0x82, 0x01][..],
        ] {
            let mut c = Cursor::new(bytes);
            let err = c.value().expect_err("truncated length must not parse");
            assert!(!err.to_string().is_empty());
        }
    }

    #[test]
    fn cursor_refuses_indefinite_and_absurd_lengths() {
        let mut c = Cursor::new(&[0x30, 0x80, 0x05, 0x00, 0x00, 0x00]);
        let err = c.value().expect_err("indefinite length is BER");
        assert!(err.to_string().contains("indefinite"), "{err}");
        // nine length octets cannot fit a usize and are refused outright
        let mut bytes = vec![0x30u8, 0x89];
        bytes.extend_from_slice(&[0xff; 9]);
        let mut c = Cursor::new(&bytes);
        assert!(c.value().is_err());
    }

    #[test]
    fn cursor_refuses_a_length_that_runs_past_the_buffer() {
        let mut bytes = vec![0x30u8, 0x81, 0x40];
        bytes.extend_from_slice(&[0u8; 0x3f]); // one byte short of 64
        let mut c = Cursor::new(&bytes);
        let err = c.value().expect_err("the value is one byte short");
        assert!(err.to_string().contains("claims"), "{err}");
    }

    #[test]
    fn cursor_reads_every_truncated_der_without_panicking() {
        // the sweep review 07 asked for: cut a real DER at every offset
        let mut full = tlv(TAG_SEQUENCE, &tlv(TAG_INTEGER, &[0x02]));
        full.extend_from_slice(&[0x31, 0x83, 0x05, 0x00]); // trailing SET claims 3
        for end in 0..=full.len() {
            let mut c = Cursor::new(&full[..end]);
            while c.value().is_ok() {}
        }
    }

    #[test]
    fn cursor_refuses_non_minimal_integers() {
        // X.690 minimal form: 0x0281 is not DER, 0x020081 is not either;
        // 0x0200 and 0x0281-with-high-bit... only [0x00] alone or a leading
        // zero followed by a high bit byte are legal zeros/padding.
        let mut c = Cursor::new(&[0x02, 0x02, 0x00, 0x01]);
        assert!(c.small_uint("version").is_err());
        let mut c = Cursor::new(&[0x02, 0x01, 0x80]);
        assert!(c.small_uint("version").is_err(), "a negative INTEGER");
        let mut c = Cursor::new(&[0x02, 0x00]);
        assert!(
            c.small_uint("version").is_err(),
            "an empty INTEGER is not DER"
        );
        let mut c = Cursor::new(&[0x02, 0x01, 0x03]);
        assert_eq!(c.small_uint("version").unwrap(), 3);
        let mut c = Cursor::new(&[0x02, 0x01, 0x00]);
        assert_eq!(c.small_uint("version").unwrap(), 0);
        let mut c = Cursor::new(&[0x02, 0x02, 0x00, 0x80]);
        assert_eq!(c.small_uint("version").unwrap(), 128);
    }

    #[test]
    fn high_tag_form_refused_only_when_asked() {
        // tag 0xBF, second tag octet 0x05 (top bit clear), definite length 1
        let bytes = [0xBF, 0x05, 0x01, 0x2A];
        let mut c = Cursor::new(&bytes);
        assert_eq!(c.value().unwrap().tag, 0xBF); // tolerated by default
        let mut c = Cursor::with_options(&bytes, NO_HIGH_TAG);
        assert!(c.value().is_err());
    }

    #[test]
    fn high_tag_form_is_measured_not_skipped_wrongly() {
        // the multi octet tag occupies bytes 0..2 and the length lives at
        // index 2: a cursor that assumed one tag byte would read the tag's
        // continuation (0x05 = NULL) as the length and mis-slice.
        let bytes = [0xBFu8, 0x81, 0x05, 0x01, b'A'];
        let mut c = Cursor::new(&bytes);
        let v = c.value().unwrap();
        assert_eq!(v.content, b"A");
        assert_eq!(v.whole, &bytes[..]);
        assert!(c.done());
    }

    #[test]
    fn cursor_slices_composite_values_by_position() {
        let inner = tlv(TAG_SEQUENCE, &[0x05, 0x00]);
        let mut outer = vec![0x02u8, 0x01, 0x01]; // an INTEGER before it
        outer.extend_from_slice(&inner);
        let mut c = Cursor::new(&outer);
        c.value().unwrap(); // version
        let start = c.position();
        assert_eq!(c.value().unwrap().whole, &inner[..]);
        assert_eq!(&c.buffer()[start..c.position()], &inner[..]);
    }
}
