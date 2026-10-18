//! PKCS#12, RFC 7292: the container a real certificate arrives in.
//!
//! AutoFirma gets this for free from the JCA `KeyStore.getInstance("PKCS12")`.
//! We have no JCA, and the obvious crate is not an option: RustCrypto's
//! `pkcs12` sits on the previous ASN.1 generation, the same reason `cms` was
//! ruled out in ADR-0001. So this is a reader for the subset that real files
//! use, written on the same `der` generation as the rest of the workspace.
//!
//! What it understands:
//!
//! - the MAC that protects the whole container, with SHA-1, SHA-256, SHA-384
//!   and SHA-512, which is how a wrong password is detected before any
//!   decryption is trusted; an empty password in either of the two encodings
//!   the real writers use (Java's zero bytes, OpenSSL/NSS's BMP terminator);
//!   and MD5, which no current writer defaults to but old Windows tooling and
//!   `openssl pkcs12 -macalg md5` do write — reading it is a compatibility
//!   need, the MAC being a password check and never a trust decision;
//! - PBES2 with PBKDF2 (any of those hashes as PRF) over AES-128/192/256-CBC
//!   and 3DES-CBC, which is what OpenSSL 3 and current Java write — including
//!   the optional `keyLength` INTEGER that Java 11+ writes in every set of
//!   PBKDF2 parameters (finding A1);
//! - the legacy PKCS#12 PBEs with SHA-1 over 3DES *and RC2-40*, which is what
//!   older FNMT software, OpenSSL's `-legacy`, Java up to 8u301 defaults and
//!   the macOS keychain produce (finding A2). RC2 lives here because a refusal
//!   that sends people to `openssl pkcs12` for re-export does not work: a
//!   current OpenSSL refuses to *read* those files without `-legacy`, and with
//!   it writes PEM. A 40-bit cipher is worthless crypto; refusing to open the
//!   files people actually hold is not the way to say so;
//! - cert bags, shrouded and plain key bags, nested safe contents, and the
//!   `friendlyName` / `localKeyID` attributes that tie a key to its chain.
//!
//! The framing is BER, not only DER. Firefox's own "Hacer copia…" exports —
//! and `pk12util`, which is the same code — write indefinite lengths and
//! constructed OCTET STRINGs at every level of the container (finding C2), and
//! they are the single most common way a Spaniard gets a .p12 out of a
//! browser. The MAC is computed over decoded contents, never over framing
//! bytes, so accepting BER weakens nothing that integrity covers. What stays
//! refused: indefinite lengths on primitive values, untagged garbage, nesting
//! past any real container (the core `tlv::Cursor`'s rules apply).
//!
//! What it refuses, loudly: RC4 PBE, which no real writer ever defaulted to;
//! PBMAC1 integrity (RFC 9579), still rare enough to name rather than
//! implement; and key derivation counts above ten million iterations, which
//! no legitimate writer produces and which are a denial of service the moment
//! they are believed. Every refusal message says how to re-export the file
//! with a modern openssl — where a re-export exists at all.

use const_oid::ObjectIdentifier;
use digest::{Digest, KeyInit, Mac};
use hmac::Hmac;
use openfirma_core::cert::CertificateHandle;
use openfirma_core::{Error, Result};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const OID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const OID_ENCRYPTED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.6");
const OID_KEY_BAG: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.10.1.1");
const OID_SHROUDED_KEY_BAG: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.10.1.2");
const OID_CERT_BAG: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.10.1.3");
const OID_SAFE_CONTENTS_BAG: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.10.1.6");
const OID_X509_CERTIFICATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.22.1");
const OID_FRIENDLY_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.20");
const OID_LOCAL_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.21");
const OID_PBE_SHA1_3DES: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.1.3");
const OID_PBE_SHA1_RC2_40: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.1.6");
const OID_PBES2: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.5.13");
const OID_PBMAC1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.5.14");
const OID_PBKDF2: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.5.12");
const OID_HMAC_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.2.7");
const OID_HMAC_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.2.9");
const OID_HMAC_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.2.10");
const OID_HMAC_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.2.11");
const OID_AES128_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.2");
const OID_AES192_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.22");
const OID_AES256_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.42");
const OID_DES_EDE3_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.3.7");
/// RC2-CBC as PKCS#5 v2 names it (`openssl pkcs12 -certpbe RC2-40-CBC` writes
/// PBES2 with this scheme; the 40-bit strength comes from the keyLength, review
/// 04 finding A2). Its parameters carry the IV as an INTEGER, unlike AES's
/// OCTET STRING.
const OID_RC2_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.3.2");
const OID_MD5: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.2.5");
const OID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

/// A key bag as it is found: `localKeyID`, `friendlyName`, and the decrypted
/// PKCS#8 private key. The key is zeroized when this tuple drops, which is why
/// it travels in a [`Zeroizing`] until it is copied into an [`Entry`], whose
/// own `Drop` takes over from there.
type FoundKey = (Option<Vec<u8>>, Option<String>, Zeroizing<Vec<u8>>);

/// One private key and the certificates that travel with it.
///
/// The `Debug` implementation prints the alias, the localKeyID and the chain
/// but never `key_pkcs8`: an `{entry:?}` in a log or a panic would otherwise
/// publish the decrypted private key next to it (finding B-3). Keeping the
/// trait (rather than dropping the derive outright) is what keeps `.unwrap()`
/// usable on `Result<Entry, _>`; printing the key is what it refuses to do.
#[derive(Clone)]
pub struct Entry {
    /// `friendlyName`, the human readable alias, when the file carries one.
    pub alias: Option<String>,
    /// `localKeyID`, what ties the key bag to its certificate bags.
    pub local_key_id: Option<Vec<u8>>,
    /// The private key as PKCS#8 `PrivateKeyInfo` DER, decrypted.
    pub key_pkcs8: Vec<u8>,
    /// Certificates, leaf first, then the chain up to whatever the file held.
    pub chain: Vec<Vec<u8>>,
}

impl Drop for Entry {
    /// The decrypted private key is the one buffer in this crate that outlives
    /// the load call, so it is the one that has to be zeroed on the way out
    /// instead of left to the allocator's mercy.
    fn drop(&mut self) {
        self.key_pkcs8.zeroize();
    }
}

impl std::fmt::Debug for Entry {
    /// The manual form of the key-hiding rule stated at `Entry`: every field
    /// except the private key prints normally (test failures need to see the
    /// alias and chain), and the key is named but never shown. A future
    /// `#[derive(Debug)]` here would silently undo it — this impl's existence
    /// makes that a compile-visible choice, not an invisible one.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("alias", &self.alias)
            .field("local_key_id", &self.local_key_id)
            .field("key_pkcs8", &"[hidden]")
            .field("chain", &self.chain.len())
            .finish()
    }
}

/// Everything a PKCS#12 file held. `Debug` is the manual, key-hiding one of
/// [`Entry`] applied to every entry; nothing here ever formats a key.
#[derive(Clone, Default)]
pub struct Pkcs12 {
    pub entries: Vec<Entry>,
}

impl std::fmt::Debug for Pkcs12 {
    /// Delegates to `Entry`'s key-hiding Debug, so the container inherits the
    /// rule instead of needing its own.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs12")
            .field("entries", &self.entries)
            .finish()
    }
}

impl Pkcs12 {
    /// Reads and decrypts a container. A wrong password is reported as such,
    /// because the MAC is checked before anything is trusted.
    pub fn load(bytes: &[u8], password: &str) -> Result<Self> {
        load(bytes, password)
    }

    /// Picks an entry by alias, or the only one there is. Several entries and
    /// no alias is an error rather than a guess: signing with the wrong
    /// identity is the one mistake a signature tool cannot afford.
    pub fn entry(&self, alias: Option<&str>) -> Result<&Entry> {
        match alias {
            Some(wanted) => self
                .entries
                .iter()
                .find(|e| e.alias.as_deref() == Some(wanted))
                .ok_or_else(|| {
                    Error::Keystore(format!(
                        "no entry named {wanted:?}; the file holds {}",
                        self.aliases().join(", ")
                    ))
                }),
            None => match self.entries.len() {
                0 => Err(Error::Keystore("the PKCS#12 holds no private key".into())),
                1 => Ok(&self.entries[0]),
                n => Err(Error::Keystore(format!(
                    "the PKCS#12 holds {n} keys ({}); pass --alias to choose one",
                    self.aliases().join(", ")
                ))),
            },
        }
    }

    /// The entry names of this container, in file order: each entry's
    /// friendlyName, or a positional `<entry n>` when it carries none. Public
    /// because `autofirma listaliases` (review 06, A-8) answers exactly that
    /// question for a PKCS#12 and must read it through this crate's own rule,
    /// never a re-parse that could drift from what `entry()` actually picks.
    pub fn aliases(&self) -> Vec<String> {
        self.entries
            .iter()
            .enumerate()
            .map(|(i, e)| {
                e.alias
                    .clone()
                    .unwrap_or_else(|| format!("<entry {}>", i + 1))
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// DER/BER reading: the workspace's one bounds-checked cursor, in its
// BER-tolerant mode (see `openfirma_core::tlv::BER_INDEFINITE`: Firefox and
// pk12util export indefinite-length BER), wrapped so that a malformed
// container always answers with the keystore error the CLI shows, re-export
// hint included. The wrapper exists because a truncated .p12 used to index
// `&b[1..=n]` past the buffer: `printf '\x30\x84' > trunc.p12` panicked at the
// length read. There is now one reader with one set of bounds rules for the
// whole workspace (openfirma_core::tlv).
//
// Nesting copies: descending into a value hands back a level that OWNS the
// value's bytes. One bounded copy per descent — containers are kilobytes, and
// PKCS#12 nests about fifteen levels on real files — for a lifetime story with
// no story: no borrowed cursors, no raw pointers, nothing a child can
// outlive. (`&mut`-split buffers were tried first and are a dead end here: the
// mutable half freezes the parent exactly when PKCS#12 needs it to advance.)
// A BER constructed OCTET STRING (`0x24`, what NSS writes at every level; its
// value is the concatenation of chunks spread through its parent) becomes an
// owned join here and reads as a plain `0x04` from here up: substitution in
// exactly one place, one shape for every reader above.

/// One nesting level of the container and how far its read has come. The
/// buffer is the value's own bytes: either copied out of the parent (one
/// bounded copy per descent — see the section comment for why copying is what
/// this reader wants, and why nothing borrows) or owned outright (a BER join,
/// a decrypted block). `Zeroizing` because every level of a PKCS#12 may be
/// holding password-protected material on its way to being a key.
struct Level {
    buf: Zeroizing<Vec<u8>>,
    i: usize,
}

impl Level {
    /// A level over bytes taken from elsewhere (the file, or a value's content
    /// copied out of its parent). Copying is what removes every lifetime story
    /// from this module: no cursor here addresses memory it does not own.
    fn new(bytes: &[u8]) -> Self {
        Level {
            buf: Zeroizing::new(bytes.to_vec()),
            i: 0,
        }
    }

    /// A level that already owns its bytes (joins, decrypted blocks).
    fn owned(buf: Zeroizing<Vec<u8>>) -> Self {
        Level { buf, i: 0 }
    }

    fn bytes(&self) -> &[u8] {
        &self.buf
    }

    fn is_done(&self) -> bool {
        self.i >= self.buf.len()
    }

    /// The tag of the next value without consuming it, `None` at the end.
    fn peek_tag(&self) -> Option<u8> {
        // The real tag: multi-octet (high-tag-number) forms would be a bug in
        // this reader's own paths, but do not report the continuation byte as
        // if it were the tag.
        let first = *self.buf.get(self.i)?;
        if first & 0x1F == 0x1F {
            let mut j = self.i + 1;
            while matches!(self.buf.get(j), Some(b) if b & 0x80 != 0) {
                j += 1;
            }
            return self.buf.get(j).copied();
        }
        Some(first)
    }

    /// One value: its tag and a NEW level over its content, this one advanced
    /// past it. A `0x24` constructed OCTET STRING (NSS's BER signature) hands
    /// back the owned join of its chunks and reads as a plain `0x04` from here
    /// up; every other value hands back a copy of its content — one header's
    /// worth at most, bounded by the file. This is the only place tag shapes
    /// change, so every reader above sees exactly one form of each thing.
    fn any(&mut self) -> Result<(u8, Level)> {
        // A `let` binding for the base cursor rather than a chain: chained, it
        // is a temporary whose borrow of `self.buf` dies at the end of the
        // statement while the resumed cursor still reads through it. The named
        // binding keeps that borrow alive exactly as long as `inner`.
        let base = openfirma_core::tlv::Cursor::with_options(
            &self.buf,
            openfirma_core::tlv::BER_INDEFINITE,
        );
        let mut inner = base.resume_at(self.i);
        let v = inner.value().map_err(|e| {
            Error::Keystore(format!(
                "{e}. Re-export the file with `openssl pkcs12 -in old.p12 \
                 -out new.p12` if it came from elsewhere"
            ))
        })?;
        self.i = inner.position();
        if v.tag == 0x24 {
            // A BER constructed OCTET STRING (NSS writes them at every level)
            // denotes its chunks concatenated: hand back tag `0x04` and the
            // owned join — NOT the join re-wrapped in OCTET STRING framing.
            // Every caller that receives this value already sits inside the
            // OCTET STRING context that framing states (the authSafe level,
            // a chunk list, an implicit `[0]`'s content), and DER nests
            // another header *inside* those contexts, never around the bytes
            // being handed out. Re-wrapping here added a phantom `04 …` to
            // NSS's `a0 82 24 82 …` authSafe and shifted every offset inside
            // by two bytes — MACs failed and ciphertexts read truncated.
            let joined = join_constructed_octet_string(v.content)?;
            return Ok((0x04, Level::owned(joined)));
        }
        // The child must own the value's CONTENT as a level of its own: an
        // AlgorithmIdentifier's parameters, say. `v.whole` is the full TLV —
        // handing it out made every params level carry one extra header and
        // shifted each element inside by two bytes (the prf SEQUENCE read as
        // if its tag were where its length was). One copy per descent, which is
        // also this reader's whole lifetime story: see the section comment.
        Ok((v.tag, Level::new(v.content)))
    }

    /// The next value's content, which must be a SEQUENCE.
    fn sequence(&mut self) -> Result<Level> {
        let (tag, level) = self.any()?;
        if tag != 0x30 {
            return Err(sequence_error(tag));
        }
        Ok(level)
    }

    /// The next value's content, which must be an OCTET STRING (`0x24` joins
    /// count as plain ones: `any()` rewrote their tag).
    fn octets(&mut self) -> Result<Level> {
        let (tag, level) = self.any()?;
        if tag != 0x04 {
            return Err(Error::Keystore(format!(
                "expected an OCTET STRING in the PKCS#12, found tag {tag:#04x}. \
                 Re-export the file with `openssl pkcs12 -in old.p12 -pw new.p12` \
                 if it came from elsewhere"
            )));
        }
        // A nested OCTET STRING means BER put one element in the wrapper
        // (`04 82 …` inside `a0 82 …`, which OpenSSL 3 does for both the
        // authSafe and the encrypted content). Unwrap only when exactly one
        // value fills the level — joining several would mix up a chunked
        // payload (whose concatenation is the data, see `decrypt_content_info`)
        // with a wrapper, and demanding two spellings of one file from every
        // reader on the path was how this reader got the sizes wrong. One
        // unwrap per level, which is as deep as any writer in the field nests.
        let nested = {
            let mut probe = Level::new(level.bytes());
            match (probe.any(), probe.is_done()) {
                (Ok((0x04, inner)), true) => Some(inner.into_level_bytes()),
                _ => None,
            }
        };
        Ok(match nested {
            Some(inner) => Level::owned(inner),
            None => level,
        })
    }

    /// `[n] EXPLICIT`, the wrapper PKCS#12 puts around nested content. BER's
    /// constructed form of a context tag is the same bit pattern (`0xA0|n`
    /// already carries the constructed bit), so nothing extra is needed here.
    /// `[n]` EXPLICIT — the wrapper PKCS#12 puts around nested content, in
    /// whichever framing the writer used. BER spells a constructed tag with a
    /// definite or an indefinite length and both mean one encoding, so `a0|n`
    /// is accepted either way; its CONTENT is what the caller walks, exactly
    /// as OpenSSL's d2i descends it. A primitive implicit `[n]` (the tag
    /// `80|n`, which DER writers use where the schema says `[n] IMPLICIT
    /// OCTET STRING`) hands out ITS content for the same walk: with no inner
    /// structure, the content of an implicit value is the level. Anything else
    /// at this position — a SEQUENCE, say, where NSS puts the certificate bag's
    /// or EncryptedData's payload directly (`a0 80 <SEQUENCE …>`) — means there
    /// is no wrapper here and nothing is consumed; the caller reads the element
    /// that follows. Empty content (the "no wrapper" answer) costs nothing: it
    /// only ever gets walked by callers dispatching on `peek_tag`.
    fn explicit(&mut self, n: u8) -> Result<Level> {
        let at = self.i;
        let (tag, level) = self.any()?;
        if tag == 0xa0 | n {
            return Ok(level);
        }
        // A primitive `80|n` is DER's `[n] IMPLICIT`: an EXPLICIT `[n]` around
        // a primitive type (an OCTET STRING, like the certificate bag's)
        // collides with exactly that tag — both spellings of an octet string
        // primitive are identical. The caller re-frames it as `0x04 <content>`
        // and reads the nesting inside, which is what OpenSSL's d2i does at
        // every one of these positions.
        if tag == 0x80 | n {
            return Ok(Level::owned(tlv_octet_string(&level.buf)));
        }
        self.i = at;
        Ok(Level::owned(Zeroizing::new(Vec::new())))
    }

    fn oid(&mut self) -> Result<ObjectIdentifier> {
        let (tag, level) = self.any()?;
        if tag != 0x06 {
            return Err(Error::Keystore(format!(
                "expected an OID in the PKCS#12, found tag {tag:#04x}"
            )));
        }
        ObjectIdentifier::from_bytes(level.bytes())
            .map_err(|e| Error::Keystore(format!("unreadable OID in the PKCS#12: {e}")))
    }

    fn number(&mut self) -> Result<usize> {
        // strict minimal-form INTEGER: the old reader's loop silently turned
        // `00 01` into 1 and accepted negative counts; DER allows neither, and
        // an iteration count is exactly where a hostile file lies
        let (tag, level) = self.any()?;
        let c = level.bytes();
        let bad =
            || Error::Keystore("an integer that is not a minimal non negative count".to_string());
        if tag != 0x02 {
            return Err(bad());
        }
        if c.is_empty()
            || c.len() > core::mem::size_of::<usize>()
            || (c[0] & 0x80 != 0)
            || (c[0] == 0 && c.get(1).is_some_and(|b| b & 0x80 == 0))
        {
            return Err(bad());
        }
        let mut n = 0usize;
        for b in c {
            n = (n << 8) | *b as usize;
        }
        Ok(n)
    }

    /// The next value's content, which must be a SET (0x31) — attribute
    /// containers in PKCS#12 are SET OF.
    fn expect_set(&mut self) -> Result<Level> {
        let (tag, level) = self.any()?;
        if tag != 0x31 {
            return Err(Error::Keystore(format!(
                "expected a SET in the PKCS#12, found tag {tag:#04x}"
            )));
        }
        Ok(level)
    }

    /// The next value's content as an owned buffer (payloads that travel to
    /// the decryptors and `assemble`).
    fn take_bytes(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        let (_, level) = self.any()?;
        Ok(level.buf)
    }

    /// The next value's tag plus its content as an owned buffer — EncryptedData
    /// dispatches on the implicit `[0]`'s tag and then keeps its bytes.
    fn take_bytes_with_tag(&mut self) -> Result<(u8, Zeroizing<Vec<u8>>)> {
        let (tag, level) = self.any()?;
        Ok((tag, level.buf))
    }

    /// Take this level's own bytes out (the level is done being read).
    fn into_level_bytes(self) -> Zeroizing<Vec<u8>> {
        self.buf
    }
}

/// A level over the container's bytes. One copy of the file at the top, which
/// is what removes the last lifetime question from this module: nothing here
/// ever addresses memory it does not own, so no `unsafe`, and every escape
/// hatch (`take_bytes`, `into_level_bytes`) hands out owned bytes anyway.
/// Containers are kilobytes; the copy is bounded by the file the caller
/// already handed over.
fn file_level(bytes: &[u8]) -> Level {
    Level::new(bytes)
}

/// The value a BER constructed OCTET STRING means: its chunks concatenated,
/// zeroized like whatever they were chunking. Chunks must be plain OCTET
/// STRINGs — anything else inside a `0x24` is the file lying about its shape.
/// The recursion owns each level's bytes, so nesting cannot run past the
/// buffer's size any more than the cursor's own checks allow.
fn join_constructed_octet_string(content: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut parts: Vec<u8> = Vec::with_capacity(content.len());
    let mut chunks = Level::new(content);
    while !chunks.is_done() {
        let (tag, chunk) = chunks.any()?;
        if tag != 0x04 {
            return Err(Error::Keystore(
                "a constructed OCTET STRING whose chunks are not plain \
                 OCTET STRINGs: malformed BER"
                    .into(),
            ));
        }
        parts.extend_from_slice(chunk.bytes());
    }
    Ok(Zeroizing::new(parts))
}

/// The inner value of `bytes` when the whole buffer is exactly one OCTET
/// STRING TLV (plain or BER constructed — `any()` reads both), and nothing
/// after it. `None` for anything else, including trailing bytes: those are a
/// real value, not a wrapper. This is OpenSSL's recursive `d2i_ASN1_TYPE` of
/// BER OCTET STRING chains, at the level granularity this reader keeps.
/// DER's `04 <len> <bytes>` header around content — the re-framing a primitive
/// implicit `[0]` needs before its nesting can be walked (see `explicit`).
fn tlv_octet_string(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = vec![0x04];
    if bytes.len() < 0x80 {
        out.push(bytes.len() as u8);
    } else {
        let len = bytes.len().to_be_bytes();
        let first = len.iter().position(|b| *b != 0).unwrap_or(len.len() - 1);
        out.push(0x80 | (len.len() - first) as u8);
        out.extend_from_slice(&len[first..]);
    }
    out.extend_from_slice(bytes);
    Zeroizing::new(out)
}

/// Concatenate every OCTET STRING element of `level`: DER's nested single one
/// (a primitive element whose content is another chain peels again through the
/// recursion in `any()`), BER's chunking of a constructed string, or any mix
/// the real writers use. Chunks must be OCTET STRINGs; another tag between
/// chunks means the file is lying about its shape.
fn join_octet_elements(mut level: Level) -> Result<Zeroizing<Vec<u8>>> {
    let mut parts: Vec<u8> = Vec::with_capacity(level.buf.len() - level.i);
    while !level.is_done() {
        let (tag, chunk) = level.any()?;
        if tag != 0x04 {
            return Err(Error::Keystore(format!(
                "an OCTET STRING that continues with tag {tag:#04x} instead of \
                 another chunk: malformed BER"
            )));
        }
        // DER nests an OCTET STRING inside one (OpenSSL 3 does it for the safe
        // bytes and the ciphertext alike). The bytes under a chunk are payload,
        // so they get read the way OpenSSL's d2i reads them: while the whole
        // of what is here is exactly one OCTET STRING element, its content is
        // what to keep. A chunking ends the loop instead — trailing siblings
        // mean these bytes are real data, not framing around more framing.
        let mut inner = chunk;
        loop {
            let peeled = {
                let mut probe = Level::new(inner.bytes());
                match (probe.any(), probe.is_done()) {
                    (Ok((0x04, next)), true) => Some(next),
                    _ => None,
                }
            };
            match peeled {
                Some(next) => inner = next,
                None => break,
            }
        }
        parts.extend_from_slice(inner.bytes());
    }
    Ok(Zeroizing::new(parts))
}

fn sequence_error(tag: u8) -> Error {
    Error::Keystore(format!(
        "expected a SEQUENCE in the PKCS#12, found tag {tag:#04x}. Re-export the \
         file with `openssl pkcs12 -in old.p12 -out new.p12` if it came from elsewhere"
    ))
}

// ---------------------------------------------------------------------------
// the container

struct MacData {
    digest_oid: ObjectIdentifier,
    digest: Vec<u8>,
    salt: Vec<u8>,
    iterations: usize,
}

/// The most key derivation iterations openfirma will run from a file's claim.
///
/// Real files ask for 2048 (openssl's default), 10 000 or 100 000 (Java's);
/// a paranoid re-export reaches a few million. Ten million is seconds of work
/// and covers everything legitimate, and it is what stops a 4 KB file that
/// claims a billion iterations from being an hour long denial of service.
const MAX_ITERATIONS: usize = 10_000_000;

/// Checks an iteration count the file declares, naming both the cause and the
/// way out, which is always a re-export through a tool that uses sane counts.
fn check_iterations(iterations: usize, what: &str) -> Result<()> {
    if iterations > MAX_ITERATIONS {
        return Err(Error::Keystore(format!(
            "the PKCS#12 asks for {iterations} {what} iterations, more than the \
             {MAX_ITERATIONS} openfirma accepts: the file is hostile or so old that \
             nothing wrote it that a current tool reads. Re-export it with \
             `openssl pkcs12 -in old.p12 -out new.p12`, which uses a sane count"
        )));
    }
    Ok(())
}

pub fn load(bytes: &[u8], password: &str) -> Result<Pkcs12> {
    let mut outer = file_level(bytes);
    let mut outer = outer.sequence()?;
    let version = outer.number()?;
    if version != 3 {
        return Err(Error::Keystore(format!(
            "PKCS#12 version {version}, only version 3 exists"
        )));
    }

    // authSafe: a ContentInfo whose content is the AuthenticatedSafe bytes.
    // It must be plain `data`: an EnvelopedData-authSafe container would mean
    // the whole safe is encrypted at the outer layer, which no writer emits.
    // The authSafe ContentInfo's content octets must be read *here*: a child
    // level borrowed from `outer` would go stale as soon as `outer` advances
    // to the MacData, and Rust rightly refuses that. One copy of one header's
    // worth of bytes buys a clean lifetime tree everywhere else.
    let mut auth_safe = outer.sequence()?;
    let auth_safe_type = auth_safe.oid()?;
    if auth_safe_type != OID_DATA {
        return Err(Error::Keystore(
            "the authenticated safe is not a plain data ContentInfo".into(),
        ));
    }
    // BER writes the `[0]` wrapper in its constructed form (OpenSSL 3 and NSS
    // emit `a0 82 … 24 82 … 00 00` — an indefinite [0] around a constructed
    // OCTET STRING whose chunks are plain ones), so the level under `[0]` may
    // hold OCTET STRING elements instead of being one. Their concatenation is
    // the AuthenticatedSafe's bytes, and DER's single nested OCTET STRING is
    // that same rule with one element.
    let wrapped = auth_safe.explicit(0)?;
    // The payload sits behind one of the shapes BER gives `[0] OCTET STRING`:
    // DER nests one OCTET STRING in it, OpenSSL 3 chunks a constructed one, and
    // NSS writes the safe SEQUENCE directly under the indefinite wrapper. What
    // tells them apart is only whether the content is framing at all: an
    // OCTET STRING element's bytes are payload material (joined below), any
    // other first element already IS the payload.
    // A DER nesting — the wrapper's whole content is exactly one OCTET STRING
    // element (the shape `explicit()` hands a primitive implicit `[0]` whose
    // content begins with `04 …`, and also a definite `a0 <n> 04 <n> …`)—peels
    // to the inner payload. Everything else under the wrapper is either one
    // constructed span (its join, through `any()`, *is* the payload) or a BER
    // chunking: walking every element and joining reads all three alike, and a
    // single-span nesting joins to itself minus its header, which is exactly
    // what peeling would return.
    // The elements' bytes concatenated are the payload in every shape — one
    // nested OCTET STRING joins to itself minus its header, a chunking joins
    // into its whole, and content that is not an OCTET STRING at all (NSS's
    // safe SEQUENCE directly under `[0]`) is already the payload. DER nests
    // OCTET STRINGs repeatedly inside the wrapper, so each join has to look
    // again: `join_constructed_octet_string`'s recursion does exactly that on
    // what an element's content holds, which is why every level under here is
    // walked with `.any()` and not a hand-written loop.
    let auth_safe_bytes = if matches!(wrapped.peek_tag(), Some(0x04) | Some(0x24)) {
        join_octet_elements(wrapped)?
    } else {
        wrapped.into_level_bytes()
    };

    if !outer.is_done() {
        let macs = read_macs(&mut outer)?;
        verify_mac(&macs, &auth_safe_bytes, password)?;
    }

    let mut certs: Vec<(Option<Vec<u8>>, Vec<u8>)> = Vec::new();
    let mut keys: Vec<FoundKey> = Vec::new();

    // the authenticated safe's bytes are now the input of a new level; it may
    // itself be BER inside (NSS nests its exports through `0x24` wrappers)
    let safe_bytes = Level::owned(auth_safe_bytes);
    // The AuthenticatedSafe is a SEQUENCE of ContentInfos. DER spells it with
    // a definite length, so peeling leaves the buffer holding one SEQUENCE and
    // its elements are what to walk; BER's indefinite form (`30 80 … 00 00`)
    // keeps the header in the stream, so peeling gives those ContentInfos with
    // the framing already gone — the same shape after one more peel. Probe for
    // "exactly one value fills the buffer" and descend if so; otherwise walk
    // the elements here. Both framings end up at the same list of ContentInfo
    // SEQUENCEs, which is all this loop reads.
    // A *constructed* single value is the SEQUENCE to descend; a primitive one
    // (a stray OCTET STRING nesting, say) would be framing to peel, and this
    // loop wants elements either way.
    let mut safe = {
        let mut probe = Level::new(safe_bytes.bytes());
        match probe.any() {
            Ok((tag, _)) if tag & 0x20 != 0 && probe.is_done() => {
                let mut one = Level::new(safe_bytes.bytes());
                one.any()?.1
            }
            _ => safe_bytes,
        }
    };
    while !safe.is_done() {
        let mut ci = safe.sequence()?;
        let content_type = ci.oid()?;
        let mut content = ci.explicit(0)?;
        // decrypted or not, a SafeContents can hold plain key bags, so it is
        // zeroized like the key material it may contain
        let safe_contents: Zeroizing<Vec<u8>> = if content_type == OID_DATA {
            // Same rule as the authSafe above: OCTET STRING elements under
            // `[0]` concatenate into the SafeContents bytes (`octets()` joins
            // them); NSS's indefinite `[0]` whose content begins with the
            // SafeContents SEQUENCE is that payload already, whole.
            let mut c = content;
            if matches!(c.peek_tag(), Some(0x04) | Some(0x24)) {
                c.octets()?.into_level_bytes()
            } else {
                c.into_level_bytes()
            }
        } else if content_type == OID_ENCRYPTED_DATA {
            decrypt_content_info(&mut content, password)?
        } else {
            return Err(Error::Keystore(format!(
                "unsupported ContentInfo in the authenticated safe: {content_type}"
            )));
        };
        let mut safe_level = Level::owned(safe_contents);
        let mut bags = safe_level.sequence()?;
        while !bags.is_done() {
            read_bag(&mut bags, password, &mut certs, &mut keys)?;
        }
    }

    Ok(Pkcs12 {
        entries: assemble(keys, certs)?,
    })
}

/// All MacData entries of the file. PKCS#12 allows several (one per MAC
/// algorithm/password pairing), and tools that carry more than one spelling
/// of the integrity check write them side by side; the first that verifies
/// with the given password wins.
fn read_macs(cur: &mut Level) -> Result<Vec<MacData>> {
    let mut out = Vec::new();
    while !cur.is_done() {
        let mut mac = cur.sequence()?;
        let mut digest_info = mac.sequence()?;
        let mut alg = digest_info.sequence()?;
        let digest_oid = alg.oid()?;
        // AlgorithmIdentifier parameters: absent, NULL, or (rare) absent-by-
        // convention; consume whatever is there without demanding a shape.
        if !alg.is_done() {
            let _ = alg.take_bytes()?;
        }
        let digest = digest_info.octets()?.into_level_bytes().to_vec();
        let salt = mac.octets()?.into_level_bytes().to_vec();
        // iterations defaults to 1 when absent, per the specification
        let iterations = if mac.is_done() { 1 } else { mac.number()? };
        check_iterations(iterations, "MAC")?;
        out.push(MacData {
            digest_oid,
            digest,
            salt,
            iterations,
        });
    }
    if out.is_empty() {
        return Err(Error::Keystore(
            "a PKCS#12 whose MacData section is empty cannot be checked".into(),
        ));
    }
    Ok(out)
}

/// The MAC is the password check. Doing it first means a wrong password is
/// reported as a wrong password, not as padding garbage three layers down.
/// Several MacData entries verify independently; one match is integrity.
fn verify_mac(macs: &[MacData], auth_safe: &[u8], password: &str) -> Result<()> {
    // The MAC keeps the strict PKCS#12 rule — BMPString, `00 00` for the empty
    // password on OpenSSL/NSS, no bytes at all on Java (review 04, A3). Both
    // spellings are tried; a wrong password pays two extra HMACs, nothing else
    // does. The bags do NOT have to agree with this choice: OpenSSL 3.x keys
    // PBES2's PBKDF2 over raw UTF-8 while the MAC stays BMP (see
    // `password_candidates`), which is exactly why verify_mac succeeding and a
    // bag refusing to decrypt were both true for an openssl-exported file.
    for pw in &mac_password_candidates(password) {
        for mac in macs {
            if check_one_mac(mac, auth_safe, pw) {
                return Ok(());
            }
        }
    }
    Err(Error::Keystore(
        "the PKCS#12 integrity check failed: wrong password, or the file was \
         tampered with"
            .into(),
    ))
}

/// The spellings a MAC (or a legacy SHA-1 PBE) can be keyed with. PKCS#12's
/// own rule — BMPString — plus what the field actually wrote down:
///
/// - Java writes zero BMP chars for the empty password; OpenSSL and NSS
///   write its terminator (`00 00`). Both spellings of "" are candidates.
/// - OpenSSL 3.x feeds PBKDF2 (and, per RFC 9579's errata, PBMAC1) the raw
///   UTF-8 bytes of the password with no NUL terminator; its own reader is
///   built to open such files. The raw spelling is a candidate too — ded-up
///   when it coincides with one already tried (a non-empty ASCII password's
///   BMP spelling differs from raw, ""'s raw spelling is its empty spelling).
///
/// The legacy SHA-1 PBEs share this list: OpenSSL 3.x encrypts them with the
/// same BMP+terminator it uses for the MAC, while NSS and OpenSSL < 3 agree
/// there; nothing in the field keys those with raw bytes.
fn mac_password_candidates(password: &str) -> Vec<Zeroizing<Vec<u8>>> {
    let mut out = Vec::with_capacity(4);
    // PKCS#12's own rule for the empty password — zero BMP chars — goes first:
    // it is the spelling of the specification and of Java, and only "" makes
    // it differ from every other writer's terminator.
    if password.is_empty() {
        out.push(Zeroizing::new(Vec::new()));
    }
    // BMP+terminator: what OpenSSL/NSS key with, empty included — for "" that
    // is the terminator alone, `00 00`, which `bmp_password` deliberately does
    // not return (its empty spelling follows the PKCS#12 rule Java uses). For
    // a non-empty password no other spelling collides with it.
    let bmp = if password.is_empty() {
        Zeroizing::new(vec![0u8, 0u8])
    } else {
        bmp_password(password)
    };
    if !out.iter().any(|c| **c == **bmp) {
        out.push(bmp);
    }
    let raw = Zeroizing::new(password.as_bytes().to_vec());
    if !out.iter().any(|c| **c == **raw) {
        out.push(raw);
    }
    out
}

/// The spellings a bag-level PBES2 PBKDF2 can be keyed with: the MAC list,
/// plus the NUL-terminated raw bytes that is OpenSSL 3.x's actual PBKDF2
/// input (see `pbes2_password_candidates`). It must NOT be the MAC list
/// verbatim — an empty password derives its bag keys from `00 00` (the BMP
/// terminator), not from nothing, and a container whose MAC verifies under
/// Java's zero-byte spelling still decrypts its bags with OpenSSL's two.
fn pbes2_password_candidates(password: &str) -> Vec<Zeroizing<Vec<u8>>> {
    // A bag's PBES2 can be keyed with any spelling of the family, including
    // one its MAC does not use; the padding check at the end of decryption is
    // the verdict. Order by who writes what today (OpenSSL 3's NUL-terminated
    // raw bytes and Java's terminator-less BMP first, BMP+terminator next),
    // then everything deduplicated that a real file has ever been caught
    // using — wrong spellings only cost one failed derivation on the path to
    // the right one.
    let mut out: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(5);
    let push = |out: &mut Vec<Zeroizing<Vec<u8>>>, v: Vec<u8>| {
        let z = Zeroizing::new(v);
        if !out.iter().any(|c| **c == **z) {
            out.push(z);
        }
    };
    // OpenSSL 3.x's PBKDF2 input: raw UTF-8 with a NUL terminator (and for ""
    // the two-byte `00 00`). Java 8+'s PBES2 writer hashes its BMP WITHOUT a
    // terminator; keytool's MAC may verify under either, so both carry bags.
    let mut nul = password.as_bytes().to_vec();
    nul.extend_from_slice(&[0u8; 2]);
    push(&mut out, nul);
    if !password.is_empty() {
        let mut v = Vec::with_capacity(password.len() * 2);
        for unit in password.encode_utf16() {
            v.extend_from_slice(&unit.to_be_bytes());
        }
        push(&mut out, v);
    } else {
        // "" as BMP+terminator — OpenSSL's own spelling, which keytool and
        // pk12util use when they write the bags at all.
        push(&mut out, vec![0u8, 0u8]);
    }
    for c in mac_password_candidates(password) {
        push(&mut out, c.to_vec());
    }
    out
}

fn check_one_mac(mac: &MacData, auth_safe: &[u8], pw: &[u8]) -> bool {
    // instantiated per hash rather than generic over it: Hmac's bounds in this
    // digest generation are a thicket, and there are exactly five hashes a
    // PKCS#12 MAC can use (MD5 the legacy one)
    macro_rules! check {
        ($d:ty, $v:expr) => {{
            let key = pkcs12_kdf::<$d>(
                3,
                pw,
                &mac.salt,
                mac.iterations,
                <$d as Digest>::output_size(),
                $v,
            );
            let mut m = match <Hmac<$d> as KeyInit>::new_from_slice(&key) {
                Ok(m) => m,
                Err(_) => return false,
            };
            m.update(auth_safe);
            // constant time: the MAC is compared before the password is known
            // to be right, so an early exit here would leak it digest byte by
            // digest byte to anyone who can hand us files and watch the time
            let computed = m.finalize().into_bytes();
            bool::from(mac.digest.as_slice().ct_eq(computed.as_slice()))
        }};
    }
    match mac.digest_oid {
        // MD5 is here to READ legacy containers, never to write one, and it is
        // a password check like the others: what it protects is not a trust
        // decision. openssl opens these files (with `-legacy`); refusing them as
        // a wrong password sent people to re-export a container that was fine.
        OID_MD5 => check!(md5::Md5, 64),
        OID_SHA1 => check!(sha1::Sha1, 64),
        OID_SHA256 => check!(sha2::Sha256, 64),
        OID_SHA384 => check!(sha2::Sha384, 128),
        OID_SHA512 => check!(sha2::Sha512, 128),
        // PBMAC1 (RFC 9579) integrity keeps the *bag* MACs inside a different
        // scheme; rare in the wild. Named refusal beats a wrong-password lie.
        other => {
            tracing::debug!("unsupported PKCS#12 MAC digest {other}");
            false
        }
    }
}

/// The password as PKCS#12's own rule wants it: UTF-16BE with a two byte zero
/// terminator; an empty password is the empty string (Java writes exactly
/// that, and the OpenSSL/NSS `00 00` spelling travels as its own candidate —
/// see [`mac_password_candidates`]).
fn bmp_password(password: &str) -> Zeroizing<Vec<u8>> {
    if password.is_empty() {
        return Zeroizing::new(Vec::new());
    }
    let mut out = Vec::with_capacity(password.len() * 2 + 2);
    for unit in password.encode_utf16() {
        out.extend_from_slice(&unit.to_be_bytes());
    }
    out.extend_from_slice(&[0, 0]);
    Zeroizing::new(out)
}

/// One bag-level decryption attempt with every plausible empty-password
/// encoding: try each until padding accepts the result. A non-empty password
/// is one candidate, so this costs nothing on the common path.
fn decrypt_pbe_all(
    alg: ObjectIdentifier,
    params: &[u8],
    encrypted: &[u8],
    password: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut last: Option<Error> = None;
    // Bag keys split into writer families (see `pbes2_password_candidates`):
    // PBES2 gets every spelling (OpenSSL 3.x's raw-UTF-8 PBKDF2 is not the BMP
    // one Java writes), while the legacy SHA-1 PBEs have always been keyed over
    // the BMPString, so trying more there would only slow a wrong password
    // down.
    let candidates = if alg == OID_PBES2 {
        pbes2_password_candidates(password)
    } else {
        mac_password_candidates(password)
    };
    // The padding check alone is NOT a safe verdict: with an 8-byte block
    // cipher (3DES) a wrong candidate's garbage passes PKCS#7 padding by
    // chance roughly once in 256 — measured here as a ~1/117 flake over
    // random-salts, where the empty spelling was tried first, its garbage
    // passed padding, and the correct `00 00` candidate was never reached
    // (the caller then died reading that garbage as DER). What every PKCS#12
    // decryption produces IS DER — a SafeContents SEQUENCE for the content
    // info, a PKCS#8 PrivateKeyInfo for a key bag — so a candidate is only
    // accepted when its plaintext is a complete, well-formed DER SEQUENCE.
    // The first candidate that is BOTH padding-valid and a whole SEQUENCE
    // wins; a padding-valid result that is not DER is remembered only as a
    // fallback, so the old behaviour survives for any input that could
    // legitimately decrypt to something this check reads as non-DER (none is
    // known, but the fallback keeps the change strictly additive).
    let mut padding_only: Option<Zeroizing<Vec<u8>>> = None;
    for pw in &candidates {
        match decrypt_pbe(alg, params, encrypted, pw) {
            Ok(v) if is_whole_der_sequence(&v) => return Ok(v),
            Ok(v) => {
                if padding_only.is_none() {
                    padding_only = Some(v);
                }
            }
            Err(e) => last = Some(e),
        }
    }
    if let Some(v) = padding_only {
        return Ok(v);
    }
    Err(last.expect("password candidates are never empty"))
}

/// Whether `bytes` is exactly one DER SEQUENCE and nothing else — the shape
/// every decrypted PKCS#12 payload has. Strict: an indefinite length or any
/// trailing byte fails it, which is what tells a genuine plaintext from a
/// wrong key whose garbage happened to satisfy the block padding.
fn is_whole_der_sequence(bytes: &[u8]) -> bool {
    let mut c = openfirma_core::tlv::Cursor::new(bytes);
    match c.value() {
        Ok(v) => v.tag == 0x30 && v.whole.len() == bytes.len() && c.done(),
        Err(_) => false,
    }
}

fn decrypt_content_info(content: &mut Level, password: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut ed = content.sequence()?;
    let _version = ed.number()?;
    let mut eci = ed.sequence()?;
    let _content_type = eci.oid()?;
    let (alg_oid, params) = read_algorithm(&mut eci)?;
    // [0] IMPLICIT OCTET STRING. Its shapes carry the ciphertext in different
    // places, and one rule reads them all: under a *constructed* wrapper (the
    // BER form `a0 80 …` or `a0 <n> …`, which NSS and OpenSSL 3 use), join the
    // bytes of every OCTET STRING element — NSS chunks the ciphertext itself
    // into consecutive `04` elements whose concatenation IS the ciphertext,
    // and OpenSSL 3 wraps it in one nested OCTET STRING, which joins to itself
    // minus its header. A primitive wrapper (`80 <n> <cipher>`, DER's implicit
    // form) carries the ciphertext as-is. Taking a first chunk alone is
    // reading a truncated file; that mistake was exactly what made an NSS
    // export's padding refuse to validate.
    let (tag, encrypted) = if eci.peek_tag() == Some(0xa0) {
        (0x80u8, join_octet_elements(eci.explicit(0)?)?)
    } else {
        eci.take_bytes_with_tag()?
    };
    if !matches!(tag, 0x80 | 0xa0 | 0x04) {
        return Err(Error::Keystore(format!(
            "the encrypted content carries tag {tag:#04x}, expected the implicit [0]              octet string (0x80)"
        )));
    }
    decrypt_pbe_all(alg_oid, &params, &encrypted, password)
}

fn read_bag(
    cur: &mut Level,
    password: &str,
    certs: &mut Vec<(Option<Vec<u8>>, Vec<u8>)>,
    keys: &mut Vec<FoundKey>,
) -> Result<()> {
    let mut bag = cur.sequence()?;
    let bag_id = bag.oid()?;
    let mut value = bag.explicit(0)?;
    let (alias, local_key_id) = if bag.is_done() {
        (None, None)
    } else {
        read_attributes(&mut bag)?
    };

    match bag_id {
        OID_CERT_BAG => {
            let mut cb = value.sequence()?;
            let cert_type = cb.oid()?;
            if cert_type != OID_X509_CERTIFICATE {
                return Err(Error::Keystore(format!(
                    "certificate bag of type {cert_type}; only X.509 certificates are supported"
                )));
            }
            // [0] EXPLICIT around the certificate's OCTET STRING, in every
            // framing: DER nests one OCTET STRING (`a0 <n> 04 <n>`), OpenSSL 3
            // and NSS chunk a constructed one (`a0 80 …`), and both spellings
            // of `X509Certificate ::= OCTET STRING DER ENCODED` mean the same
            // bytes. Joining every OCTET STRING element under the wrapper
            // reads all of them; a wrapper holding no OCTET STRING (NSS puts
            // the certificate SEQUENCE directly under `[0]`) is already the
            // certificate whole.
            // A definite-length `[0]` always wraps something, so its content
            // is what gets read. A *primitive* value here (tag 0x80 — OpenSSL
            // 3 writes a cert bag `a0 <n> 80 <n> …`) collides with DER's
            // implicit form of the same number and means the same bytes: it is
            // already an OCTET STRING element to join, not a wrapper. NSS
            // leaves the certificate SEQUENCE directly under its indefinite
            // `[0]`, which `explicit()` hands out as content to take whole.
            let wrapped = cb.explicit(0)?;
            let der = if matches!(wrapped.peek_tag(), Some(0x04)) {
                join_octet_elements(wrapped)?.to_vec()
            } else {
                wrapped.into_level_bytes().to_vec()
            };
            certs.push((local_key_id, der));
        }
        OID_SHROUDED_KEY_BAG => {
            let mut eki = value.sequence()?;
            let (alg_oid, params) = read_algorithm(&mut eki)?;
            let encrypted = eki.octets()?.into_level_bytes();
            let pkcs8 = decrypt_pbe_all(alg_oid, &params, &encrypted, password)?;
            keys.push((local_key_id, alias, pkcs8));
        }
        OID_KEY_BAG => {
            keys.push((local_key_id, alias, value.into_level_bytes()));
        }
        OID_SAFE_CONTENTS_BAG => {
            let mut inner = value.sequence()?;
            while !inner.is_done() {
                read_bag(&mut inner, password, certs, keys)?;
            }
        }
        other => tracing::debug!("ignoring PKCS#12 bag of type {other}"),
    }
    Ok(())
}

fn read_attributes(cur: &mut Level) -> Result<(Option<String>, Option<Vec<u8>>)> {
    let mut attrs = cur.expect_set()?;
    let mut alias = None;
    let mut local_key_id = None;
    while !attrs.is_done() {
        let mut attr = attrs.sequence()?;
        let id = attr.oid()?;
        let mut values = attr.expect_set()?;
        match id {
            OID_FRIENDLY_NAME => {
                // BMPString (0x1e); other string forms mean the file is not
                // PKCS#12 as written
                let (tag, raw) = values.take_bytes_with_tag()?;
                if tag != 0x1e {
                    return Err(Error::Keystore(format!(
                        "a friendlyName encoded as tag {tag:#04x} instead of BMPString"
                    )));
                }
                alias = Some(bmp_string(&raw)?);
            }
            OID_LOCAL_KEY_ID => local_key_id = Some(values.octets()?.into_level_bytes().to_vec()),
            _ => {}
        }
    }
    Ok((alias, local_key_id))
}

/// A BMPString is UTF-16BE, which is also how PKCS#12 encodes the password.
///
/// Decoded strictly: the lossy variant turns an unpaired surrogate into a
/// replacement character, and an alias that silently differs from the one the
/// file carries makes `--alias` fail with "no entry named" for an entry that
/// is plainly there.
fn bmp_string(bytes: &[u8]) -> Result<String> {
    if bytes.len() % 2 != 0 {
        return Err(Error::Keystore(format!(
            "a BMPString with an odd number of bytes ({}) cannot be UTF-16",
            bytes.len()
        )));
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&units).map_err(|_| {
        Error::Keystore(
            "the PKCS#12 carries a BMPString that is not valid UTF-16 (an unpaired \
             surrogate): the alias, or the password on the tool that wrote the file, \
             contains non-ASCII characters this reader cannot represent. Re-export the \
             container with an ASCII alias: `openssl pkcs12 -in old.p12 -out new.p12`"
                .into(),
        )
    })
}

// ---------------------------------------------------------------------------
// key derivation and decryption

/// The PKCS#12 key derivation of RFC 7292 appendix B.2, used for the MAC key
/// and for the legacy SHA-1 PBE schemes. It is not PBKDF2 and the two are not
/// interchangeable, which is the usual way this goes wrong.
/// `block_size` is passed in rather than taken from a trait bound: in this
/// digest generation the block size lives on `BlockSizeUser`, which is not
/// re-exported at the crate root, and it is a constant per hash anyway, 64 for
/// SHA-1 and SHA-256, 128 for SHA-384 and SHA-512.
fn pkcs12_kdf<D: Digest>(
    id: u8,
    password: &[u8],
    salt: &[u8],
    iterations: usize,
    out_len: usize,
    block_size: usize,
) -> Zeroizing<Vec<u8>> {
    let v = block_size;
    let u = <D as Digest>::output_size();
    let d = vec![id; v];
    // The folded I block holds the repeated salt AND the repeated password, so
    // it is key material like the output and gets zeroed the same way — which
    // means the repeats themselves must be `Zeroizing` too (finding B1): a
    // plain Vec here used to leave the password repeated four times per block
    // in freed allocator memory.
    let repeat = |src: &[u8]| -> Zeroizing<Vec<u8>> {
        if src.is_empty() {
            return Zeroizing::new(Vec::new());
        }
        let n = v * src.len().div_ceil(v);
        Zeroizing::new((0..n).map(|i| src[i % src.len()]).collect())
    };
    let mut i = repeat(salt);
    let pw_repeat = repeat(password);
    // `extend_from_slice` copies from a Zeroizing buffer whose copy lives in
    // `i` and zeroes with it.
    i.extend_from_slice(&pw_repeat);

    let mut out = Zeroizing::new(Vec::with_capacity(out_len + u));
    for round in 0..out_len.div_ceil(u) {
        let mut h = D::new();
        h.update(&d);
        h.update(&i);
        // the intermediate digest `a` is derived from password material, so it
        // travels zeroized (the block A that B is built from feeds every later
        // round of I)
        let mut a: Zeroizing<Vec<u8>> = Zeroizing::new(h.finalize().to_vec());
        for _ in 1..iterations {
            let mut round = D::new();
            round.update(&a);
            a = Zeroizing::new(round.finalize().to_vec());
        }
        if round + 1 < out_len.div_ceil(u) {
            // fold A back into I: every v byte block of I becomes I + B + 1,
            // B being A repeated to v bytes, as a big endian addition
            let mut b: Vec<u8> = (0..v).map(|j| a[j % u]).collect();
            for block in i.chunks_mut(v) {
                let mut carry = 1u16;
                for j in (0..v).rev() {
                    let sum = u16::from(block[j]) + u16::from(b[j]) + carry;
                    block[j] = sum as u8;
                    carry = sum >> 8;
                }
            }
            b.zeroize();
        }
        out.extend_from_slice(&a);
    }
    out.truncate(out_len);
    out
}

/// An `AlgorithmIdentifier`, returning the OID and the raw content of its
/// parameters SEQUENCE, which is all the decryption schemes need.
fn read_algorithm(cur: &mut Level) -> Result<(ObjectIdentifier, Vec<u8>)> {
    let mut ai = cur.sequence()?;
    let oid = ai.oid()?;
    let params = if ai.is_done() {
        Vec::new()
    } else {
        ai.take_bytes()?.to_vec()
    };
    Ok((oid, params))
}

pub(crate) fn decrypt_pbe(
    alg: ObjectIdentifier,
    params: &[u8],
    encrypted: &[u8],
    pw: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    match alg {
        OID_PBES2 => decrypt_pbes2(params, encrypted, pw),
        OID_PBE_SHA1_3DES | OID_PBE_SHA1_RC2_40 => {
            // The two legacy SHA-1 PBEs share everything but the cipher: salt,
            // iterations, and a key/IV derived with ids 1 and 2 of the same
            // KDF. RC2 uses a 5-byte (40-bit) key; 3DES its full 24.
            let mut p = Level::new(params);
            let salt = p.octets()?.into_level_bytes().to_vec();
            let iterations = p.number()?;
            check_iterations(iterations, "key derivation")?;
            if alg == OID_PBE_SHA1_RC2_40 {
                let key = pkcs12_kdf::<sha1::Sha1>(1, pw, &salt, iterations, 5, 64);
                let iv = pkcs12_kdf::<sha1::Sha1>(2, pw, &salt, iterations, 8, 64);
                cbc_decrypt::<rc2::Rc2>(&key, &iv, encrypted)
            } else {
                let key = pkcs12_kdf::<sha1::Sha1>(1, pw, &salt, iterations, 24, 64);
                let iv = pkcs12_kdf::<sha1::Sha1>(2, pw, &salt, iterations, 8, 64);
                cbc_decrypt::<des::TdesEde3>(&key, &iv, encrypted)
            }
        }
        OID_PBMAC1 => Err(Error::Keystore(
            "this PKCS#12 is protected with PBMAC1 (RFC 9579), which openfirma does not \
             implement yet; re-export it with `openssl pkcs12 -in old.p12 -out new.p12` \
             (without -pbmac1_* options)"
                .into(),
        )),
        other => Err(Error::Keystore(format!(
            "unsupported PKCS#12 encryption scheme {other}"
        ))),
    }
}

/// PBKDF2 counts rounds in a u32. A file claiming more is not a file, it is a
/// denial of service, and so is one claiming millions of millions within what
/// the format can express: both stop at [`MAX_ITERATIONS`].
fn rounds(iterations: usize) -> Result<u32> {
    check_iterations(iterations, "PBKDF2")?;
    u32::try_from(iterations).map_err(|_| {
        Error::Keystore(format!(
            "{iterations} PBKDF2 rounds is beyond what the format can express"
        ))
    })
}

/// The raw password bytes PBKDF2 is keyed with. PKCS#12 passwords are UTF-16BE
/// with a terminator; for the MAC the KDF takes them BMP-encoded (the caller's
/// `pw`), and for PBKDF2 too — Java hashes exactly those bytes, without a
/// trailing NUL beyond what pw already carries. Passing `pw` verbatim is what
/// both Java and OpenSSL compute; the empty password reaches this point in
/// whichever of the two spellings verified the MAC (decrypt_password).
fn decrypt_pbes2(params: &[u8], encrypted: &[u8], pw: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    // PBES2-params ::= SEQUENCE { keyDerivationFunc AlgorithmIdentifier,
    //                              encryptionScheme AlgorithmIdentifier }.
    // Each identifier is a full SEQUENCE; each child level is its content.
    // `params` is the CONTENT of PBES2-params, whose children are the two
    // identifier SEQUENCEs directly.
    // `any()` on the params CONTENT hands out each identifier's content bytes:
    // exactly what read_algorithm reads from (its argument is a level over an
    // AlgorithmIdentifier's CONTENT, not its TLV). RC2-CBC's RFC 7539 IV rides
    // an implicit `[0]` INTEGER inside that content and stays a plain element
    // of it, where `peek_tag()` below can dispatch on it.
    let mut ident = Level::new(params);
    let mut kdf_level = ident.any()?.1;
    let kdf_oid = kdf_level.oid()?;
    let kdf_params = if kdf_level.is_done() {
        return Err(Error::Keystore(
            "a PBES2 key derivation function without parameters".into(),
        ));
    } else {
        kdf_level.take_bytes()?.to_vec()
    };
    if kdf_oid != OID_PBKDF2 {
        return Err(Error::Keystore(format!(
            "PBES2 with a key derivation function that is not PBKDF2: {kdf_oid}"
        )));
    }
    let mut enc_level = ident.any()?.1;
    // encryptionScheme's parameters are the IV: an OCTET STRING for AES and
    // 3DES, but RC2-CBC's (RFC 7539) is an INTEGER — big endian, leading sign
    // zero possible. Read whichever of the two the next tag actually is.
    // RFC 7539 defines RC2-CBC's parameters as the OCTET STRING IV *wrapped in
    // a SEQUENCE* (`SEQUENCE { iv }`), and OpenSSL writes exactly that; the
    // bare-OCTET-STRING spelling shows up in files from other tools too. Walk
    // inside the SEQUENCE when there is one before demanding the bytes.
    let enc_oid = enc_level.oid()?;
    // RFC 7539's `RC2-CBC-params ::= SEQUENCE { iv OCTET STRING,
    // rc2EffectiveKeyLength [0] IMPLICIT INTEGER OPTIONAL }`: OpenSSL writes
    // the IV first, so a `[0]` after it is always that implicit INTEGER (the
    // byte 0x82 for a two-byte value). The strength gets read and checked, not
    // skipped — a file whose key-strength fields disagree describes two
    // different ciphers, and guessing one turns a lying container into
    // plaintext nobody can vouch for. RC2-40 means the 5-byte key every recipe
    // in the field derives; absent, RC2 runs at its full block width.
    // RFC 7539 puts two fields inside RC2-CBC's parameters SEQUENCE: the OCTET
    // STRING IV and an optional `rc2EffectiveKeyLength`. OpenSSL writes that
    // one *wrong* against its own RFC — as a plain INTEGER carrying the number
    // of KEY BYTES, not bits (`02 02 00 a0` beside a 5-byte PBKDF2 keyLength:
    // 5 bytes ⇒ RC2-40), and every legacy PKCS#12 in the field carries that
    // spelling. Read by tag and scale accordingly; an explicit `[0]` (`a2 …`,
    // what OpenSSL itself parses back per its RFC table) is accepted too. The
    // strength must agree with the PBKDF2 key length below — a file whose two
    // strength fields disagree names two different ciphers.
    let mut iv_level = if enc_level.peek_tag() == Some(0x30) {
        enc_level.sequence()?
    } else {
        enc_level
    };
    let mut declared_bits = 128usize;
    fn read_efcl(level: &mut Level) -> Result<usize> {
        // RFC 7539 defines it as `[0] IMPLICIT INTEGER`, which OpenSSL writes
        // as a bare INTEGER *in key bytes* (`02 02 00 a0` = 20 key bytes ⇒ the
        // same RC2-40 recipe that derives a 5-byte PBKDF2 key: RFC 7539's own
        // table maps a 20-byte field to effective 40 bits, and the byte-scale
        // spelling is what every file in the field carries). Accept both the
        // byte spelling and an explicit/implicit `[0]`; scale bytes to bits by
        // RFC 7539's mapping (`<= 128` means bytes because no effective length
        // above a block is ever expressed in them, and 255 marks "full").
        let (tag, l) = level.any()?;
        let mut inner = if tag == 0x02 {
            l
        } else if matches!(l.peek_tag(), Some(0x02)) {
            // explicit [0] around a real INTEGER: peel one level
            l
        } else {
            return Err(Error::Keystore(format!(
                "an RC2-CBC effective key length with tag {tag:#04x} that is not \
                 an integer"
            )));
        };
        let v = if matches!(inner.peek_tag(), Some(0x02)) {
            inner.number()?
        } else {
            let c = inner.bytes();
            if c.is_empty() || c[0] & 0x80 != 0 {
                return Err(Error::Keystore(
                    "an RC2-CBC effective key length that is not a non negative \
                     integer"
                        .into(),
                ));
            }
            let mut n = 0usize;
            for b in c {
                n = (n << 8) | *b as usize;
            }
            n
        };
        // Scale by magnitude, which is the only reading that keeps both real
        // spellings: a field at or below the RFC's own table bound (128) in
        // the byte scale OpenSSL writes says "this many key bytes" — 5 is how
        // RC2-40 got written before anyone normalized — while anything above
        // it speaks bits, and the block-max 128 stays full width. The values
        // in between (an RFC-conforming bit count like 40) are their own scale
        // by context: at most `key_len*8` can be effective anyway, and below
        // this function's caller checks exactly that against the derived key.
        Ok(match v {
            0 => {
                return Err(Error::Keystore(
                    "an RC2-CBC effective key length of zero".into(),
                ));
            }
            v if v <= 16 => v * 8,
            v if v <= 128 => v,
            _ => 128,
        })
    }
    let mut iv = None;
    while !iv_level.is_done() {
        match iv_level.peek_tag() {
            // 0xa0 is OpenSSL's `[0]` around the INTEGER — a tag the IV can
            // never carry, so dispatching on it cannot misread anything else.
            Some(0x04) => iv = Some(iv_level.octets()?.into_level_bytes().to_vec()),
            Some(0x82) | Some(0xa2) | Some(0xa0) | Some(0x02) => {
                declared_bits = read_efcl(&mut iv_level)?;
            }
            Some(tag) => {
                return Err(Error::Keystore(format!(
                    "an RC2-CBC parameter with tag {tag:#04x}, where RFC 7539 \
                     puts only the IV and the effective key length"
                )));
            }
            None => break,
        }
    }
    let iv = iv.ok_or_else(|| Error::Keystore("RC2-CBC parameters without an IV".to_string()))?;
    let kdf_params = Level::new(&kdf_params);

    let mut kp = kdf_params;
    let salt = kp.octets()?.into_level_bytes().to_vec();
    let iterations = kp.number()?;
    // `keyLength` is the optional INTEGER Java 11+ writes after the iteration
    // count (finding A1). It is not ignored blindly: when present it must name
    // a key length this cipher knows, because a file that says "32" over AES-
    // 128 is lying about its parameters and deriving with the wrong length is
    // exactly how a hostile container gets garbage accepted as plaintext.
    let key_len = match enc_oid {
        OID_AES128_CBC => 16,
        OID_AES192_CBC => 24,
        OID_AES256_CBC => 32,
        OID_DES_EDE3_CBC => 24,
        // RC2 in PBES2 carries its strength in the PBKDF2 keyLength, and every
        // writer in the field that means "RC2-40" declares 5 (OpenSSL's own:
        // `openssl pkcs12 -certpbe RC2-40-CBC`). The cipher accepts any key
        // length the crate exposes — 5 is what the recipe means and verifies.
        OID_RC2_CBC => 5,
        other => {
            return Err(Error::Keystore(format!(
                "PBES2 with cipher {other}, only AES-CBC and 3DES-CBC are supported"
            )));
        }
    };
    // PKCS#5 v2's PBKDF2-params is `SEQUENCE { salt, iterationCount,
    // keyLength OPTIONAL, prf OPTIONAL AlgorithmIdentifier }`, and the two
    // optionals are positionally ambiguous: OpenSSL 3 writes `prf` and omits
    // `keyLength`, Java 11+ writes `keyLength`, and a keyLength alone is a
    // bare INTEGER while a prf is always a SEQUENCE. Tag dispatch on the next
    // value reads either spelling — treating any non-INTEGER as "no keyLength"
    // was how this file opened OpenSSL's exports before finding A1, and it is
    // what keeps them opening now.
    if kp.peek_tag() == Some(0x02) {
        let declared = kp.number()?;
        // Java's own PBKDF2 encoder writes the key length in **bytes** (its
        // `keyLength` is the derived-key array size), and RFC 8018 says nothing
        // about units. The one honest reading that keeps both the fix's purpose
        // and real files open: accept the byte spelling — what every writer in
        // the field emits — and refuse anything else, naming both values,
        // because silently truncating or extending a declared key length is
        // how a hostile container gets garbage accepted as plaintext.
        if declared != key_len {
            return Err(Error::Keystore(format!(
                "the PKCS#12 declares a PBKDF2 keyLength of {declared} for a cipher \
                 with a {key_len} byte key: its parameters disagree with themselves. \
                 Re-export it with `openssl pkcs12 -in old.p12 -out new.p12`"
            )));
        }
    }
    // the PRF, optional and HMAC-SHA-1 by default (RFC 8018 + RFC 7292's use)
    let prf = if kp.is_done() {
        OID_HMAC_SHA1
    } else {
        let mut ai = kp.sequence()?;
        ai.oid()?
    };

    // The PBKDF2 output lives in a plain buffer on purpose: this key is a few
    // instructions from being consumed by the cipher below, whose own copies
    // zeroize with it, and the frame ends right after them. (A `Zeroizing`
    // destination was tried first here; with zeroize's Vec-on-drop behaviour
    // on this toolchain, PBKDF2's intermediate moves inside pbkdf2_hmac
    // cleared such buffers before they could be used. Kept out of the way in a
    // plain `Vec`, and the key material that escapes — none here — travels in
    // Zeroizing everywhere else.)
    let mut key = vec![0u8; key_len];
    match prf {
        OID_HMAC_SHA1 => {
            pbkdf2::pbkdf2_hmac::<sha1::Sha1>(pw, &salt, rounds(iterations)?, &mut key)
        }
        OID_HMAC_SHA256 => {
            pbkdf2::pbkdf2_hmac::<sha2::Sha256>(pw, &salt, rounds(iterations)?, &mut key)
        }
        OID_HMAC_SHA384 => {
            pbkdf2::pbkdf2_hmac::<sha2::Sha384>(pw, &salt, rounds(iterations)?, &mut key)
        }
        OID_HMAC_SHA512 => {
            pbkdf2::pbkdf2_hmac::<sha2::Sha512>(pw, &salt, rounds(iterations)?, &mut key)
        }
        other => {
            return Err(Error::Keystore(format!(
                "PBKDF2 with PRF {other}, only the SHA family is supported"
            )));
        }
    }
    // RC2 carries its strength twice — in the PBKDF2 key length and in RFC
    // 7539's optional effective-bits field — and the two must describe one
    // cipher. A derived key of N bytes runs at min(N*8, declared) bits; the
    // default when no effective length is stated is full width (128). The one
    // real-world exception is OpenSSL's RC2-40 recipe, which leaves 128 as the
    // RFC default while deriving a 5-byte key: with a key shorter than the
    // block, RC2 runs at the key's width, so full-width claims are vacuous and
    // only a *narrower* contradiction — an effective length that does not match
    // the derived key — is refused.
    if enc_oid == OID_RC2_CBC && declared_bits != 128 && declared_bits != key_len * 8 {
        return Err(Error::Keystore(format!(
            "RC2-CBC declares an effective key length of {declared_bits} bits over \
             a PBKDF2 key of {} bytes: its parameters name two different ciphers. \
             Re-export the file with `openssl pkcs12 -in old.p12 -out new.p12`",
            key_len
        )));
    }

    match enc_oid {
        OID_AES128_CBC => cbc_decrypt::<aes::Aes128>(&key, &iv, encrypted),
        OID_AES192_CBC => cbc_decrypt::<aes::Aes192>(&key, &iv, encrypted),
        OID_AES256_CBC => cbc_decrypt::<aes::Aes256>(&key, &iv, encrypted),
        OID_RC2_CBC => cbc_decrypt::<rc2::Rc2>(&key, &iv, encrypted),
        _ => cbc_decrypt::<des::TdesEde3>(&key, &iv, encrypted),
    }
}

/// One CBC decryption with PKCS#7 padding. The generic covers block cipher
/// backends (`aes`, `des`) and the RC2-CBC type from the `rc2` crate alike:
/// both implement the `cipher` traits `cbc` is built on, so the legacy path
/// adds no branch of its own beyond choosing the type (see `decrypt_pbe`).
fn cbc_decrypt<C>(key: &[u8], iv: &[u8], encrypted: &[u8]) -> Result<Zeroizing<Vec<u8>>>
where
    C: cbc::cipher::BlockCipherDecrypt + cbc::cipher::KeyInit,
{
    use cbc::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
    let dec = <cbc::Decryptor<C> as KeyIvInit>::new_from_slices(key, iv)
        .map_err(|e| Error::Keystore(format!("bad key or IV length: {e}")))?;
    // the plaintext of a safe contents bag or a key bag is key material until
    // the caller has looked at it, so it travels zeroized
    dec.decrypt_padded_vec::<Pkcs7>(encrypted)
        .map(Zeroizing::new)
        .map_err(|_| {
            Error::Keystore(
                "the decrypted block does not carry valid padding; wrong password or a \
                 truncated file"
                    .into(),
            )
        })
}

// ---------------------------------------------------------------------------
// putting keys and certificates together

fn assemble(keys: Vec<FoundKey>, certs: Vec<(Option<Vec<u8>>, Vec<u8>)>) -> Result<Vec<Entry>> {
    let mut entries = Vec::with_capacity(keys.len());
    for (key_id, alias, key_pkcs8) in keys {
        // localKeyID is how openssl and Java tie a key to its certificates.
        // When it is missing, every certificate in the file is a candidate and
        // the pairing check in SoftwareSigner is what decides.
        let matched: Vec<Vec<u8>> = match &key_id {
            Some(id) => {
                // Bags that carry this localKeyID are the direct answers, in
                // bag order. openssl writes it only on the leaf's bag: the
                // intermediate and root bags of the same container carry no
                // attributes at all (finding M-4 — keeping only the matched
                // ones shipped a one-certificate chain where AutoFirma emits
                // three). The unmatched bags are candidates too, after the
                // matched ones; when several keys share a file each gets its
                // own keyID-matched certificates first and the rest as chain
                // material. Dropped only on their exact DER: repeating another
                // key's leaf inside this chain is what the old by_id-only
                // behaviour was protecting against, and dedup keeps it out
                // without hiding anonymous bags. `order_chain` puts a bag
                // that does not chain at the end, so offering everything
                // cannot corrupt the ordered part.
                let mut owned: Vec<Vec<u8>> = certs
                    .iter()
                    .filter(|(cid, _)| cid.as_ref() == Some(id))
                    .map(|(_, der)| der.clone())
                    .collect();
                for (cid, der) in &certs {
                    if !owned.iter().any(|kept| kept == der) {
                        let _ = cid;
                        owned.push(der.clone());
                    }
                }
                owned
            }
            None => certs.iter().map(|(_, der)| der.clone()).collect(),
        };
        let chain = order_chain(&key_pkcs8, &matched)?;
        if chain.is_empty() {
            return Err(Error::Keystore(
                "the PKCS#12 holds a private key but no certificate for it".into(),
            ));
        }
        entries.push(Entry {
            alias,
            local_key_id: key_id,
            // the copy is what the Entry's Drop zeroizes; the Zeroizing
            // original goes out of scope here and zeroes itself
            key_pkcs8: key_pkcs8.to_vec(),
            chain,
        });
    }
    Ok(entries)
}

/// Puts the certificate the key belongs to first, then walks subject to
/// issuer. Certificates that do not chain off the leaf still travel, at the
/// end, because a PKCS#12 often carries unrelated intermediates and dropping
/// them would silently shorten the chain we embed in signatures.
fn order_chain(key_pkcs8: &[u8], certs: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
    if certs.is_empty() {
        return Ok(Vec::new());
    }
    let leaf_index = certs
        .iter()
        .position(|der| key_matches(key_pkcs8, der))
        .unwrap_or(0);

    let mut out = vec![certs[leaf_index].clone()];
    while let Ok(current) = CertificateHandle::from_der(out.last().unwrap()) {
        let issuer = current.issuer();
        let next = certs.iter().find(|der| {
            !out.contains(der)
                && CertificateHandle::from_der(der)
                    .map(|h| h.subject() == issuer)
                    .unwrap_or(false)
        });
        match next {
            Some(der) => out.push(der.clone()),
            None => break,
        }
    }
    for der in certs {
        if !out.contains(der) {
            out.push(der.clone());
        }
    }
    Ok(out)
}

/// Whether a PKCS#8 key is the private half of a certificate. The same check
/// `SoftwareSigner` makes, done early so the chain comes out ordered.
/// Pairing rule: the certificate belongs to the key when the SPKI derived
/// from the private key equals the certificate's SubjectPublicKeyInfo,
/// byte-exact. The old code looked for a `[1]` public key inside PKCS#8 v1,
/// which no writer emits (finding B2): every OpenSSL container then silently
/// fell back to "first certificate in the file" and chained whatever came
/// first, roots included. Deriving is total — any PKCS#8 this crate can sign
/// with has a derivable public half.
fn key_matches(key_pkcs8: &[u8], cert_der: &[u8]) -> bool {
    let Ok(cert) = CertificateHandle::from_der(cert_der) else {
        return false;
    };
    let Ok(cert_spki) = cert.spki_der() else {
        return false;
    };
    match pkcs8_spki(key_pkcs8) {
        Some(spki) => spki == cert_spki,
        None => false,
    }
}

/// The SubjectPublicKeyInfo of a PKCS#8 private key: RSA's `(n, e)` or an EC
/// P-256 point, re-encoded the way certificates carry it. Both derivations are
/// public-key arithmetic on RustCrypto types this workspace already depends on
/// (`rsa`, `p256`), so no new dependency and no parsing of optional PKCS#8
/// fields that OpenSSL does not write anyway. Returns None for keys openfirma
/// could not sign with; the caller then falls back to localKeyID order and
/// lets SoftwareSigner refuse a mismatch at signing time.
fn pkcs8_spki(key_pkcs8: &[u8]) -> Option<Vec<u8>> {
    // one derivation, in core, kept next to the curve list it must cover; a
    // per-curve copy here silently stopped at P-256 for a while (finding M6)
    openfirma_core::signer::SoftwareSigner::pkcs8_public_spki(key_pkcs8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openfirma_core::tlv;

    /// A DER INTEGER in minimal form, for the iteration counts below.
    fn der_integer(v: usize) -> Vec<u8> {
        let be = v.to_be_bytes();
        let start = be.iter().position(|b| *b != 0).unwrap_or(be.len() - 1);
        let mut content = be[start..].to_vec();
        if content[0] & 0x80 != 0 {
            content.insert(0, 0);
        }
        tlv::tlv(tlv::TAG_INTEGER, &content)
    }

    /// The smallest shape that is still a PFX: version 3, an empty plain
    /// authenticated safe, and a MAC whose iteration count is the point of
    /// the test. No certificate material anywhere, so it can live here.
    fn pfx_with_mac_iterations(iterations: usize) -> Vec<u8> {
        let digest_info = tlv::sequence(&[
            tlv::sequence(&[tlv::oid(&OID_SHA1).unwrap(), tlv::null()]),
            tlv::octet_string(&[0u8; 20]).unwrap(),
        ]);
        let mac_data = tlv::sequence(&[
            digest_info,
            tlv::octet_string(b"saltsalt").unwrap(),
            der_integer(iterations),
        ]);
        let safe_contents = tlv::sequence(&[]);
        let auth_safe = tlv::sequence(&[
            tlv::oid(&OID_DATA).unwrap(),
            tlv::explicit(0, &tlv::octet_string(&safe_contents).unwrap()),
        ]);
        tlv::sequence(&[tlv::integer_small(3), auth_safe, mac_data])
    }

    /// The MAC runs before anything is decrypted, so its iteration count is
    /// the first denial of service a hostile file can ask for. Ten million is
    /// the ceiling; past it the error names the cause and the re-export.
    #[test]
    fn mac_iterations_above_the_cap_are_refused_with_a_way_out() {
        let pfx = pfx_with_mac_iterations(MAX_ITERATIONS + 1);
        let err = load(&pfx, "whatever").unwrap_err().to_string();
        assert!(err.contains("10000001 MAC iterations"), "{err}");
        assert!(err.contains("hostile"), "{err}");
        assert!(err.contains("openssl pkcs12"), "{err}");
    }

    #[test]
    fn mac_iterations_at_the_cap_reach_the_mac_itself() {
        // the digest is zeros, so the container is still refused — but as a
        // failed integrity check, which is the stage the cap must not preempt
        let pfx = pfx_with_mac_iterations(MAX_ITERATIONS);
        let err = load(&pfx, "whatever").unwrap_err().to_string();
        assert!(err.contains("integrity check failed"), "{err}");
    }

    #[test]
    fn pbkdf2_rounds_are_capped_too() {
        assert_eq!(rounds(2048).unwrap(), 2048);
        assert_eq!(rounds(MAX_ITERATIONS).unwrap(), MAX_ITERATIONS as u32);
        let err = rounds(MAX_ITERATIONS + 1).unwrap_err().to_string();
        assert!(err.contains("PBKDF2"), "{err}");
        assert!(err.contains("openssl pkcs12"), "{err}");
    }

    /// The lossy UTF-16 decode used to invent a replacement character for an
    /// unpaired surrogate, so an alias could silently stop matching what the
    /// user types into --alias. A strict decode says what is wrong instead,
    /// including the possibility that the password is what will not decode.
    #[test]
    fn bmp_string_is_decoded_strictly() {
        assert_eq!(bmp_string(b"\x00A\x00n\x00a").unwrap(), "Ana");
        // an unpaired high surrogate
        let err = bmp_string(&[0xD8, 0x00]).unwrap_err().to_string();
        assert!(err.contains("not valid UTF-16"), "{err}");
        assert!(err.contains("non-ASCII"), "{err}");
        // an odd number of bytes cannot be UTF-16 at all
        let err = bmp_string(b"\x00A\x00").unwrap_err().to_string();
        assert!(err.contains("odd number of bytes"), "{err}");
    }

    #[test]
    fn the_password_encoding_round_trips() {
        // PKCS#12 wants UTF-16BE with a two byte terminator; the empty
        // password exists in two spellings, and both must exist here for the
        // A3 dance of verify_mac/decrypt_password to have anything to try.
        assert!(bmp_password("").is_empty());
        assert_eq!(&*mac_password_candidates("")[1], b"\x00\x00");
        assert_eq!(&*bmp_password("a"), b"\x00a\x00\x00");
        assert_eq!(&*bmp_password("\u{e9}"), b"\x00\xe9\x00\x00");
    }

    /// A truncated BER value must error like every other malformed input,
    /// not panic: the exact bytes of review 04's M1 (`30 84`, a length that
    /// claims four octets that are not there) through the PKCS#12 wrapper.
    #[test]
    fn truncated_lengths_produce_an_error_not_a_panic() {
        for bytes in [&[0x30u8, 0x84][..], &[0x30, 0x80], &[0x24, 0x80]] {
            let err = load(bytes, "x").unwrap_err().to_string();
            assert!(!err.is_empty());
        }
    }

    /// The empty password candidates: Java's zero bytes and OpenSSL/NSS's BMP
    /// terminator, in order (the PKCS#12-rule spelling first, like every other
    /// conforming reader). PBES2 additionally gains the raw-bytes spelling —
    /// OpenSSL 3.x keys its PBKDF2 with those — and non-empty passwords have
    /// exactly one MAC spelling.
    #[test]
    fn empty_password_tries_both_encodings_in_order() {
        let cands = mac_password_candidates("");
        assert_eq!(cands.len(), 2, "{:?}", *cands[0]);
        // Java's zero BMP chars first, then OpenSSL/NSS's `00 00` terminator.
        assert!(cands[0].is_empty());
        assert_eq!(&*cands[1], b"\x00\x00");
        // "ab": the BMP spelling and OpenSSL 3.x's raw one (the MAC of an
        // openssl-3 file is keyed with the latter — see pbes2 notes)
        let ab = mac_password_candidates("ab");
        assert_eq!(ab.len(), 2);
        assert_eq!(&*ab[0], b"\x00a\x00b\x00\x00");
        assert_eq!(&*ab[1], b"ab");
        // PBES2 additionally accepts Java's no-terminator BMP spelling — for
        // "" that is the same bytes as the MAC's first candidate, so the list
        // does not grow; for "ab" it adds `\x00a\x00b` between the two.
        // "" collapses to the two spellings that exist: `00 00` and nothing.
        let empty = pbes2_password_candidates("");
        assert_eq!(empty.len(), 2);
        assert_eq!(&*empty[0], b"\x00\x00");
        assert!(empty[1].is_empty());
        let ab_pbes2 = pbes2_password_candidates("ab");
        // OpenSSL 3's NUL-terminated raw bytes, Java's terminator-less BMP,
        // then the MAC spellings (BMP+terminator and bare raw) deduped in.
        assert_eq!(ab_pbes2.len(), 4);
        assert_eq!(&*ab_pbes2[0], b"ab\x00\x00");
        assert_eq!(&*ab_pbes2[1], b"\x00a\x00b");
        assert_eq!(&*ab_pbes2[2], b"\x00a\x00b\x00\x00");
        assert_eq!(&*ab_pbes2[3], b"ab");
    }

    /// keyLength must name the cipher's own key size — in bytes, the spelling
    /// Java writes: a mismatch is a container lying about its parameters.
    #[test]
    fn pbes2_rejects_a_key_length_that_disagrees_with_the_cipher() {
        // AES-128 (16 byte key) declaring 32: refuse, naming both values.
        let params = pbes2_params(OID_AES128_CBC, 32);
        let err = decrypt_pbe(OID_PBES2, &params, &[0u8; 16], b"x")
            .unwrap_err()
            .to_string();
        assert!(err.contains("32") && err.contains("16"), "{err}");
    }

    #[test]
    fn key_length_matching_the_cipher_passes_the_parameter_check() {
        // Same shape with the honest 16: the parameter block is accepted and
        // the failure (if any) comes from padding, not from the check.
        let params = pbes2_params(OID_AES128_CBC, 16);
        let err = decrypt_pbe(OID_PBES2, &params, &[0u8; 16], b"x")
            .unwrap_err()
            .to_string();
        assert!(err.contains("padding"), "{err}");
    }

    /// The bug that made PKCS#12 loading flaky (measured ~1 in 117 over
    /// random-salt exports): with an 8-byte block cipher the WRONG password
    /// candidate's garbage satisfies PKCS#7 padding roughly once in 256, and
    /// `decrypt_pbe_all` returned the first padding-valid result — so the real
    /// plaintext was never reached and the caller read the garbage as DER
    /// ("a DER length that is overlong or runs past the input"). The fix makes
    /// a candidate acceptable only when its plaintext is a whole DER SEQUENCE.
    /// Deterministic: it searches a fixed salt space for a collision and then
    /// asserts the empty-password path returns the DER, not the garbage.
    #[test]
    fn a_wrong_candidate_whose_garbage_passes_padding_is_not_accepted_over_the_real_one() {
        use cbc::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
        // a tiny but complete DER SEQUENCE: SEQUENCE { INTEGER 1 }
        let plaintext: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x01];
        // the spelling OpenSSL/NSS key this PBE with for the empty password
        let good: &[u8] = &[0x00, 0x00];
        let iterations = 1usize;

        let mut found = None;
        for seed in 0u32..2_000_000 {
            let salt = seed.to_le_bytes();
            let key = pkcs12_kdf::<sha1::Sha1>(1, good, &salt, iterations, 24, 64);
            let iv = pkcs12_kdf::<sha1::Sha1>(2, good, &salt, iterations, 8, 64);
            let enc =
                <cbc::Encryptor<des::TdesEde3> as KeyIvInit>::new_from_slices(&key, &iv).unwrap();
            let ct = enc.encrypt_padded_vec::<Pkcs7>(plaintext);
            let params = pbe_sha1_params(&salt, iterations);
            // does the WRONG (empty) candidate satisfy padding on this ct?
            if decrypt_pbe(OID_PBE_SHA1_3DES, &params, &ct, &[]).is_ok() {
                found = Some((salt, params, ct));
                break;
            }
        }
        let (salt, params, ct) =
            found.expect("a padding collision must exist within the fixed salt search");

        // the good candidate really is the DER plaintext
        let good_out = decrypt_pbe(OID_PBE_SHA1_3DES, &params, &ct, good).unwrap();
        assert_eq!(
            &good_out[..],
            plaintext,
            "sanity: the real key yields the DER"
        );
        // and the empty-password path must return THAT, never the garbage
        let out = decrypt_pbe_all(OID_PBE_SHA1_3DES, &params, &ct, "").unwrap();
        assert_eq!(
            &out[..],
            plaintext,
            "the wrong candidate's garbage (salt {salt:?}) was accepted over the real plaintext"
        );
    }

    /// `pkcs-12PbeParams` content: an OCTET STRING salt and an INTEGER count,
    /// the two fields every legacy SHA-1 PBE reads (see `decrypt_pbe`).
    fn pbe_sha1_params(salt: &[u8], iterations: usize) -> Vec<u8> {
        let mut out = tlv::octet_string(salt).unwrap();
        out.extend_from_slice(&der_integer(iterations));
        out
    }

    /// `PBES2-params` for one cipher with a declared keyLength: PBKDF2 with a
    /// salt and count, then the encryption identifier with an all-zero IV.
    /// The COMPLETE PBES2 AlgorithmIdentifier (OID + params): that is what
    /// `decrypt_pbe` receives and unwraps via `read_algorithm`.
    fn pbes2_params(cipher: ObjectIdentifier, key_length: usize) -> Vec<u8> {
        let mut kp = tlv::octet_string(b"salt").unwrap();
        kp.extend_from_slice(&der_integer(2048));
        if key_length != 0 {
            kp.extend_from_slice(&der_integer(key_length));
        }
        let enc = tlv::sequence(&[
            tlv::oid(&cipher).unwrap(),
            tlv::octet_string(&[0u8; 16]).unwrap(),
        ]);
        let kdf_ident = tlv::sequence(&[tlv::oid(&OID_PBKDF2).unwrap(), tlv::tlv(0x30, &kp)]);
        // The CONTENT of PBES2-params — the two identifier SEQUENCEs back to
        // back — which is what `decrypt_pbe` hands decrypt_pbes2 after
        // read_algorithm unwraps the outer identifier.
        [kdf_ident, enc].concat()
    }

    /// The parameter a current `keytool` really writes (AES-256 with
    /// keyLength 32 in bytes) must not trip the check: the failure below is
    /// padding, which means the KDF ran with 32 bytes.
    #[test]
    fn the_byte_spelling_java_writes_is_accepted() {
        let params = pbes2_params(OID_AES256_CBC, 32);
        let err = decrypt_pbe(OID_PBES2, &params, &[0u8; 16], b"x")
            .unwrap_err()
            .to_string();
        assert!(err.contains("padding"), "{err}");
    }

    /// A file whose RC2-40 parameters are real must decrypt: the legacy PBE
    /// path is exercised end to end against fixtures in tests/pkcs12_interop;
    /// here the refusal of an *unsupported* scheme stays cheap to test.
    #[test]
    fn pbes2_refuses_a_cipher_it_cannot_decrypt_by_name() {
        let params = pbes2_params(OID_PBKDF2, 0); // nonsense cipher on purpose
        let err = decrypt_pbe(OID_PBES2, &params, &[0u8; 16], b"x")
            .unwrap_err()
            .to_string();
        assert!(err.contains("PBES2 with cipher"), "{err}");
    }

    #[test]
    fn rc4_and_unknown_schemes_are_refused_by_name() {
        // RC4 never appears in PKCS#12 as a bag scheme anyone writes; the
        // generic refusal names it when a file claims it anyway.
        let err = decrypt_pbe(
            ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.1.1"),
            b"",
            b"",
            b"x",
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("unsupported PKCS#12 encryption scheme"),
            "{err}"
        );
    }

    /// The KDF of RFC 7292 B.2 against a known-answer vector computed with an
    /// independent implementation (OpenSSL 3.6's PKCS12_key_gen_uni, SHA-1,
    /// password "password" as BMP+terminator, salt `0a58a46a`, id=3 — the MAC
    /// key role — one iteration, 20 bytes). Whole-file checks against real
    /// Java/OpenSSL/NSS containers live in tests/pkcs12_interop.rs; this is
    /// the primitive-level tripwire that holds even when testdata is absent.
    #[test]
    fn pkcs12_kdf_matches_an_independent_known_answer() {
        let pw: Vec<u8> = "password"
            .encode_utf16()
            .flat_map(|u| u.to_be_bytes())
            .chain([0, 0])
            .collect();
        let salt = [0x0a, 0x58, 0xa4, 0x6a];
        let key = pkcs12_kdf::<sha1::Sha1>(3, &pw, &salt, 1, 20, 64);
        assert_eq!(
            hex::encode(&*key),
            "a5fd9898a26dfdb8695e3e768c8d590ffdea920e"
        );
    }
}
