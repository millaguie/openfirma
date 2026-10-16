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
//!   decryption is trusted;
//! - PBES2 with PBKDF2 (any of those hashes as PRF) over AES-128/192/256-CBC
//!   and 3DES-CBC, which is what OpenSSL 3 and current Java write;
//! - the legacy PKCS#12 PBE with SHA-1 and 3DES, which is what older FNMT
//!   software and old Java keystores still produce;
//! - cert bags, shrouded and plain key bags, nested safe contents, and the
//!   `friendlyName` / `localKeyID` attributes that tie a key to its chain.
//!
//! What it refuses, loudly: RC2 and RC4 PBE, which only files from two decades
//! ago use; indefinite lengths, which DER forbids anyway; and key derivation
//! counts above ten million iterations, which no legitimate writer produces
//! and which are a denial of service the moment they are believed. Every
//! refusal message says how to re-export the file with a modern openssl.
//!
//! What it does not leave behind: the MAC comparison is constant time, and
//! every decrypted buffer that could hold key material is zeroized on drop.

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
const OID_PBKDF2: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.5.12");
const OID_HMAC_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.2.7");
const OID_HMAC_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.2.9");
const OID_HMAC_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.2.10");
const OID_HMAC_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.2.11");
const OID_AES128_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.2");
const OID_AES192_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.22");
const OID_AES256_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.42");
const OID_DES_EDE3_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.3.7");
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
#[derive(Clone, Debug)]
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

/// Everything a PKCS#12 file held.
#[derive(Clone, Debug, Default)]
pub struct Pkcs12 {
    pub entries: Vec<Entry>,
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

    fn aliases(&self) -> Vec<String> {
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
// a cursor over DER, just enough for this format

struct Cur<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cur<'a> {
    fn new(b: &'a [u8]) -> Self {
        Cur { b, i: 0 }
    }

    fn is_done(&self) -> bool {
        self.i >= self.b.len()
    }

    fn tlv(&mut self) -> Result<(u8, &'a [u8])> {
        let tag = *self
            .b
            .get(self.i)
            .ok_or_else(|| Error::Keystore("the DER ends mid tag".into()))?;
        if tag & 0x1f == 0x1f {
            return Err(Error::Keystore(
                "high tag number form in a PKCS#12, which DER does not use here".into(),
            ));
        }
        self.i += 1;
        let (len, n) = read_len(&self.b[self.i..])?;
        self.i += n;
        let end = self
            .i
            .checked_add(len)
            .ok_or_else(|| Error::Keystore("an absurd length in the DER".into()))?;
        if end > self.b.len() {
            return Err(Error::Keystore(format!(
                "a {len} byte value runs past the end of the container"
            )));
        }
        let v = &self.b[self.i..end];
        self.i = end;
        Ok((tag, v))
    }

    fn expect(&mut self, tag: u8) -> Result<&'a [u8]> {
        let (t, v) = self.tlv()?;
        if t != tag {
            return Err(Error::Keystore(format!(
                "expected tag {tag:#04x} in the PKCS#12, found {t:#04x}"
            )));
        }
        Ok(v)
    }

    fn sequence(&mut self) -> Result<Cur<'a>> {
        Ok(Cur::new(self.expect(0x30)?))
    }

    fn oid(&mut self) -> Result<ObjectIdentifier> {
        let v = self.expect(0x06)?;
        ObjectIdentifier::from_bytes(v)
            .map_err(|e| Error::Keystore(format!("unreadable OID in the PKCS#12: {e}")))
    }

    fn number(&mut self) -> Result<usize> {
        let v = self.expect(0x02)?;
        if v.len() > 8 {
            return Err(Error::Keystore("an integer too large to be a count".into()));
        }
        let mut n = 0usize;
        for b in v {
            n = (n << 8) | *b as usize;
        }
        Ok(n)
    }

    fn octets(&mut self) -> Result<&'a [u8]> {
        self.expect(0x04)
    }

    /// `[n] EXPLICIT`, the wrapper PKCS#12 puts around nested content.
    fn explicit(&mut self, n: u8) -> Result<&'a [u8]> {
        self.expect(0xa0 | n)
    }
}

fn read_len(b: &[u8]) -> Result<(usize, usize)> {
    let first = *b
        .first()
        .ok_or_else(|| Error::Keystore("the DER ends mid length".into()))?;
    if first < 0x80 {
        return Ok((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 {
        return Err(Error::Keystore(
            "indefinite length, which DER forbids and a PKCS#12 never carries".into(),
        ));
    }
    if n > 4 {
        return Err(Error::Keystore(
            "a length field wider than four bytes".into(),
        ));
    }
    let mut v = 0usize;
    for x in &b[1..=n] {
        v = (v << 8) | *x as usize;
    }
    Ok((v, n + 1))
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
    let mut outer = Cur::new(bytes).sequence()?;
    let version = outer.number()?;
    if version != 3 {
        return Err(Error::Keystore(format!(
            "PKCS#12 version {version}, only version 3 exists"
        )));
    }

    // authSafe: a ContentInfo whose content is the AuthenticatedSafe bytes
    let mut auth_safe = outer.sequence()?;
    let auth_safe_type = auth_safe.oid()?;
    if auth_safe_type != OID_DATA {
        return Err(Error::Keystore(
            "the authenticated safe is not a plain data ContentInfo".into(),
        ));
    }
    let auth_safe_bytes = Zeroizing::new({
        let mut wrapped = Cur::new(auth_safe.explicit(0)?);
        wrapped.octets()?.to_vec()
    });

    if !outer.is_done() {
        let mac = read_mac(&mut outer)?;
        verify_mac(&mac, &auth_safe_bytes, password)?;
    }

    let mut certs: Vec<(Option<Vec<u8>>, Vec<u8>)> = Vec::new();
    let mut keys: Vec<FoundKey> = Vec::new();

    let mut safe = Cur::new(&auth_safe_bytes).sequence()?;
    while !safe.is_done() {
        let mut ci = safe.sequence()?;
        let content_type = ci.oid()?;
        let content = ci.explicit(0)?;
        // decrypted or not, a SafeContents can hold plain key bags, so it is
        // zeroized like the key material it may contain
        let safe_contents: Zeroizing<Vec<u8>> = if content_type == OID_DATA {
            Zeroizing::new(Cur::new(content).octets()?.to_vec())
        } else if content_type == OID_ENCRYPTED_DATA {
            decrypt_content_info(content, password)?
        } else {
            return Err(Error::Keystore(format!(
                "unsupported ContentInfo in the authenticated safe: {content_type}"
            )));
        };
        let mut bags = Cur::new(&safe_contents).sequence()?;
        while !bags.is_done() {
            read_bag(&mut bags, password, &mut certs, &mut keys)?;
        }
    }

    Ok(Pkcs12 {
        entries: assemble(keys, certs)?,
    })
}

fn read_mac(cur: &mut Cur) -> Result<MacData> {
    let mut mac = cur.sequence()?;
    let mut digest_info = mac.sequence()?;
    let mut alg = digest_info.sequence()?;
    let digest_oid = alg.oid()?;
    let digest = digest_info.octets()?.to_vec();
    let salt = mac.octets()?.to_vec();
    // iterations defaults to 1 when absent, per the specification
    let iterations = if mac.is_done() { 1 } else { mac.number()? };
    check_iterations(iterations, "MAC")?;
    Ok(MacData {
        digest_oid,
        digest,
        salt,
        iterations,
    })
}

/// The MAC is the password check. Doing it first means a wrong password is
/// reported as a wrong password, not as padding garbage three layers down.
fn verify_mac(mac: &MacData, auth_safe: &[u8], password: &str) -> Result<()> {
    let pw = bmp_password(password);
    // instantiated per hash rather than generic over it: Hmac's bounds in this
    // digest generation are a thicket, and there are exactly four hashes a
    // PKCS#12 MAC can use
    macro_rules! check {
        ($d:ty, $v:expr) => {{
            let key = pkcs12_kdf::<$d>(
                3,
                &pw,
                &mac.salt,
                mac.iterations,
                <$d as Digest>::output_size(),
                $v,
            );
            let mut m = <Hmac<$d> as KeyInit>::new_from_slice(&key)
                .map_err(|e| Error::Keystore(format!("cannot build the MAC key: {e}")))?;
            m.update(auth_safe);
            // constant time: the MAC is compared before the password is known
            // to be right, so an early exit here would leak it digest byte by
            // digest byte to anyone who can hand us files and watch the time
            let computed = m.finalize().into_bytes();
            bool::from(mac.digest.as_slice().ct_eq(computed.as_slice()))
        }};
    }
    let ok = match mac.digest_oid {
        OID_SHA1 => check!(sha1::Sha1, 64),
        OID_SHA256 => check!(sha2::Sha256, 64),
        OID_SHA384 => check!(sha2::Sha384, 128),
        OID_SHA512 => check!(sha2::Sha512, 128),
        other => {
            return Err(Error::Keystore(format!(
                "the MAC uses digest {other}, which is not supported"
            )));
        }
    };
    if !ok {
        return Err(Error::Keystore(
            "the PKCS#12 integrity check failed: wrong password, or the file was \
             tampered with"
                .into(),
        ));
    }
    Ok(())
}

fn decrypt_content_info(content: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut ed = Cur::new(content).sequence()?;
    let _version = ed.number()?;
    let mut eci = ed.sequence()?;
    let _content_type = eci.oid()?;
    let (alg_oid, params) = read_algorithm(&mut eci)?;
    // [0] IMPLICIT OCTET STRING: the tag is 0x80, not 0x04
    let (tag, encrypted) = eci.tlv()?;
    if tag != 0x80 {
        return Err(Error::Keystore(format!(
            "the encrypted content carries tag {tag:#04x}, expected the implicit 0x80"
        )));
    }
    decrypt_pbe(alg_oid, params, encrypted, password)
}

fn read_bag(
    cur: &mut Cur,
    password: &str,
    certs: &mut Vec<(Option<Vec<u8>>, Vec<u8>)>,
    keys: &mut Vec<FoundKey>,
) -> Result<()> {
    let mut bag = cur.sequence()?;
    let bag_id = bag.oid()?;
    let value = bag.explicit(0)?;
    let (alias, local_key_id) = if bag.is_done() {
        (None, None)
    } else {
        read_attributes(&mut bag)?
    };

    match bag_id {
        OID_CERT_BAG => {
            let mut cb = Cur::new(value).sequence()?;
            let cert_type = cb.oid()?;
            if cert_type != OID_X509_CERTIFICATE {
                return Err(Error::Keystore(format!(
                    "certificate bag of type {cert_type}; only X.509 certificates are supported"
                )));
            }
            let der = Cur::new(cb.explicit(0)?).octets()?.to_vec();
            certs.push((local_key_id, der));
        }
        OID_SHROUDED_KEY_BAG => {
            let mut eki = Cur::new(value).sequence()?;
            let (alg_oid, params) = read_algorithm(&mut eki)?;
            let encrypted = eki.octets()?.to_vec();
            let pkcs8 = decrypt_pbe(alg_oid, params, &encrypted, password)?;
            keys.push((local_key_id, alias, pkcs8));
        }
        OID_KEY_BAG => {
            keys.push((local_key_id, alias, Zeroizing::new(value.to_vec())));
        }
        OID_SAFE_CONTENTS_BAG => {
            let mut inner = Cur::new(value).sequence()?;
            while !inner.is_done() {
                read_bag(&mut inner, password, certs, keys)?;
            }
        }
        other => tracing::debug!("ignoring PKCS#12 bag of type {other}"),
    }
    Ok(())
}

fn read_attributes(cur: &mut Cur) -> Result<(Option<String>, Option<Vec<u8>>)> {
    let set = cur.expect(0x31)?;
    let mut attrs = Cur::new(set);
    let mut alias = None;
    let mut local_key_id = None;
    while !attrs.is_done() {
        let mut attr = attrs.sequence()?;
        let id = attr.oid()?;
        let mut values = Cur::new(attr.expect(0x31)?);
        match id {
            OID_FRIENDLY_NAME => alias = Some(bmp_string(values.expect(0x1e)?)?),
            OID_LOCAL_KEY_ID => local_key_id = Some(values.octets()?.to_vec()),
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

/// The password as PKCS#12 wants it: UTF-16BE with a two byte zero terminator.
/// An empty password is encoded as no bytes at all, which is what openssl and
/// Java both expect.
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
    let repeat = |src: &[u8]| -> Vec<u8> {
        if src.is_empty() {
            return Vec::new();
        }
        let n = v * src.len().div_ceil(v);
        (0..n).map(|i| src[i % src.len()]).collect()
    };
    // the folded I block holds the repeated password, so it is key material
    // like the output and gets zeroed the same way
    let mut i = Zeroizing::new(repeat(salt));
    i.extend_from_slice(&repeat(password));

    let mut out = Zeroizing::new(Vec::with_capacity(out_len + u));
    for round in 0..out_len.div_ceil(u) {
        let mut h = D::new();
        h.update(&d);
        h.update(&i);
        let mut a = h.finalize();
        for _ in 1..iterations {
            let mut round = D::new();
            round.update(&a);
            a = round.finalize();
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
fn read_algorithm(cur: &mut Cur) -> Result<(ObjectIdentifier, Vec<u8>)> {
    let mut ai = cur.sequence()?;
    let oid = ai.oid()?;
    let params = if ai.is_done() {
        Vec::new()
    } else {
        ai.expect(0x30)?.to_vec()
    };
    Ok((oid, params))
}

fn decrypt_pbe(
    alg: ObjectIdentifier,
    params: Vec<u8>,
    encrypted: &[u8],
    password: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    match alg {
        OID_PBES2 => decrypt_pbes2(&params, encrypted, password),
        OID_PBE_SHA1_3DES => {
            let mut p = Cur::new(&params);
            let salt = p.octets()?.to_vec();
            let iterations = p.number()?;
            check_iterations(iterations, "key derivation")?;
            let pw = bmp_password(password);
            let key = pkcs12_kdf::<sha1::Sha1>(1, &pw, &salt, iterations, 24, 64);
            let iv = pkcs12_kdf::<sha1::Sha1>(2, &pw, &salt, iterations, 8, 64);
            cbc_decrypt::<des::TdesEde3>(&key, &iv, encrypted)
        }
        OID_PBE_SHA1_RC2_40 => Err(Error::Keystore(
            "this PKCS#12 uses RC2, a cipher from 1995 that this reader will not \
             implement. Re-export it with `openssl pkcs12 -in old.p12 -out new.p12` \
             and a current openssl will use AES."
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

fn decrypt_pbes2(params: &[u8], encrypted: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut p = Cur::new(params);
    let mut kdf_ai = p.sequence()?;
    let kdf_oid = kdf_ai.oid()?;
    if kdf_oid != OID_PBKDF2 {
        return Err(Error::Keystore(format!(
            "PBES2 with a key derivation function that is not PBKDF2: {kdf_oid}"
        )));
    }
    let kdf_params = kdf_ai.expect(0x30)?.to_vec();
    let mut enc_ai = p.sequence()?;
    let enc_oid = enc_ai.oid()?;
    let iv = enc_ai.octets()?.to_vec();

    let mut kp = Cur::new(&kdf_params);
    let salt = kp.octets()?.to_vec();
    let iterations = kp.number()?;
    // keyLength is optional and we ignore it: the cipher below knows its own
    let prf = if kp.is_done() {
        OID_HMAC_SHA1
    } else {
        let mut ai = kp.sequence()?;
        ai.oid()?
    };

    let key_len = match enc_oid {
        OID_AES128_CBC => 16,
        OID_AES192_CBC => 24,
        OID_AES256_CBC => 32,
        OID_DES_EDE3_CBC => 24,
        other => {
            return Err(Error::Keystore(format!(
                "PBES2 with cipher {other}, only AES-CBC and 3DES-CBC are supported"
            )));
        }
    };

    let mut key = Zeroizing::new(vec![0u8; key_len]);
    match prf {
        OID_HMAC_SHA1 => pbkdf2::pbkdf2_hmac::<sha1::Sha1>(
            password.as_bytes(),
            &salt,
            rounds(iterations)?,
            &mut key,
        ),
        OID_HMAC_SHA256 => pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
            password.as_bytes(),
            &salt,
            rounds(iterations)?,
            &mut key,
        ),
        OID_HMAC_SHA384 => pbkdf2::pbkdf2_hmac::<sha2::Sha384>(
            password.as_bytes(),
            &salt,
            rounds(iterations)?,
            &mut key,
        ),
        OID_HMAC_SHA512 => pbkdf2::pbkdf2_hmac::<sha2::Sha512>(
            password.as_bytes(),
            &salt,
            rounds(iterations)?,
            &mut key,
        ),
        other => {
            return Err(Error::Keystore(format!(
                "PBKDF2 with PRF {other}, only the SHA family is supported"
            )));
        }
    }

    match enc_oid {
        OID_AES128_CBC => cbc_decrypt::<aes::Aes128>(&key, &iv, encrypted),
        OID_AES192_CBC => cbc_decrypt::<aes::Aes192>(&key, &iv, encrypted),
        OID_AES256_CBC => cbc_decrypt::<aes::Aes256>(&key, &iv, encrypted),
        _ => cbc_decrypt::<des::TdesEde3>(&key, &iv, encrypted),
    }
}

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
                let by_id: Vec<Vec<u8>> = certs
                    .iter()
                    .filter(|(cid, _)| cid.as_ref() == Some(id))
                    .map(|(_, der)| der.clone())
                    .collect();
                if by_id.is_empty() {
                    certs.iter().map(|(_, der)| der.clone()).collect()
                } else {
                    by_id
                }
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
fn key_matches(key_pkcs8: &[u8], cert_der: &[u8]) -> bool {
    let Ok(cert) = CertificateHandle::from_der(cert_der) else {
        return false;
    };
    let Ok(cert_spki) = cert.spki_der() else {
        return false;
    };
    let Ok(info) = pkcs8_public_key(key_pkcs8) else {
        return false;
    };
    info == cert_spki
}

/// The SubjectPublicKeyInfo that corresponds to a PKCS#8 private key,
/// rebuilt from the algorithm identifier and the public key the container
/// carries in its optional `[0]` field. PKCS#8 v1 has no such field, and then
/// there is nothing to match against: the caller falls back to the first
/// certificate and lets `SoftwareSigner` reject a mismatch.
fn pkcs8_public_key(key_pkcs8: &[u8]) -> Result<Vec<u8>> {
    use openfirma_core::tlv;
    let mut s = Cur::new(key_pkcs8).sequence()?;
    let _version = s.tlv()?; // INTEGER
    let (alg_tag, alg_value) = s.tlv()?; // AlgorithmIdentifier
    let _private = s.octets()?;
    if s.is_done() {
        return Err(Error::Keystore(
            "the PKCS#8 key carries no public key to match against".into(),
        ));
    }
    let (wrap_tag, wrapped) = s.tlv()?;
    if wrap_tag != 0xa0 {
        return Err(Error::Keystore(format!(
            "expected the [0] public key wrapper, found tag {wrap_tag:#04x}"
        )));
    }
    let (bit_tag, bit_value) = Cur::new(wrapped).tlv()?;
    let mut content = tlv::tlv(alg_tag, alg_value);
    content.extend_from_slice(&tlv::tlv(bit_tag, bit_value));
    Ok(tlv::tlv(tlv::TAG_SEQUENCE, &content))
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
        // PKCS#12 wants UTF-16BE with a two byte terminator, and nothing for
        // an empty password, which is what openssl and Java both expect
        assert!(bmp_password("").is_empty());
        assert_eq!(&*bmp_password("a"), b"\x00a\x00\x00");
        assert_eq!(&*bmp_password("\u{e9}"), b"\x00\xe9\x00\x00");
    }
}
