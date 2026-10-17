#!/usr/bin/env python3
"""Add the empty-password MAC spellings to a PKCS#12 file (fixture helper).

Why this exists: keytool refuses store passwords under six characters, so the
Java shape of an empty-password container (the `keyLength`/PBES2-AES form of
review 04's A1 x A3) cannot be written directly by a JDK on this machine. What
a Java tool that DID allow empty passwords writes is a file whose MacData
verifies with the password in Java's encoding — zero bytes. This script takes
a real keytool/openssl file and appends two extra MacData entries to its outer
sequence: one verifying with the OpenSSL/NSS empty encoding (the BMP terminator
alone), one with Java's (nothing at all). The original MacData is kept, so the
file still verifies for the password it was written with (`openfirma` here);
PKCS#12 parsers read the MacData and accept any that matches, which is exactly
how both spellings get exercised by one file. `keytool -list -storepass
openfirma` opens the result — Java's own reader accepts the shape.

The encryption of the safe bags does not move: decrypting these fixtures still
needs the original password, so they are containers whose *integrity check*
passes with no password at all — the A3 condition as a real container.

Usage: p12-empty-mac.py in.p12 out.p12
"""
import hashlib
import hmac
import sys


def parse_len(whole):
    """Number of header bytes (tag + length octets) of a definite-length TLV."""
    i = 1
    if whole[0] & 0x1F == 0x1F:          # high tag number form
        while whole[i] & 0x80:
            i += 1
        i += 1
    fl = whole[i]
    return i + 1 if fl < 0x80 else i + 1 + (fl & 0x7F)


def parse(b, i=0):
    """One definite-length TLV starting at i -> (whole_bytes, next_index).

    An indefinite length is refused: rewriting a BER file byte-exact is a
    different job, and the BER fixtures here carry real MACs."""
    j = 1
    if b[i] & 0x1F == 0x1F:
        while b[i + j] & 0x80:
            j += 1
        j += 1
    first = b[i + j]
    if first < 0x80:
        hdr, ln = j + 1, first
    else:
        n = first & 0x7F
        if n == 0:
            raise ValueError("indefinite length: re-MACing a BER file is not supported")
        ln = int.from_bytes(b[i + j + 1:i + j + 1 + n], "big")
        hdr = j + 1 + n
    return b[i:i + hdr + ln], i + hdr + ln


def content(whole):
    """The body of a definite-length TLV (everything past its header)."""
    return whole[parse_len(whole):]


def tlv(tag, body):
    """Wrap a body in tag + minimal definite length."""
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    ln = len(body).to_bytes(max(1, (len(body).bit_length() + 7) // 8), "big")
    return bytes([tag, 0x80 | len(ln)]) + ln + body


def der_int(v):
    if v == 0:
        return tlv(0x02, b"\x00")
    be = v.to_bytes((v.bit_length() + 8) // 8, "big")
    if be[0] & 0x80:
        be = b"\x00" + be
    return tlv(0x02, be)


def kdf(idbyte, pw, salt, iters, outlen, v, name):
    """The PKCS#12 KDF of RFC 7292 B.2 — the same one openfirma implements;
    a fixture this computes but RustCrypto refused would show up as Java
    (`keytool -list`) opening it while nothing else does."""
    u = hashlib.new(name).digest_size
    d = bytes([idbyte]) * v

    def rep(s):
        if not s:
            return bytearray()
        n = v * -(-len(s) // v)
        return bytearray(s[i % len(s)] for i in range(n))

    I = rep(salt) + rep(pw)
    out = b""
    for rnd in range(-(-outlen // u)):
        a = hashlib.new(name, d + bytes(I)).digest()
        for _ in range(iters - 1):
            a = hashlib.new(name, a).digest()
        if rnd + 1 < -(-outlen // u):
            B = (a * (v // u + 1))[:v]
            for off in range(0, len(I), v):
                blk = int.from_bytes(I[off:off + v], "big")
                s = (blk + int.from_bytes(B, "big") + 1) % (1 << (8 * v))
                I[off:off + v] = s.to_bytes(v, "big")
        out += a
    return out[:outlen]


# hmacWith* OID bodies -> (hash name, KDF block size)
HMAC_OIDS = {
    b"\x06\x05+\x0e\x03\x02\x1a": ("sha1", 64),
    # (keys are the full OID TLV including tag 06 and length)
    b"\x06\t`\x86H\x01e\x03\x04\x02\x01": ("sha256", 64),
    b"\x06\t`\x86H\x01e\x03\x04\x02\x02": ("sha384", 128),
    b"\x06\t`\x86H\x01e\x03\x04\x02\x03": ("sha512", 128),
}


def main(src, dst):
    b = open(src, "rb").read()
    outer_whole, _ = parse(b)
    oc = content(outer_whole)                  # the PFX SEQUENCE's body
    version, i = parse(oc)                     # INTEGER 3
    auth_ci, i = parse(oc, i)                  # ContentInfo of the authSafe
    macs = []
    while i < len(oc):
        part, i = parse(oc, i)
        if content(part)[0] == 0x30:           # MacData is a SEQUENCE
            macs.append(part)
    assert macs, "no MacData in the source file"

    wrapped = content(content(auth_ci)[9:])    # strip OID; [0] wrapper
    auth_safe_octets = content(wrapped)        # the OCTET STRING holding authSafe
    auth_safe = content(auth_safe_octets)      # its content: what the MAC covers

    mac = macs[0]                              # reuse the first entry's parameters
    # The nesting is three SEQUENCEs deep — MacData { DigestInfo { AlgId, digest } }:
    # each step descends one content level, or the OID lookup below reads the
    # AlgorithmIdentifier as an OID. (An earlier version of this helper merged
    # two of these levels and failed exactly there.)
    mcd = content(mac)                         # MacData's body: DigestInfo, salt, iterations
    digest_info, j = parse(mcd)                # DigestInfo | salt OCTET STRING | INTEGER
    di_body = content(digest_info)             # its body: AlgorithmIdentifier then digest
    alg_whole, _ = parse(di_body)              # the AlgorithmIdentifier TLV
    oid_tlv, _ = parse(content(alg_whole))     # OID is AlgId's first element
    # The map is keyed on the full OID TLV (tag 06 + length + body): keying on
    # the body alone collides sha1's `2b0e...` prefix with nothing else but
    # invites exactly this class of off-by-one-tag confusion.
    name, v = HMAC_OIDS[oid_tlv]
    salt_whole, k = parse(mcd, j)
    salt = content(salt_whole)
    iters = None
    if k < len(mcd):
        iters = int.from_bytes(content(parse(mcd, k)[0]), "big") or 1

    # The two empty-password encodings: OpenSSL/NSS's BMP terminator alone,
    # and Java's zero bytes. Each appended as its own MacData with its own
    # salt; a parser keeps whichever verifies — which is exactly how one file
    # exercises both spellings.
    extra = b""
    for i_pw, pw in enumerate((b"\x00\x00", b"")):
        s = salt if i_pw == 0 else bytes(x ^ 0x5B for x in salt)
        key = kdf(3, pw, s, iters, hashlib.new(name).digest_size, v, name)
        digest = hmac.new(key, auth_safe, name).digest()
        di = tlv(0x30, tlv(0x30, oid_tlv) + tlv(0x04, digest))
        body = di + tlv(0x04, s) + (der_int(iters) if iters else b"")
        extra += tlv(0x30, body)

    open(dst, "wb").write(tlv(0x30, oc + extra))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
