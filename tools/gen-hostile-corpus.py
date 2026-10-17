"""Deterministic hostile-corpus generator (H-11).

Single source of truth for testdata/hostile/: byte mutations of *valid*
specimens, produced by a fixed recipe so the corpus is reproducible from
this script alone.  Run `python3 tools/gen-hostile-corpus.py` to regenerate;
the committed files must match byte for byte (the test suite's sibling check
recomputes sha256 of every file against the README table).
"""
import hashlib, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent / "testdata" / "hostile"
VALID_CMS_PREFIX = bytes.fromhex("3082016606092a864886f70d010702")  # SE(358) + signedData OID — a real SignedInfo header, truncated here on purpose

def main():
    files = {}
    # --- DER: length-field attacks shared by CMS/TSP/OCSP/p12 parsers
    files["der-contentinfo-trunc.der"] = VALID_CMS_PREFIX[:4]              # 30 82 01 -> claims 2 octets, has 1
    files["der-longlen-huge.der"] = (bytes.fromhex("3089") + b"\xff" * 9 + b"\x00")  # 2^64 length claim
    files["der-seq-eol.der"] = bytes.fromhex("30050201FF")                 # SEQ(5) with only 3 payload bytes
    files["der-null-len.der"] = bytes.fromhex("3080")                      # indefinite length: not DER, must refuse
    # --- XML: truncation / undeclared namespace / deep nesting (parser MAX_DEPTH is 512; 140 must succeed)
    files["xml-truncated-tag.xml"] = (b"<root xmlns='http://www.w3.org/2000/09/xmldsig#'>"
                                      b"<SignedInfo Id=")
    files["xml-undeclared-prefix.xml"] = (b"<xades:XLen xmlns:a='urn:x'>"
                                          b"<b:y>deep</b:y></xades:XLen>")
    files["xml-deep-nesting.xml"] = b"<a>" * 140 + b"x" + b"</a>" * 140
    files["xml-bad-utf8.xml"] = b"<root>\xff\xfe<child/>"
    # --- PKCS#12: truncated and junk-shaped (both paths must error, not panic)
    files["p12-garbage-head.p12"] = VALID_CMS_PREFIX[:4] + hashlib.sha256(b"openfirma-hostile-seed").digest()[:40]
    files["p12-truncated-header.p12"] = VALID_CMS_PREFIX[:2]               # PFX SEQ claims 358 bytes, has 2

    for name, data in sorted(files.items()):
        (ROOT / name).write_bytes(data)
        print(f"{name:28} {len(data):5}  sha256 {hashlib.sha256(data).hexdigest()}")

if __name__ == "__main__":
    main()
