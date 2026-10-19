//! Shared builders for the integration tests. They live in `src/testkit.rs`
//! under `cfg(test)`, which only applies when the LIBRARY itself is compiled
//! as a test binary — invisible to an external test crate. The workspace rule
//! against copy-paste has its exception here on purpose: keep in sync with
//! src/testkit.rs, whose doc comment records why these exist at all.

#![allow(dead_code)] // each binary links only the builders it uses

/// The minimal catalog-with-pages shape: object 1 is the catalog exactly as
/// given, object 2 `/Pages`, object 3 the single page, behind a classic
/// cross-reference table whose trailer reads `/Size 4 /Root 1 0 R`.
pub fn mini_pdf(catalog: &str) -> Vec<u8> {
    let bodies: [&str; 3] = [
        catalog,
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>",
    ];
    build_pdf(&bodies, "/Size 4 /Root 1 0 R")
}

/// A one-revision PDF whose objects are the given bodies (numbered 1..=n) and
/// whose trailer is exactly `trailer` (without the angle brackets).
pub fn build_pdf(bodies: &[&str], trailer: &str) -> Vec<u8> {
    let mut out = Vec::from(&b"%PDF-1.4\n"[..]);
    let mut offsets = Vec::new();
    for (i, body) in bodies.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{body}\nendobj\n", i + 1).as_bytes());
    }
    write_xref(&mut out, &offsets, trailer);
    out
}

/// Appends the classic cross-reference table for `offsets` — entry `n` is
/// object `n+1`, generation 0 — the given trailer and the startxref record.
pub fn write_xref(out: &mut Vec<u8>, offsets: &[usize], trailer: &str) {
    let xref_at = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n", offsets.len() + 1).as_bytes());
    out.extend_from_slice(b"0000000000 65535 f \n");
    for off in offsets {
        out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(format!("trailer\n<< {trailer} >>\nstartxref\n").as_bytes());
    out.extend_from_slice(format!("{xref_at}\n%%EOF\n").as_bytes());
}

/// The RSA signer of the throwaway PKI, or `None` when it has not been
/// generated. Present-but-unloadable material panics rather than skipping.
pub fn test_signer() -> Option<openfirma_core::signer::SoftwareSigner> {
    use openfirma_core::cert::CertificateHandle;
    use openfirma_core::signer::SoftwareSigner;
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs");
    let read = |name: &str| std::fs::read_to_string(dir.join(name));
    let (Ok(cert), Ok(key)) = (read("signer-rsa.crt"), read("signer-rsa.key")) else {
        return None;
    };
    let signer = SoftwareSigner::from_pkcs8_pem(&cert, &key).unwrap_or_else(|e| {
        panic!("the test PKI is present but unusable: {e}. Rerun tools/gen-testcert.sh")
    });
    let chain = ["intermediate.crt", "ca.crt"]
        .iter()
        .map(|c| {
            CertificateHandle::from_pem(&read(c).expect("the test PKI is incomplete"))
                .expect("not a certificate")
        })
        .collect();
    Some(signer.with_chain(chain))
}

// ---------------------------------------------------------------------------
// The document round two's 02-N-4 was measured on: what a producer hands a signing
// tool, and therefore the shape a SECOND signature has to live with.

/// The XMP packet `gs` writes into `/Metadata`: three `xmp:` dates and nothing a
/// signing pass has a reason to touch.
pub const XMP_PACKET: &str = r#"<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999-02-22-rdf-syntax-ns#">
  <rdf:Description rdf:about="" xmlns:xmp="http://ns.adobe.com/xap/1.0/">
   <xmp:CreateDate>2026-10-19T10:11:06+02:00</xmp:CreateDate>
   <xmp:ModifyDate>2026-10-19T10:11:07+02:00</xmp:ModifyDate>
   <xmp:MetadataDate>2026-10-19T10:11:07+02:00</xmp:MetadataDate>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"#;

/// The same packet one second later, the way AutoFirma 1.9.1 leaves it on its second
/// pass: two elements differ, every other byte — the packet's length included — is
/// what the first revision carried.
pub const XMP_PACKET_LATER: &str = r#"<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999-02-22-rdf-syntax-ns#">
  <rdf:Description rdf:about="" xmlns:xmp="http://ns.adobe.com/xap/1.0/">
   <xmp:CreateDate>2026-10-19T10:11:06+02:00</xmp:CreateDate>
   <xmp:ModifyDate>2026-10-19T10:11:08+02:00</xmp:ModifyDate>
   <xmp:MetadataDate>2026-10-19T10:11:08+02:00</xmp:MetadataDate>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"#;

/// `/Info` as the producer writes it, with the `/Producer` a signing pass leaves
/// alone. The `/Author` is a key that is not one of the two dates and carries a
/// well-formed PDF date as its value: the shape that only the key-name guard on the
/// date rule can refuse.
pub const INFO_BODY: &str = "<< /Producer (GPL Ghostscript 10.08.0) \
     /Author (D:20261019101107+02'00') \
     /CreationDate (D:20261019101106+02'00') /ModDate (D:20261019101107+02'00') >>";

/// The same dictionary the way iText writes it — no spaces — with `/ModDate` one
/// second later, `/Producer` and `/Author` byte for byte intact.
pub const INFO_BODY_LATER: &str = "<</Producer(GPL Ghostscript 10.08.0)\
     /Author(D:20261019101107+02'00')\
     /CreationDate(D:20261019101106+02'00')/ModDate(D:20261019101108+02'00')>>";

/// The object numbers `xmp_document` writes, so a test can name what it rewrites.
pub const METADATA_OBJ: u32 = 4;
pub const CONTENT_OBJ: u32 = 6;
pub const INFO_OBJ: u32 = 7;

/// A one-page document whose catalog names an XMP `/Metadata` stream and whose
/// trailer names an `/Info` dictionary, both dated `XMP_PACKET` / `INFO_BODY`. This
/// is the input `gs` hands a signing tool, and the reason the revision gate has to
/// understand a date refresh: refusing it refused the reference tool's own second
/// signature (round two, 02-N-4).
pub fn xmp_document() -> Vec<u8> {
    let metadata = format!(
        "<< /Type /Metadata /Subtype /XML /Length {} >>\nstream\n{}\nendstream",
        XMP_PACKET.len(),
        XMP_PACKET
    );
    let content = format!(
        "<< /Length {} >>\nstream\n{}\nendstream",
        b"BT /F1 24 Tf 72 700 Td (PAGO UN CERO UNO) Tj ET".len(),
        "BT /F1 24 Tf 72 700 Td (PAGO UN CERO UNO) Tj ET"
    );
    let bodies: &[&str] = &[
        "<< /Type /Catalog /Pages 2 0 R /Metadata 4 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 6 0 R \
         /Resources << /Font << /F1 5 0 R >> >> >>",
        &metadata,
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        &content,
        INFO_BODY,
    ];
    build_pdf(bodies, "/Size 8 /Root 1 0 R /Info 7 0 R")
}
