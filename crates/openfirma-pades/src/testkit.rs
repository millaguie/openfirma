//! Shared PDF builders for the crate's unit and integration tests. Every
//! document a test signs or parses has to be synthetic and small (AGENT-BRIEF:
//! committed fixtures only when they earn their bytes), so the one-page PDFs —
//! including the hostile shapes of the adversarial review — are assembled here
//! byte by byte, behind correct classic cross-reference tables, instead of
//! being committed as binaries. `tests/common` re-exports these so unit tests
//! and integration tests build exactly the same documents.

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

/// A one-page-revision PDF whose objects are the given bodies (numbered
/// 1..=n) and whose trailer is exactly `trailer` (without the angle brackets)
/// — so a test can write a trailer with no `/Size`, with an `/ID`, with an
/// `/Encrypt` reference, anything the finding under test describes.
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
/// generated. Present-but-unloadable material panics rather than skipping: a
/// silent skip once hid that every signing test was passing without signing.
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
