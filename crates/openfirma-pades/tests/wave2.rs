//! Robustness of what signing does to the document, against offsets a hostile
//! file declares. Wave 2 of the adversarial review: an encrypted input must
//! be refused rather than destroyed (C-2), the appended trailer must carry
//! `/ID` over and reference the `/Info` it writes (A-1, M-1), a certification
//! (`/Perms /DocMDP` `/P 1`) must stop signing unless told otherwise and must
//! be flagged by `verify` when revisions followed it (A-2), usage rights are
//! withdrawn before signing (M-4), the page tree is walked once per node
//! (M-5), a declared offset or width past the end of the file produces an
//! error rather than a panic (M-6), and a trailer with no `/Size` refuses to
//! sign instead of numbering new objects over existing ones (B-1).
//!
//! Every hostile document here is built byte by byte from `common`: small,
//! synthetic, and exactly the shape the finding describes — the reviewer's
//! own PoCs (an qpdf-encrypted file, an object-stream document that lost its
//! `/ID`, a `/Kids` bomb) reproduce from these few dozen bytes.

mod common;

use common::{build_pdf, mini_pdf, test_signer};
use openfirma_pades::{PadesOptions, pdf};

fn opts() -> PadesOptions {
    PadesOptions::default()
}

/// C-2: `qpdf --encrypt user owner 256 -- simple.pdf` produces a first
/// revision whose trailer names an `/Encrypt` dictionary; the file openfirma
/// used to produce from it was an *unencrypted* document whose streams were
/// still ciphertext — qpdf read it as "File is not encrypted" and then failed
/// to decode every stream. Signing now refuses it at the first trailer it
/// reads, with the way out in the message. The committed PoC equivalent: any
/// trailer naming /Encrypt, at any revision depth (the two-revision half below
/// covers a file whose newest trailer dropped the key an older one carried).
#[test]
fn signing_an_encrypted_pdf_is_refused_with_the_way_out() {
    let Some(signer) = test_signer() else {
        eprintln!("skipped, test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    // The /Encrypt dictionary is object 4; the trailer names it exactly as
    // qpdf's output does. No password can be relevant: openfirma never reads
    // an encrypted document at all.
    let enc = build_pdf(
        &[
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>",
            "<< /Filter /Standard /V 4 /R 4 /Length 128 /P -4 >>",
        ],
        "/Size 5 /Root 1 0 R /Encrypt 4 0 R /ID [<6162> <6162>]",
    );
    let err = openfirma_pades::pades_sign(&enc, &signer, &opts())
        .expect_err("an encrypted document must never be signed into a broken one");
    let text = err.to_string();
    assert!(
        text.contains("/Encrypt"),
        "the refusal names the key: {text}"
    );
    assert!(
        text.contains("--decrypt"),
        "the refusal gives the way out (qpdf --decrypt): {text}"
    );
    // reading is not signing: inspect still reports a document whose newest
    // revision has no encryption dictionary of its own, but a trailer walk
    // must never crash on this shape either.
    let _ = openfirma_pades::inspect::signatures(&enc);
}

/// C-2's second half: the reviewer's signed-and-re-encrypted PoC kept the
/// /Encrypt reference in an OLDER revision's trailer while the newest trailer
/// dropped it. A document like that is still encrypted to every reader that
/// honours the chain (and ISO 32000-1 7.5.6 forbids a new trailer from
/// changing /Encrypt at all), so signing it is refused as well.
#[test]
fn an_older_revision_holding_encrypt_is_refused_too() {
    let Some(signer) = test_signer() else {
        eprintln!("skipped, test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    // revision 1: a full one-page document whose trailer names /Encrypt
    let first = build_pdf(
        &[
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>",
            "<< /Filter /Standard /V 2 /R 3 /Length 40 /P -4 >>",
        ],
        "/Size 5 /Root 1 0 R /Encrypt 4 0 R",
    );
    let first_xref = pdf::last_startxref(&first).unwrap();
    // revision 2: one new object, a trailer without /Encrypt but with /Prev
    let mut out = first;
    let appended_at = out.len();
    out.extend_from_slice(b"\n5 0 obj\n<< /Spared 1 >>\nendobj\n");
    let xref_at = out.len();
    out.extend_from_slice(
        format!(
            "xref\n5 1\n{appended_at:010} 00000 n \ntrailer\n<< /Size 6 /Root 1 0 R /Prev \
             {first_xref} >>\nstartxref\n{xref_at}\n%%EOF\n"
        )
        .as_bytes(),
    );
    let err = openfirma_pades::pades_sign(&out, &signer, &opts())
        .expect_err("a document whose earlier revision was encrypted is still encrypted");
    assert!(err.to_string().contains("/Encrypt"), "{err}");
}

/// A-1: the reviewer signed `qpdf --object-streams=generate simple.pdf` and
/// got a trailer of `<< /Prev … /Root … /Size … >>` — no `/ID`. ISO 32000-1
/// 7.5.6 requires the appended trailer to carry all the previous entries
/// except /Prev, PDF/A and PDF 2.0 require /ID, and AutoFirma's golden output
/// carries it. openfirma now copies the earlier trailer and writes its own
/// keys on top: /ID (and any other key) survive byte for byte.
#[test]
fn the_appended_trailer_carries_the_previous_id_and_extra_keys() {
    let Some(signer) = test_signer() else {
        eprintln!("skipped, test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    // A document whose trailer holds /ID and a vendor key: exactly the shape
    // qpdf's --object-streams output has (it always writes /ID).
    let doc = build_pdf(
        &[
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>",
        ],
        "/Size 4 /Root 1 0 R /ID [<0011> <0011>] /MyVendorKey 42",
    );
    let signed = openfirma_pades::pades_sign(&doc, &signer, &opts()).expect("signing failed");
    let at = pdf::last_startxref(&signed).unwrap();
    let dict = pdf::trailer_dict(&signed, at).unwrap();
    let text = String::from_utf8_lossy(&dict).to_string();
    assert!(text.contains("/ID [<0011> <0011>]"), "carried over: {text}");
    assert!(
        text.contains("/MyVendorKey 42"),
        "every key survives: {text}"
    );
    // and the revision still reads back through its own chain. The identifier
    // itself is carried by the WRITER (asserted byte for byte above, which is
    // what PDF/A and PDF 2.0 ask of one); it is not part of the reader's
    // immutability rule any more, because iText regenerates it on every append
    // and a document AutoFirma signed twice must stay readable — measured, and
    // `an_append_that_regenerates_the_file_id_is_still_read` in revisions.rs
    // holds the other end of it.
    let tr = pdf::trailer(&signed, at).unwrap();
    assert!(tr.prev.is_some());
}

/// M-1: the reviewer's s1.pdf had object 11 — a fresh `/Info` with /ModDate —
/// in the xref while the trailer was `<< /Size 12 /Root 1 0 R /Prev … >>`:
/// the dictionary was written and then orphaned. Signing a document with no
/// /Info now writes one AND names it in the trailer; signing one that has an
/// /Info keeps its reference and rewrites its bytes under the same number.
#[test]
fn the_info_object_the_signature_writes_is_the_one_the_trailer_names() {
    let Some(signer) = test_signer() else {
        eprintln!("skipped, test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    // no /Info anywhere (mini_pdf): the fixture simple.pdf is this shape, and
    // so was every document AutoFirma's golden diff compares against
    let signed = openfirma_pades::pades_sign(
        &mini_pdf("<< /Type /Catalog /Pages 2 0 R >>"),
        &signer,
        &opts(),
    )
    .expect("signing failed");
    let at = pdf::last_startxref(&signed).unwrap();
    let tr = pdf::trailer(&signed, at).unwrap();
    let info = tr
        .info
        .expect("M-1: the trailer must reference the /Info it wrote");
    let locations = pdf::object_locations(&signed, at).unwrap();
    let body = pdf::resolve(&signed, &locations, None, info).unwrap();
    assert!(
        String::from_utf8_lossy(&body).contains("/ModDate"),
        "the referenced /Info carries the date: {}",
        String::from_utf8_lossy(&body)
    );

    // with an /Info already in the document: same object number, kept reference
    let doc = build_pdf(
        &[
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>",
            "<< /Title (documento) >>",
        ],
        "/Size 5 /Root 1 0 R /Info 4 0 R",
    );
    let signed = openfirma_pades::pades_sign(&doc, &signer, &opts()).expect("signing failed");
    let at = pdf::last_startxref(&signed).unwrap();
    let tr = pdf::trailer(&signed, at).unwrap();
    assert_eq!(
        tr.info,
        Some(pdf::ObjRef::new(4, 0)),
        "the author's /Info object"
    );
    let locations = pdf::object_locations(&signed, at).unwrap();
    let body = pdf::resolve(&signed, &locations, None, tr.info.unwrap()).unwrap();
    let text = String::from_utf8_lossy(&body).to_string();
    assert!(
        text.contains("/Title (documento)"),
        "the splice keeps /Title: {text}"
    );
    assert!(text.contains("/ModDate"), "and stamps the date: {text}");
}

/// M-2: PDF/A. ISO 19005-1 requires xmp:ModifyDate in the /Metadata stream to
/// equal /Info /ModDate, and openfirma does not rewrite the XMP packet (the
/// simpler conforming choice, docs/pades.md). A document whose XMP packet
/// declares a conformance part therefore gets NO new /Info at all, so the pair
/// the producer wrote stays as it was.
///
/// Round 2's N-2: the declaration is `pdfaid:part` in the packet's *data*
/// (that is where ISO 19005-1 puts it), and the detection used to look for it
/// as a key of the stream dictionary — a shape no producer writes. The review
/// built a real PDF/A with `gs -dPDFA=2`, signed it, and the file came out with
/// a fresh /ModDate against an XMP the signature never touched. The packets
/// below are the shape Ghostscript writes, both uncompressed and
/// FlateDecode-compressed, because producers compress them and the detection
/// has to read through the filter chain.
#[test]
fn a_pdf_a_identity_declaration_stops_the_moddate_rewrite() {
    let Some(signer) = test_signer() else {
        eprintln!("skipped, test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    for (packet, compress) in [
        (PDFA_PACKET, false),
        (PDFA_PACKET, true),
        // the same declaration as an attribute, the other spelling producers
        // write (`pdfaid:part='2'` on the rdf:Description)
        (PDFA_PACKET_ATTRIBUTES, true),
    ] {
        let doc = with_metadata(packet.as_bytes(), compress);
        // /Info is object 5 (with_metadata numbers in order); its bytes must
        // survive untouched inside the signed file
        let at = pdf::last_startxref(&doc).unwrap();
        let info_at = {
            let locations = pdf::object_locations(&doc, at).unwrap();
            match locations[&pdf::ObjRef::new(5, 0)] {
                pdf::Location::Direct(off) => off,
                _ => panic!("classic table names direct offsets"),
            }
        };
        let old_info = {
            let span = pdf::object_body(&doc, info_at).unwrap();
            doc[span].to_vec()
        };

        let signed = openfirma_pades::pades_sign(&doc, &signer, &opts()).expect("signing failed");
        assert!(signed.starts_with(&doc), "the original revision survives");
        let at = pdf::last_startxref(&signed).unwrap();
        let tr = pdf::trailer(&signed, at).unwrap();
        let locations = pdf::object_locations(&signed, at).unwrap();
        // the newest definition of object 5 is still exactly the author's
        // bytes: no rewrite happened (a rewritten one would carry today's
        // ModDate, which the XMP ModifyDate would contradict)
        let current = pdf::resolve(&signed, &locations, None, tr.info.unwrap()).unwrap();
        assert_eq!(
            current.as_ref(),
            old_info.as_slice(),
            "a PDF/A document's /Info keeps its bytes (compressed={compress}): the XMP \
             ModifyDate would be left behind"
        );
    }

    // control: the same document whose packet carries no conformance
    // declaration IS stamped — an XMP without pdfaid:part is not a PDF/A claim
    let plain = with_metadata(PLAIN_PACKET.as_bytes(), true);
    let signed = openfirma_pades::pades_sign(&plain, &signer, &opts()).expect("signing failed");
    let at = pdf::last_startxref(&signed).unwrap();
    let tr = pdf::trailer(&signed, at).unwrap();
    let locations = pdf::object_locations(&signed, at).unwrap();
    let current = pdf::resolve(&signed, &locations, None, tr.info.unwrap()).unwrap();
    assert!(
        String::from_utf8_lossy(&current).contains("/ModDate (D:20")
            && !String::from_utf8_lossy(&current).contains("(D:20000101000000Z)"),
        "an ordinary document keeps being stamped: {}",
        String::from_utf8_lossy(&current)
    );
}

/// The packet `gs -dPDFA=2` writes, trimmed to what matters: the declaration
/// lives in the `http://www.aiim.org/pdfa/ns/id/` namespace inside the RDF, as
/// an ordinary element. `xmp:ModifyDate` is the date the /Info copy has to
/// agree with.
const PDFA_PACKET: &str = r#"<?xpacket begin="&#xFEFF;" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="GPL Ghostscript">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about=""
    xmlns:pdfaid="http://www.aiim.org/pdfa/ns/id/">
   <pdfaid:part>2</pdfaid:part>
   <pdfaid:conformance>B</pdfaid:conformance>
  </rdf:Description>
  <rdf:Description rdf:about=""
    xmlns:xmp="http://ns.adobe.com/xap/1.0/">
   <xmp:ModifyDate>2000-01-01T00:00:00Z</xmp:ModifyDate>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"#;

/// The same declaration in its other spelling: the `pdfaid` namespace is
/// declared on the `rdf:Description` and `pdfaid:part` is an attribute of it,
/// which is how some producers (and the review's own `gs` output) write it.
const PDFA_PACKET_ATTRIBUTES: &str = r#"<?xpacket begin="&#xFEFF;" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about=""
    xmlns:pdfaid="http://www.aiim.org/pdfa/ns/id/"
    pdfaid:part="2" pdfaid:conformance="B"
    xmlns:xmp="http://ns.adobe.com/xap/1.0/">
   <xmp:ModifyDate>2000-01-01T00:00:00Z</xmp:ModifyDate>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"#;

/// The same packet for an ordinary document: XMP that says nothing about PDF/A
/// conformance.
const PLAIN_PACKET: &str = r#"<?xpacket begin="&#xFEFF;" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about=""
    xmlns:xmp="http://ns.adobe.com/xap/1.0/">
   <xmp:CreatorTool>openfirma tests</xmp:CreatorTool>
   <xmp:ModifyDate>2000-01-01T00:00:00Z</xmp:ModifyDate>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"#;

/// The same minimal document as `common::build_pdf`, with a real `/Metadata`
/// stream carrying `packet` as its data — compressed with FlateDecode when
/// `compress`, the way every producer stores it. `build_pdf` takes `&str`
/// bodies, and a compressed packet is not text.
fn with_metadata(packet: &[u8], compress: bool) -> Vec<u8> {
    let data = if compress {
        deflate(packet)
    } else {
        packet.to_vec()
    };
    let filter = if compress {
        " /Filter /FlateDecode"
    } else {
        ""
    };
    let mut metadata = format!(
        "<< /Type /Metadata /Subtype /XML{filter} /Length {} >>\nstream\n",
        data.len()
    )
    .into_bytes();
    metadata.extend_from_slice(&data);
    metadata.extend_from_slice(b"\nendstream");

    let bodies: [&[u8]; 5] = [
        b"<< /Type /Catalog /Pages 2 0 R /Metadata 4 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>",
        &metadata,
        b"<< /ModDate (D:20000101000000Z) /Producer (author) >>",
    ];
    let mut out = Vec::from(&b"%PDF-1.4\n"[..]);
    let mut offsets = Vec::new();
    for (i, body) in bodies.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    common::write_xref(&mut out, &offsets, "/Size 6 /Root 1 0 R /Info 5 0 R");
    out
}

fn deflate(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).expect("zlib encoder");
    enc.finish().expect("zlib encoder")
}

/// A-2, the signing half: `/Perms /DocMDP` with `/TransformParams /P 1` says
/// no changes are permitted, and adding a signature breaks that certification
/// in every reader that honours it. AutoFirma refuses such a document unless
/// its caller passes allowSigningCertifiedPdfs; openfirma likewise refuses and
/// names the opt-in, then signs when explicitly allowed. /Perms is written
/// here in the PDF 2.0 shape — one /Reference dictionary under /DocMDP — which
/// iText produces for certifications; the older flat shape reads through the
/// same path (both spellings are accepted).
#[test]
fn a_p1_certification_refuses_signing_unless_told_otherwise() {
    let Some(signer) = test_signer() else {
        eprintln!("skipped, test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let certified = mini_pdf(
        "<< /Type /Catalog /Pages 2 0 R \
         /Perms << /DocMDP << /Reference << /TransformParams << /P 1 /V 2 >> /Type /TransformParams >> >> >> >>",
    );
    let err = openfirma_pades::pades_sign(&certified, &signer, &opts())
        .expect_err("a P=1 certification forbids this change");
    let text = err.to_string();
    assert!(
        text.contains("/DocMDP"),
        "the refusal names the certification: {text}"
    );
    assert!(
        text.contains("allow_signing_certified") || text.contains("--allow-certified"),
        "and says how to override it: {text}"
    );

    let allowed = PadesOptions {
        allow_signing_certified: true,
        ..PadesOptions::default()
    };
    let signed = openfirma_pades::pades_sign(&certified, &signer, &allowed)
        .expect("the explicit opt-in signs the certified document");
    assert!(
        signed.starts_with(&certified),
        "still an incremental update"
    );

    // P=2 (filling in form fields and signing is permitted): no refusal. The
    // /Reference array form is the other shape AutoFirma meets; read it too.
    let lenient = mini_pdf(
        "<< /Type /Catalog /Pages 2 0 R \
         /Perms << /DocMDP << /Reference [<< /TransformParams << /P 2 /V 2 >> >>] >> >> >>",
    );
    openfirma_pades::pades_sign(&lenient, &signer, &opts()).expect("P=2 permits signing");

    // an indirect /Perms dictionary resolves through the cross-reference
    let indirect = build_pdf(
        &[
            "<< /Type /Catalog /Pages 2 0 R /Perms 4 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>",
            "<< /DocMDP << /Reference << /TransformParams << /P 1 /V 2 >> >> >> >>",
        ],
        "/Size 5 /Root 1 0 R",
    );
    let err = openfirma_pades::pades_sign(&indirect, &signer, &opts())
        .expect_err("an indirect /Perms says the same thing");
    assert!(err.to_string().contains("/DocMDP"), "{err}");
}

/// A-2, the verification half: a document certified with P=1 that has any
/// revision after the certification reads as a broken certification (Adobe
/// and AutoFirma's validator both say so), so `verify` must report it while
/// its signatures still close over their own revisions. The PoC is one small
/// PDF built here: an uncertified page signed, then a forged revision whose
/// catalog rewrites /Perms as a P=1 certification that points at the signature
/// of the older revision — a certification-after-the-fact — and on top of that
/// one more honest append that changes the page.
#[test]
fn verify_flags_revisions_after_a_p1_certification() {
    let Some(signer) = test_signer() else {
        eprintln!("skipped, test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    // First: an ordinary signed document (its own revision chain is honest).
    let first = openfirma_pades::pades_sign(
        &mini_pdf("<< /Type /Catalog /Pages 2 0 R >>"),
        &signer,
        &opts(),
    )
    .expect("signing failed");

    // A forged final revision: it redefines /Root (object 1), keeping the keys
    // the signed catalog had and adding /Perms /DocMDP P=1 whose /Reference
    // points (/V) at the signature object of an EARLIER revision. Signatures
    // are found through the whole file by inspect (each covers its own bytes),
    // which is what made verify silent about the certification before this
    // fix; a reader with certification support marks every change after the
    // certified state as breaking it.
    let first_at = pdf::last_startxref(&first).unwrap();
    let sig_obj = {
        let locations = pdf::object_locations(&first, first_at).unwrap();
        *locations
            .keys()
            .find(|r| {
                pdf::resolve(&first, &locations, None, **r).is_ok_and(|b| {
                    pdf::get(&b, "/Type").is_some_and(|t| pdf::trim_ws(t) == b"/Sig")
                })
            })
            .expect("the first signature's dictionary")
    };
    let catalog = {
        let tr = pdf::trailer(&first, first_at).unwrap();
        let locations = pdf::object_locations(&first, first_at).unwrap();
        let acro = pdf::get(
            &pdf::resolve(&first, &locations, None, tr.root).unwrap(),
            "/AcroForm",
        )
        .map(|v| pdf::trim_ws(v).to_vec());
        let mut s = String::from("<< /Type /Catalog /Pages 2 0 R ");
        if let Some(v) = acro {
            s.push_str("/AcroForm ");
            s.push_str(&String::from_utf8_lossy(&v));
            s.push(' ');
        }
        s.push_str("/Perms << /DocMDP << /Reference [ << /TransformParams << /Type /TransformParams /P 1 /V 2 >> /DigestMethod /SHA256 /DigestLocation /Document-Level /Weight 1 >> ] /V ");
        s.push_str(&sig_obj.to_string());
        s.push_str(" /M (D:20260103000000Z) >> >> >>");
        s
    };
    // The certification-after-the-fact closes the CERTIFYING revision honestly —
    // its record names this revision's own cross-reference — and only then does
    // another revision get appended on top of it, redefining the one page with
    // different bytes. wave 1's chain scan delimits both appends fine (their
    // records name their own sections; there is no middle), yet its whitelist
    // sees only "the catalog gained /Perms and the page changed", sentences
    // that never mention the certification the document now claims. Only this
    // gate can say what a reader with certification support shows: a P=1
    // certification broken by revisions after it.
    let prev_size = pdf::trailer(&first, first_at).unwrap().size.unwrap_or(10);
    let mut forged = first.clone();
    forged.extend_from_slice(b"\n");
    let cat_at = forged.len();
    forged.extend_from_slice(format!("1 0 obj\n{catalog}\nendobj\n").as_bytes());
    // Same generation, new offset: the newest entry wins a merged read (the way
    // openfirma's own writer supersedes objects it rewrites).
    let mid_xref = {
        let xref_at = forged.len();
        forged.extend_from_slice(
            format!(
                "xref\n1 1\n{cat_at:010} 00000 n \ntrailer\n\
                 << /Size {prev_size} /Root 1 0 R /Prev {first_at} >>\nstartxref\n{xref_at}\n%%EOF\n"
            )
            .as_bytes(),
        );
        xref_at
    };
    // On top of it: one more revision closing its own cross-reference honestly,
    // which redefines the page with different bytes — a plain change after the
    // certification, and what wave 1's whitelist separately refuses.
    forged.extend_from_slice(b"\n");
    let page_at = forged.len();
    forged.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n",
    );
    let xref_at = forged.len();
    forged.extend_from_slice(
        format!(
            "xref\n3 1\n{page_at:010} 00000 n \ntrailer\n<< /Size {prev_size} /Root 1 0 R /Prev {mid_xref} >>\nstartxref\n{xref_at}\n%%EOF\n"
        )
        .as_bytes(),
    );

    // sanity: the older signature still passes its own integrity (inspect
    // reads it), which is what made verify silent about the certification.
    let sigs = openfirma_pades::inspect::signatures(&forged).expect("readable");
    assert_eq!(sigs.len(), 1);

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs");
    let Ok(chain) = std::fs::read_to_string(dir.join("intermediate.crt")) else {
        eprintln!("skipped, test PKI missing");
        return;
    };
    let ca = std::fs::read_to_string(dir.join("ca.crt")).unwrap();
    let opts = openfirma_cades::verify::VerifyOptions::new(vec![
        openfirma_core::CertificateHandle::from_pem(&chain).unwrap(),
        openfirma_core::CertificateHandle::from_pem(&ca).unwrap(),
    ]);
    let err = openfirma_pades::pades_verify(&forged, &opts)
        .expect_err("a revision after a P=1 certification must not pass clean");
    let text = err.to_string();
    assert!(
        text.contains("certif") && (text.contains("/P 1") || text.contains("P 1")),
        "verify flags the broken certification: {text}"
    );
    // and it says so on top of what wave 1 already refuses for its own sake:
    // both sentences are in the output, not one hiding the other.
    assert!(
        text.contains("was followed by changes no archive may append"),
        "the revisions gate still speaks too: {text}"
    );
    // N-6: the sentence a user reads is one sentence. The literals of the
    // certification gate were missing their line continuations, so the message
    // carried a strip of ~25 spaces where the source wrapped; this pins both
    // the shape of the text and that nothing else in it grew a run of spaces.
    assert!(
        text.contains("(no changes permitted), and the document has"),
        "the certification sentence reads as one: {text:?}"
    );
    assert!(
        !text.contains("  "),
        "no run of spaces from a line break that was not continued: {text:?}"
    );
}

/// M-4: AutoFirma strips usage rights (`removeUsageRights`) before signing;
/// a signed document that still carries /Perms /UR3 shows Adobe's extended-
/// features warning over a state of the file that no longer exists. openfirma
/// now removes /UR3 (and the older /UR) from /Perms while signing, leaving
/// every other key of /Perms byte for byte — and documents without usage
/// rights keep their /Perms untouched entirely (the catalog is not rewritten
/// at all when nothing had to change).
#[test]
fn signing_withdraws_usage_rights_and_keeps_the_rest_of_perms() {
    let Some(signer) = test_signer() else {
        eprintln!("skipped, test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let doc = mini_pdf(
        "<< /Type /Catalog /Pages 2 0 R \
         /Perms << /UR3 << /P 3 >> /SigStamp << /V 1 >> >> >>",
    );
    let signed = openfirma_pades::pades_sign(&doc, &signer, &opts()).expect("signing failed");
    assert!(signed.starts_with(&doc), "the original revision survives");
    let at = pdf::last_startxref(&signed).unwrap();
    let tr = pdf::trailer(&signed, at).unwrap();
    let locations = pdf::object_locations(&signed, at).unwrap();
    let catalog = pdf::resolve(&signed, &locations, None, tr.root).unwrap();
    let perms = pdf::get(&catalog, "/Perms").expect("the document still has /Perms");
    assert!(
        pdf::get(perms, "/UR3").is_some_and(|v| pdf::trim_ws(v) == b"null"),
        "/UR3 is withdrawn: {}",
        String::from_utf8_lossy(perms)
    );
    assert!(
        perms.windows(12).any(|w| w == b"/SigStamp <<"),
        "the rest of /Perms survives byte for byte: {}",
        String::from_utf8_lossy(perms)
    );

    // no usage rights: the catalog is not rewritten at all, so an unchanged
    // /AcroForm-less document keeps the revision's object set minimal. A doc
    // with /Perms but no UR/UR3 keeps both keys untouched.
    let untouched = mini_pdf("<< /Type /Catalog /Pages 2 0 R /Perms << /SigStamp << /V 1 >> >> >>");
    let signed = openfirma_pades::pades_sign(&untouched, &signer, &opts()).expect("signing failed");
    let at = pdf::last_startxref(&signed).unwrap();
    let tr = pdf::trailer(&signed, at).unwrap();
    let locations = pdf::object_locations(&signed, at).unwrap();
    let catalog = pdf::resolve(&signed, &locations, None, tr.root).unwrap();
    assert!(
        String::from_utf8_lossy(&catalog).contains("/Perms << /SigStamp << /V 1 >> >>"),
        "nothing to remove means nothing rewritten: {}",
        String::from_utf8_lossy(&catalog)
    );
}

/// B-1: `/Size` absent read as 0, so the signature's objects were numbered
/// 0, 1, 2... — over the catalog, the page tree and the page itself in the
/// new revision, silently replacing pages with fonts. Signing a trailer with
/// no /Size is now an error that says so; and where /Size exists but lies
/// below the real object numbers, first_new takes the maximum of /Size and
/// the largest object number plus one, so objects are never overwritten.
#[test]
fn a_trailer_without_size_refuses_and_a_lying_size_never_overwrites() {
    let Some(signer) = test_signer() else {
        eprintln!("skipped, test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    // no /Size at all
    let doc = build_pdf(
        &[
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>",
        ],
        "/Root 1 0 R",
    );
    let err = openfirma_pades::pades_sign(&doc, &signer, &opts())
        .expect_err("without /Size there is no honest place to put new objects");
    let text = err.to_string();
    assert!(
        text.contains("/Size"),
        "the refusal names what is missing: {text}"
    );

    // a trailer whose /Size lies: the page tree really holds object 3, and a
    // /Size of 2 would number the appearance as `1 0 obj` — over the catalog.
    let doc = build_pdf(
        &[
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>",
        ],
        "/Size 2 /Root 1 0 R",
    );
    let signed = openfirma_pades::pades_sign(&doc, &signer, &opts()).expect("signing failed");
    let at = pdf::last_startxref(&signed).unwrap();
    let locations = pdf::object_locations(&signed, at).unwrap();
    // every original object must still resolve to what it was: the page is a
    // /Page, not a Helvetica font dictionary (the reviewer's silent overwrite)
    let page = pdf::resolve(&signed, &locations, None, pdf::ObjRef::new(3, 0)).unwrap();
    assert_eq!(
        pdf::get(&page, "/Type").map(pdf::trim_ws),
        Some(b"/Page".as_slice()),
        "the page survived the lying /Size: {}",
        String::from_utf8_lossy(&page)
    );
}

fn unsafe_str_rfind(hay: &[u8], needle: &[u8]) -> usize {
    (0..hay.len().saturating_sub(needle.len()) + 1)
        .rev()
        .find(|i| &hay[*i..*i + needle.len()] == needle)
        .expect("the builder always writes a startxref record")
}

/// M-5: a page tree whose /Kids list names the same node twice replays its
/// whole subtree — three levels of `/Kids [N N]` are 2^3 visits, twenty are
/// 2^20 — and the old walk happily recursed through all of them while signing
/// a visible signature. The walk now remembers what it has seen and refuses
/// the repeat (what iText's PageRefs marks for), with an error that says how
/// to get out: fix the tree, do not sign the file as it stands.
#[test]
fn a_page_tree_that_repeats_a_child_is_refused_not_explored() {
    let Some(signer) = test_signer() else {
        eprintln!("skipped, test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    // object 2 is the root: /Kids [4 0 R 4 0 R], and 4 itself repeats the leaf
    // below it. Two levels already replay the leaf; a hostile document nests
    // this twenty deep, which is why a repeat must be an error and not work.
    let doc = build_pdf(
        &[
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [4 0 R 4 0 R] /Count 3 >>",
            "<< /Type /Page /Parent 4 0 R /MediaBox [0 0 595 842] >>",
            "<< /Type /Pages /Parent 2 0 R /Kids [3 0 R 3 0 R] /Count 2 >>",
        ],
        "/Size 5 /Root 1 0 R",
    );
    let visible = openfirma_pades::appearance::Appearance {
        page: 2,
        rect: [50.0, 760.0, 250.0, 800.0],
        label: None,
    };
    let opts = PadesOptions {
        visible: Some(visible),
        ..PadesOptions::default()
    };
    let err = openfirma_pades::pades_sign(&doc, &signer, &opts)
        .expect_err("a /Kids that repeats a child must be refused, not replayed");
    let text = err.to_string();
    assert!(
        text.contains("twice"),
        "the refusal names the repeat: {text}"
    );
}

/// M-6: offsets and widths a hostile file declares used to index the buffer
/// past its end and panic (or wrap) before any check looked at them. Every one
/// of these documents must answer with an error whose message names the bad
/// number — and the process must still be alive to print it. The PoCs are the
/// reviewer's shapes: a `startxref` past EOF, a `/Prev` past EOF, an xref
/// stream whose /W widths overflow a u32 sum.
#[test]
fn offsets_past_the_end_of_the_file_are_errors_never_panics() {
    let Some(signer) = test_signer() else {
        eprintln!("skipped, test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    // startxref names an offset far past the end of the file.
    let doc = build_pdf(
        &[
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>",
        ],
        "/Size 4 /Root 1 0 R",
    );
    let mut far = doc.clone();
    far.truncate(unsafe_str_rfind(&far, b"startxref\n"));
    far.extend_from_slice(b"startxref\n99999999\n%%EOF\n");
    for outcome in [
        openfirma_pades::inspect::signatures(&far)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        openfirma_pades::pades_sign(&far, &signer, &opts())
            .map(|_| ())
            .map_err(|e| e.to_string()),
    ] {
        let text = outcome.expect_err("an offset past EOF cannot be read as a cross-reference");
        assert!(
            text.contains("99999999"),
            "the error names the offset: {text}"
        );
    }
    // /Prev of the newest revision names an offset past the end. The newest
    // trailer itself is fine; walking one step back must fail closed.
    let mut lying = doc.clone();
    lying.extend_from_slice(b"\n");
    let at = lying.len();
    lying.extend_from_slice(b"4 0 obj\n<< /X 1 >>\nendobj\n");
    let x2 = lying.len();
    lying.extend_from_slice(
        format!(
            "xref\n4 1\n{at:010} 00000 n \ntrailer\n<< /Size 5 /Root 1 0 R /Prev 99999998 >>\nstartxref\n{x2}\n%%EOF\n"
        )
        .as_bytes(),
    );
    let text = openfirma_pades::pades_sign(&lying, &signer, &opts())
        .map(|_| ())
        .expect_err("a /Prev past EOF is not a revision")
        .to_string();
    assert!(
        text.contains("99999998"),
        "the error names the offset: {text}"
    );

    // an xref stream whose /W claims u32-scale widths: reading one row used to
    // compute `widths[0] + widths[1]` as a u32 and panic on the overflow.
    let mut stream = Vec::from(&b"%PDF-1.5\n"[..]);
    let o1 = stream.len();
    stream.extend_from_slice(
        b"1 0 obj\n<< /Type /XRef /Size 2 /W [1 4294967295 1] /Root 1 0 R /Filter /FlateDecode /Length 2 >>\nstream\nx\nendstream\nendobj\n",
    );
    stream.extend_from_slice(format!("startxref\n{o1}\n%%EOF\n").as_bytes());
    // every entry of these numbers comes from the file; nothing may panic.
    let _ = openfirma_pades::inspect::signatures(&stream);
    let _ = openfirma_pades::pades_sign(&stream, &signer, &opts())
        .map(|_| ())
        .map_err(|e| e.to_string());
}
