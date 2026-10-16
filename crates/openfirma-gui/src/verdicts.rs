//! Verdicts: the library's verification reports rendered as Spanish a person
//! reads, plus the rules that decide what each line says.
//!
//! The verdict is computed by the *same verifier* `openfirma verify` runs —
//! `openfirma_cades::verify` for detached/encapsulated CMS and
//! `openfirma_pades::pades_verify` for PDFs. What lives here is only how its
//! result is shown: one line per signature, plain language first, the
//! technical strings (chain subjects, byte ranges, check names) reachable
//! behind a details control and never in front of the verdict (docs/adr-0006:
//! this is the screen where openfirma is allowed to be better than AutoFirma,
//! whose validation viewer shows a certificate tree instead of an answer).

use std::time::{SystemTime, UNIX_EPOCH};

use openfirma_cades::{VerifyOptions, VerifyReport};
use openfirma_core::Error;
use openfirma_pades::DocumentReport;

use crate::wizard::{VerdictLine, VerdictList};

/// The validation time of the GUI's verify path: now. (`--at` is a
/// specialist's tool and stays in the CLI; the citizen's question — does this
/// signature hold today — is what this screen answers.)
pub fn now() -> SystemTime {
    SystemTime::now()
}

/// Verify one file with the library verifier and turn its result into the
/// verdict list. `anchors` empty means "nothing is trusted yet": that is not
/// an error but a state the caller renders as the ask-for-a-anchor prompt,
/// because inventing anchors would be exactly the unfounded success this
/// project bans. CMS or PDF, decided by the same detection both frontends
/// share (`openfirma_core::workflow::Format`).
pub fn verdicts_for(
    bytes: &[u8],
    anchors: Vec<openfirma_core::CertificateHandle>,
) -> Result<VerdictList, openfirma_core::Error> {
    if anchors.is_empty() {
        return Err(Error::Verification(NO_ANCHORS_MARK.into()));
    }
    let opts = VerifyOptions {
        trust_anchors: anchors,
        validation_time: now(),
    };
    match openfirma_core::workflow::Format::detect(bytes) {
        openfirma_core::workflow::Format::Pdf => Ok(verdicts_from_pdf(
            &openfirma_pades::pades_verify(bytes, &opts)?,
        )),
        _ => {
            let reports = openfirma_cades::verify(bytes, None, &opts)?;
            Ok(VerdictList {
                lines: reports.iter().map(verdict_line).collect(),
                notes: Vec::new(),
            })
        }
    }
}

/// The mark [`verdicts_for`] returns when the reason is simply that no trust
/// anchor was supplied; the UI turns it into its ask-the-user screen.
pub const NO_ANCHORS_MARK: &str = "openfirma: no trust anchors were supplied";

/// One `VerifyReport` (all checks passed — a failure never produces one) as
/// a valid line. The CLI prints the same fields; only their order differs,
/// because here a person reads them and there a script does.
fn verdict_line(r: &VerifyReport) -> VerdictLine {
    VerdictLine {
        valid: true,
        signer: signer_display_from_report(r),
        when: r.attributes.signing_time.map(fmt_local).unwrap_or_default(),
        why_not: None,
        trust_anchor: Some(r.trust_anchor.clone()),
        technical: technical_of(r),
    }
}

/// The technical block behind the details control.
fn technical_of(r: &VerifyReport) -> Vec<String> {
    let mut lines = vec![
        format!("digest: {}", r.digest.name()),
        format!("algoritmo de firma: {}", r.signature_alg),
        format!("sujeto (DN): {}", r.signer_subject),
        format!("anclas de confianza alcanzada: {}", r.trust_anchor),
    ];
    for (i, s) in r.chain_subjects.iter().enumerate() {
        lines.push(format!("cadena {}: {s}", i + 1));
    }
    if let Some(t) = r.attributes.signing_time {
        lines.push(format!("signingTime: {}", fmt_utc(t)));
    }
    if r.attributes.signature_time_stamp_token {
        lines.push("nivel: B-T (sellado de firma)".into());
    }
    lines.push(format!("comprobaciones superadas: {}", r.passed.join(", ")));
    lines
}

/// The PDF verdict: one line per signature dictionary (every co-signer gets
/// its own — the CLI counts them and so does this screen), plus the document
/// time-stamps and `/DSS` as plain notes. `pades_verify` answers all-or-nothing;
/// when a part fails, the caller shows the error panel instead of a list, but
/// the list's own note about what was found still has to be built here so a
/// signed-and-timestamped document never looks like a mere signature.
pub fn verdicts_from_pdf(report: &DocumentReport) -> VerdictList {
    let mut lines = Vec::new();
    for sig in &report.signatures {
        for r in &sig.reports {
            let mut line = verdict_line(r);
            line.technical.push(format!(
                "/ByteRange [{a} {b} {c} {d}]",
                a = sig.byte_range[0],
                b = sig.byte_range[1],
                c = sig.byte_range[2],
                d = sig.byte_range[3]
            ));
            lines.push(line);
        }
    }
    let mut notes = Vec::new();
    if !report.document_timestamps.is_empty() {
        notes.push(format!(
            "El documento lleva {} sello(s) de tiempo de documento (nivel B-LTA): cada uno \
             certifica todos los bytes anteriores al momento del sellado.",
            report.document_timestamps.len()
        ));
    }
    if let Some(dss) = &report.dss {
        notes.push(format!(
            "El documento guarda datos de validación ({} certificados, {} CRLs, {} respuestas \
             OCSP), todos legibles y cada CRL firmada por la autoridad que la emite.",
            dss.certificates,
            dss.crls.len(),
            dss.ocsps
        ));
        for chain in &dss.chains {
            notes.push(format!(
                "La cadena de la firma {} se reconstruye solo con los datos del documento: {}.",
                chain.signature,
                chain.subjects.join(" -> ")
            ));
        }
    }
    VerdictList { lines, notes }
}

/// A `SystemTime` as wall-clock text: UTC, because a machine's local zone is
/// the same answer for every signature on it and mixing zones into one list
/// would make two lines incomparable. The calendar comes from core — the same
/// conversion the CLI prints its validation time with, so the GUI can never
/// state a different date than `openfirma verify` does.
fn fmt_local(t: SystemTime) -> String {
    let Ok(d) = t.duration_since(UNIX_EPOCH) else {
        return "antes de 1970".into();
    };
    let secs = d.as_secs() as i64;
    let (y, m, day) = openfirma_core::workflow::civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{day:02} {:02}:{:02} UTC",
        rem / 3600,
        (rem % 3600) / 60,
    )
}

/// A `SystemTime` as the UTC ISO form the technical block keeps.
fn fmt_utc(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    // Hinnant's civil_from_days, same as openfirma-pades and the CLI.
    let z = (secs / 86_400) as i64;
    let rem = (secs % 86_400) as i64;
    let z2 = z + 719_468;
    let era = if z2 >= 0 { z2 } else { z2 - 146_096 } / 146_097;
    let doe = z2 - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let (y, m) = if m <= 2 { (y + 1, m) } else { (y, m) };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// The friendly name from a verify report: the verifier already resolved the
/// subject CN when it built the report; if that came out empty the workflow's
/// fallback chain (store label, subject serialNumber, certificate number)
/// runs on the *certificate carried by the signature itself*, so the GUI and
/// `openfirma verify` show one name for one signer.
fn signer_display_from_report(r: &VerifyReport) -> String {
    let dn = r.signer_subject.trim();
    // A report's subject string is RFC 4514; CN= comes first in every Spanish
    // qualified certificate the test PKI and FNMT profiles produce.
    if let Some(cn) = dn.strip_prefix("CN=").or_else(|| {
        dn.split(',')
            .map(str::trim)
            .find_map(|p| p.strip_prefix("CN="))
    }) {
        let cn = cn.trim();
        if !cn.is_empty() {
            return cn.to_string();
        }
    }
    // No CN: the certificate number at least distinguishes signers.
    format!("certificado sin nombre (sujeto {dn})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_utc_formatter_matches_the_libraries_one() {
        // Known instants; the CLI's `fmt_system_time` and this one must never
        // disagree, so both are pinned to hand-checked values.
        assert_eq!(fmt_utc(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        let t = UNIX_EPOCH + std::time::Duration::from_secs(1_792_071_360);
        assert_eq!(fmt_utc(t), "2026-10-15T13:36:00Z");
    }

    #[test]
    fn no_anchors_is_the_distinguished_answer() {
        // An empty anchor list never reaches the verifier: it is this mark,
        // which the UI renders as its ask-the-user screen. A file that isn't
        // even a signature must not be blamed first for the anchors.
        let err = match verdicts_for(b"nada", Vec::new()) {
            Ok(_) => panic!("no anchors must never verify against nothing"),
            Err(e) => e,
        };
        match err {
            Error::Verification(m) => assert_eq!(m, NO_ANCHORS_MARK),
            other => panic!("expected the no-anchors mark, got {other:?}"),
        }
    }

    #[test]
    fn a_cms_failure_carries_the_verifiers_reason() {
        // The synthetic root from tools/gen-testcert.sh when present — real
        // material beats anything this file could embed. Without it the test
        // skips, and OPENFIRMA_REQUIRE_TESTS makes that visible.
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs");
        let Ok(ca_pem) = std::fs::read_to_string(dir.join("ca.crt")) else {
            eprintln!("SKIP: testdata/certs/ca.crt is absent, run tools/gen-testcert.sh");
            if std::env::var_os("OPENFIRMA_REQUIRE_TESTS").is_some() {
                panic!("OPENFIRMA_REQUIRE_TESTS is set and the test PKI is missing");
            }
            return;
        };
        let anchors = vec![openfirma_core::CertificateHandle::from_pem(&ca_pem).unwrap()];
        let err = verdicts_for(b"not a signature", anchors).err();
        assert!(matches!(err, Some(Error::Verification(_))), "{err:?}");
    }
}
