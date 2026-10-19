//! The thin GUI seam over the shared TSA transport.
//!
//! The protocol lives in `openfirma_cades::tsa` — one HTTP client, one status
//! parser, one response cap, which the CLI's `--tsa` runs too (review 06,
//! M-9: this file used to BE the second copy). What stays here is the window's
//! own vocabulary: its Spanish-worded https refusal, and the rule that a token
//! nobody could verify gets said out loud in the terminal the window was
//! started from (the GUI has no inline warning line for it yet — review 06,
//! M-11 records making that a real on-screen notice).

use openfirma_core::Result;

/// The unsigned-attribute timestamp provider for one URL, with the GUI's
/// https refusal text. Plain http only — see `openfirma_cades::tsa`.
pub fn provider(
    url: &str,
    unchecked: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<openfirma_cades::TimestampFn> {
    let unchecked = std::sync::Arc::clone(unchecked);
    openfirma_cades::tsa::provider(url, HTTPS_REFUSAL, move |source, _token| {
        note_token_seen(&unchecked, source);
    })
}

/// What happens for every token this window embeds: it can prove WHAT it
/// covers and never WHO made it (M-11). The flag carries that fact back to the
/// screen the citizen is looking at — the Done screen turns it into the
/// sentence that says a stamp nobody verified proves the time only if you
/// trust its issuer; the stderr line is for whoever started the window from a
/// terminal. Split out so both halves of the piece are testable: that the
/// callback fires is `openfirma_cades::tsa::provider`'s own tested rule.
fn note_token_seen(unchecked: &std::sync::Arc<std::sync::atomic::AtomicBool>, source: &str) {
    unchecked.store(true, std::sync::atomic::Ordering::SeqCst);
    warn_if_token_unverified(source);
}

/// The message the window's own TSA field shows when someone types an https
/// url. Same truth as the CLI's flag text, in the words this frontend chose.
const HTTPS_REFUSAL: &str = "the TSA url must start with http:// (plain): an https TSA needs \
                             a TLS client, which is a dependency decision of its own; until \
                             then fetch the token by hand and sign in a terminal with \
                             --timestamp-token.";

/// The token about to be embedded imprints the right bytes (the verifier of
/// `token_from_response` proved that), but its own signature is unverified:
/// nothing in a signing client knows which TSA certificates to trust, and a
/// plain-http answer can be planted by anyone on the path. Say it on stderr
/// the way the CLI's warning does; the imprint still proves *what* the token
/// covers, just not *who* made it.
fn warn_if_token_unverified(source: &str) {
    eprintln!(
        "warning: the time-stamp token from {source} was accepted on its imprint alone; \
         check the TSA's answer against its CA yourself: \
         openssl ts -verify -CAfile <tsa-ca.pem> -in <answer.tsr> -data <file>"
    );
}

#[cfg(test)]
mod tests {
    fn unchecked_flag() -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false))
    }

    /// The GUI and the CLI must refuse the same https url for the same reason
    /// (one rule, two frontends): the text is the window's, the decision is
    /// the crate's.
    #[test]
    fn an_https_tsa_url_is_refused_before_anything_connects() {
        // unwrap_err() would need the provider closure to be Debug; match
        // keeps the assertion about the MESSAGE, which is what matters here.
        let err = match super::provider("https://tsa.example/tsa", &unchecked_flag()) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("an https TSA url must be refused"),
        };
        assert!(err.contains("--timestamp-token"), "{err}");
    }

    #[test]
    fn a_plain_http_url_builds_a_provider() {
        assert!(super::provider("http://127.0.0.1:1/tsa", &unchecked_flag()).is_ok());
    }

    /// 06-N-11 (review M-11): the flag the Done screen reads is set by the one
    /// function every embedded token goes through. Without this, a signature
    /// carrying a stamp nobody verified looked exactly like one whose stamp
    /// was checked.
    #[test]
    fn a_token_that_was_only_imprint_checked_raises_the_flag() {
        let seen = unchecked_flag();
        assert!(!seen.load(std::sync::atomic::Ordering::SeqCst));
        super::note_token_seen(&seen, "the TSA at http://tsa.example/tsa");
        assert!(
            seen.load(std::sync::atomic::Ordering::SeqCst),
            "the Done screen has to be told"
        );
    }
}
