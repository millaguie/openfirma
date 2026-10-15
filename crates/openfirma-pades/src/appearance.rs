//! The visible appearance of a signature field.
//!
//! A signature does not have to be visible: `/Rect [0 0 0 0]` with a blank
//! appearance is what AutoFirma writes when no position is given, and it is the
//! default here. When it is visible, the field carries a rectangle in page
//! coordinates and its `/AP /N` is a form XObject that draws inside a box of
//! that size.
//!
//! The drawing is deliberately plain: a border and up to three lines of text in
//! Helvetica. Helvetica is one of the standard 14 fonts, so it needs no
//! embedding and every viewer has it. That is also the limit of what this does:
//! no logos, no handwritten stroke images, no rich layout. What a signature
//! appearance has to convey is who signed and when, and anything more elaborate
//! belongs in a template the caller supplies.

use openfirma_core::{Error, Result};

/// Where a visible signature goes.
pub struct Appearance {
    /// Page to put it on, counting from 1.
    pub page: usize,
    /// Rectangle in PDF user space units: `[llx, lly, urx, ury]`. The origin is
    /// the bottom left corner of the page, which is why the y values look
    /// upside down to anyone expecting a screen coordinate system.
    pub rect: [f64; 4],
    /// Optional line drawn above the signer's name.
    pub label: Option<String>,
}

/// Padding between the border and the text, in user space units.
const PADDING: f64 = 3.0;

/// Sizes tried in order, largest first. Text is shrunk until it fits rather
/// than clipped, because a signature box that hides the signer's name is worse
/// than one with small text in it.
const SIZES: [f64; 6] = [11.0, 10.0, 9.0, 8.0, 7.0, 6.0];

/// Average glyph advance for Helvetica, as a fraction of the font size. The
/// real metrics vary per character, from 0.278 for a space to 0.722 for a
/// capital M, and shipping the width table of a standard font to draw three
/// lines of text is not a trade worth making. Half an em overestimates for
/// lower case, so the fit is conservative.
const AVERAGE_ADVANCE: f64 = 0.5;

/// Builds the body of the form XObject that draws `lines` inside a box of
/// `width` by `height`.
pub fn form_xobject(
    width: f64,
    height: f64,
    lines: &[String],
    helv: crate::pdf::ObjRef,
) -> Result<Vec<u8>> {
    let (size, leading) = fit(width, height, lines);
    let content = draw(width, height, lines, size, leading);

    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "<< /BBox [0 0 {} {}] /FormType 1 /Length {} /Matrix [1 0 0 1 0 0] \
             /Resources << /Font << /F1 {helv} >> /ProcSet [/PDF /Text] >> \
             /Subtype /Form /Type /XObject >>\nstream\n",
            num(width),
            num(height),
            content.len(),
        )
        .as_bytes(),
    );
    body.extend_from_slice(&content);
    body.extend_from_slice(b"\nendstream");
    Ok(body)
}

/// The empty appearance, which is what an invisible signature carries.
///
/// Viewers still expect the entry to exist, so this is not the same as leaving
/// `/AP` out.
pub fn blank() -> Vec<u8> {
    Vec::from(
        &b"<< /BBox [0 0 0 0] /FormType 1 /Length 0 /Matrix [1 0 0 1 0 0] \
           /Resources << /ProcSet [/PDF /Text /ImageB /ImageC /ImageI] >> \
           /Subtype /Form /Type /XObject >>\nstream\nendstream"[..],
    )
}

/// Picks the largest size at which every line fits the width and all of them
/// together fit the height.
fn fit(width: f64, height: f64, lines: &[String]) -> (f64, f64) {
    let usable_w = (width - 2.0 * PADDING).max(1.0);
    let n = lines.len().max(1) as f64;
    for size in SIZES {
        let leading = size + 2.0;
        let fits_width = lines
            .iter()
            .all(|l| l.chars().count() as f64 * size * AVERAGE_ADVANCE <= usable_w);
        let fits_height = n * leading + PADDING <= height.max(1.0);
        if fits_width && fits_height {
            return (size, leading);
        }
    }
    // nothing fits, use the smallest size rather than drawing outside the box
    (SIZES[SIZES.len() - 1], SIZES[SIZES.len() - 1] + 2.0)
}

fn draw(width: f64, height: f64, lines: &[String], size: f64, leading: f64) -> Vec<u8> {
    let mut out = Vec::new();
    // the border, drawn first so the text sits on top of it
    out.extend_from_slice(
        format!(
            "q\n0.4 w\n0 0 0 RG\n0 0 {} {} re\nS\nQ\n",
            num(width),
            num(height)
        )
        .as_bytes(),
    );
    if lines.is_empty() {
        return out;
    }
    out.extend_from_slice(b"BT\n");
    out.extend_from_slice(format!("/F1 {} Tf\n0 g\n", num(size)).as_bytes());
    // first baseline, measured down from the top of the box
    let first_y = height - PADDING - size;
    out.extend_from_slice(format!("1 0 0 1 {} {} Tm\n", num(PADDING), num(first_y)).as_bytes());
    for (i, line) in lines.iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(format!("0 {} Td\n", num(-leading)).as_bytes());
        }
        out.extend_from_slice(&text_operand(line));
        out.extend_from_slice(b" Tj\n");
    }
    out.extend_from_slice(b"ET\n");
    out
}

/// A string operand for a content stream.
///
/// Unlike the text strings in a dictionary, these are not UTF-16BE with a byte
/// order mark: the font's encoding decides, and `/F1` is declared with
/// `WinAnsiEncoding`. WinAnsi and Latin-1 agree over 0xC0 to 0xFF, which is
/// where the accented letters of a Spanish name live, so single byte output is
/// correct for them. Anything outside Latin-1 has no WinAnsi code point at all
/// and becomes a question mark, which is honest: the alternative is a garbled
/// glyph that looks like a mistake rather than a missing character.
fn text_operand(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() + 2);
    out.push(b'(');
    for c in text.chars() {
        let b = u32::from(c);
        let b = if b < 0x100 { b as u8 } else { b'?' };
        match b {
            b'(' => out.extend_from_slice(b"\\("),
            b')' => out.extend_from_slice(b"\\)"),
            b'\\' => out.extend_from_slice(b"\\\\"),
            _ => out.push(b),
        }
    }
    out.push(b')');
    out
}

/// Formats a number the way PDF wants it: no trailing zeros, and never
/// scientific notation, which is not a PDF number.
pub fn num(value: f64) -> String {
    if !value.is_finite() {
        // unreachable through the public API, which takes a rectangle the
        // caller validated, but a NaN written into a PDF is a corrupt file
        return "0".into();
    }
    let rounded = (value * 100.0).round() / 100.0;
    if rounded == 0.0 {
        // also swallows negative zero, which formats as "-0" and is not a
        // number anyone wants to read in a rectangle
        return "0".into();
    }
    let text = format!("{rounded:.2}");
    let text = text.trim_end_matches('0').trim_end_matches('.');
    if text.is_empty() || text == "-" {
        "0".into()
    } else {
        text.to_string()
    }
}

/// Validates a rectangle, which is the one piece of caller input that can
/// silently produce a document a viewer refuses to draw.
pub fn check_rect(rect: [f64; 4]) -> Result<()> {
    let [llx, lly, urx, ury] = rect;
    for (name, v) in [("llx", llx), ("lly", lly), ("urx", urx), ("ury", ury)] {
        if !v.is_finite() {
            return Err(Error::Pdf(format!(
                "the {name} of the rectangle is not a number"
            )));
        }
    }
    if urx <= llx || ury <= lly {
        return Err(Error::Pdf(format!(
            "the rectangle [{llx} {lly} {urx} {ury}] has no area, the upper right corner \
             must be above and to the right of the lower left one"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_drop_the_trailing_zeros() {
        assert_eq!(num(595.0), "595");
        assert_eq!(num(842.5), "842.5");
        assert_eq!(num(0.0), "0");
        assert_eq!(num(-0.0), "0");
        // 12.346 is used rather than 12.345 because the latter is stored as
        // 12.34499999... and rounds down; a test should not depend on that
        assert_eq!(num(12.346), "12.35");
        assert_eq!(
            num(1e20),
            "100000000000000000000",
            "never scientific notation"
        );
    }

    #[test]
    fn a_degenerate_rectangle_is_refused() {
        assert!(check_rect([0.0, 0.0, 0.0, 0.0]).is_err());
        assert!(check_rect([100.0, 100.0, 50.0, 50.0]).is_err());
        assert!(check_rect([0.0, 0.0, f64::NAN, 10.0]).is_err());
        assert!(check_rect([50.0, 50.0, 250.0, 100.0]).is_ok());
    }

    #[test]
    fn text_shrinks_until_it_fits() {
        let lines = vec!["A".repeat(200)];
        let (small, _) = fit(100.0, 60.0, &lines);
        assert_eq!(
            small, 6.0,
            "a long line in a narrow box ends at the smallest size"
        );

        let lines = vec!["Ana".to_string()];
        let (big, _) = fit(300.0, 100.0, &lines);
        assert_eq!(
            big, 11.0,
            "a short line in a wide box keeps the largest size"
        );
    }

    #[test]
    fn the_stream_declares_its_own_length() {
        let body = form_xobject(
            200.0,
            60.0,
            &["PEREZ GARCIA, ANA".to_string(), "2026-10-15".to_string()],
            crate::pdf::ObjRef::new(7, 0),
        )
        .unwrap();
        let body = String::from_utf8(body).unwrap();
        let declared: usize = body
            .split("/Length ")
            .nth(1)
            .unwrap()
            .split(' ')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let start = body.find("stream\n").unwrap() + "stream\n".len();
        let end = body.rfind("\nendstream").unwrap();
        assert_eq!(declared, end - start, "/Length must match the stream bytes");
        assert!(body.contains("(PEREZ GARCIA, ANA) Tj"));
    }

    #[test]
    fn content_strings_are_winansi_not_utf16() {
        // an accented name goes out as a single byte, because /F1 is declared
        // with WinAnsiEncoding and a byte order mark here would be literal text
        assert_eq!(text_operand("JOSÉ"), b"(JOS\xC9)".to_vec());
        assert_eq!(text_operand("a(b)c"), b"(a\\(b\\)c)".to_vec());
        // no WinAnsi code point exists for these, so they degrade visibly
        assert_eq!(text_operand("日本"), b"(??)".to_vec());
    }

    #[test]
    fn the_blank_appearance_is_a_stream_of_zero_bytes() {
        let body = String::from_utf8(blank()).unwrap();
        assert!(body.contains("/Length 0"), "{body}");
        assert!(body.contains("/BBox [0 0 0 0]"), "{body}");
    }
}
