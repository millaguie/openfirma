//! The window's own colours (review 06, M-7).
//!
//! egui's defaults are not accessible, and the colours that fail are exactly
//! the ones that carry meaning here. Its "weak" text is the ordinary colour at
//! 60 % alpha — 2.66:1 on the dark theme, 2.89:1 on the light — and the weak
//! colour is what this window paints its notes with: "el certificado no se ha
//! comprobado", "no se ha encontrado ningún certificado", "falta la
//! contraseña". Its `warn_fg_color` and `error_fg_color` are 4.31:1 and 3.98:1
//! (dark) / 3.76:1 (light), and they are what a refusal is painted with.
//! WCAG 2.2 AA for body text is 4.5:1; a sentence a person cannot read on a dim
//! screen is a sentence this project's whole premise does not get to rely on
//! ("the code says what it checked, not more").
//!
//! So the surfaces the window paints on are named here — egui 0.37's own
//! `panel_fill`/`window_fill`, plus `extreme_bg_color` (text edits) and the
//! barely-visible group fill — and the three tones are picked per theme to
//! clear 4.5:1 on every one of them. The arithmetic is not a comment:
//! `every_colour_reaches_wcag_aa_on_the_surfaces_it_is_painted_on` recomputes
//! the ratios, so a "nicer" colour that drops below the floor fails the suite.

use egui::Color32;

/// The dark theme's surfaces, as egui 0.37 builds them: `window_fill` and
/// `panel_fill` are gray 27, a group's faint fill is 5 above that, and a text
/// edit sits on `extreme_bg_color` (10).
pub const DARK_SURFACES: [Color32; 3] = [
    Color32::from_gray(10),
    Color32::from_gray(27),
    Color32::from_gray(32),
];

/// The light theme's: 248, 253 for the faint fill, 255 for a text edit.
pub const LIGHT_SURFACES: [Color32; 3] = [
    Color32::from_gray(248),
    Color32::from_gray(253),
    Color32::from_gray(255),
];

/// The three tones the window uses for text that is not ordinary text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Palette {
    /// Notes and hints: secondary text a reader still has to be able to read.
    pub note: Color32,
    /// "Cannot be confirmed": not a refusal, not a green light.
    pub warn: Color32,
    /// A refusal or a failed check.
    pub alert: Color32,
}

/// Dark theme: grays are lifted and the red is a light one, because the
/// background is nearly black.
pub const DARK: Palette = Palette {
    note: Color32::from_rgb(0x90, 0x90, 0x90),
    warn: Color32::from_rgb(0xFF, 0xB7, 0x4D),
    alert: Color32::from_rgb(0xFF, 0x8A, 0x80),
};

/// Light theme: darker text on a white page. `note` at 0x70 would be 4.66:1 on
/// the faintest surface and 4.95:1 on white — it clears the floor, and 0x5A is
/// kept for margin, because a person reading at 4.6:1 is reading at the edge.
pub const LIGHT: Palette = Palette {
    note: Color32::from_rgb(0x5A, 0x5A, 0x5A),
    warn: Color32::from_rgb(0x7A, 0x4F, 0x00),
    alert: Color32::from_rgb(0xB0, 0x00, 0x20),
};

/// The palette for the theme the ui is actually painting (`visuals.dark_mode`,
/// which follows the desktop's preference and can change while the window is
/// open).
pub fn of(dark_mode: bool) -> Palette {
    if dark_mode { DARK } else { LIGHT }
}

/// WCAG 2.2's contrast ratio between two opaque colours (1.0 to 21.0). Public
/// because the test that guards the palette must use the same formula a
/// reader's eye is judged by, not a copy of it.
pub fn contrast_ratio(a: Color32, b: Color32) -> f32 {
    let (la, lb) = (luminance(a), luminance(b));
    let (hi, lo) = if la > lb { (la, lb) } else { (lb, la) };
    (hi + 0.05) / (lo + 0.05)
}

fn luminance(c: Color32) -> f32 {
    let lin = |v: u8| {
        let v = f32::from(v) / 255.0;
        if v <= 0.040_45 {
            v / 12.92
        } else {
            ((v + 0.055) / 1.055).powf(2.4)
        }
    };
    0.212_6 * lin(c.r()) + 0.715_2 * lin(c.g()) + 0.072_2 * lin(c.b())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The floor is WCAG 2.2 AA for body text. Each tone is measured on every
    /// surface of its own theme, because the same sentence is painted inside
    /// the panel, inside a group and inside a text-edit field.
    #[test]
    fn every_colour_reaches_wcag_aa_on_the_surfaces_it_is_painted_on() {
        for (theme, palette, surfaces) in [
            ("dark", DARK, DARK_SURFACES),
            ("light", LIGHT, LIGHT_SURFACES),
        ] {
            for (what, colour) in [
                ("note", palette.note),
                ("warn", palette.warn),
                ("alert", palette.alert),
            ] {
                for bg in surfaces {
                    let ratio = contrast_ratio(colour, bg);
                    assert!(
                        ratio >= 4.5,
                        "{theme} {what} {colour:?} on {bg:?} is {ratio:.2}:1, below AA 4.5:1"
                    );
                }
            }
        }
    }

    /// The palettes are told apart by the theme, and the formula agrees with
    /// the two reference points everyone knows (white on black is 21:1, a
    /// colour on itself is 1:1). If this passes, the test above means
    /// something.
    #[test]
    fn the_palette_follows_the_theme_and_the_formula_is_the_real_one() {
        assert_eq!(of(true), DARK);
        assert_eq!(of(false), LIGHT);
        assert_ne!(of(true), of(false));
        assert!((contrast_ratio(Color32::WHITE, Color32::BLACK) - 21.0).abs() < 0.01);
        assert!(
            (contrast_ratio(Color32::from_gray(140), Color32::from_gray(140)) - 1.0).abs() < 0.01
        );
        // The colour egui itself would have used, kept as the measurement the
        // module's doc comment states: ordinary text (gray 140) at 60 % alpha
        // over the dark panel is the 2.66:1 the reviewer read off a screenshot.
        let weak_over_dark = blend(Color32::from_gray(140), Color32::from_gray(27), 0.6);
        let ratio = contrast_ratio(weak_over_dark, Color32::from_gray(27));
        assert!(ratio < 4.5, "egui's weak text measures {ratio:.2}:1");
    }

    /// The palette is worthless if the window paints with egui's colours
    /// anyway. A rendered colour is not something the widget harness can read
    /// back, so the crate's own sources are the evidence: nothing outside this
    /// module may ask egui for weak text or for its warning/error tones. (The
    /// ordinary text colour stays available by design: it is the one that
    /// already reaches AA, and it is what a valid verdict line is painted in.)
    #[test]
    fn the_window_does_not_paint_with_the_colours_that_fail() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut seen = 0;
        for entry in std::fs::read_dir(&root).expect("the crate's own sources") {
            let path = entry.expect("a source entry").path();
            let is_rust = path.extension().is_some_and(|e| e == "rs");
            let is_this = path.file_name().is_some_and(|n| n == "palette.rs");
            if !is_rust || is_this {
                continue;
            }
            seen += 1;
            let text = std::fs::read_to_string(&path).expect("readable source");
            for needle in [
                "ui.weak(",
                "warn_fg_color",
                "error_fg_color",
                "weak_text_color",
                "weak_text_alpha",
            ] {
                assert!(
                    !text.contains(needle),
                    "{} still paints with egui's {needle}",
                    path.display()
                );
            }
        }
        assert!(seen > 5, "the scanner found only {seen} sources");
    }

    /// 60 % alpha of `fg` over `bg`, as egui composites it.
    fn blend(fg: Color32, bg: Color32, alpha: f32) -> Color32 {
        let mix =
            |a: u8, b: u8| (f32::from(a) * alpha + f32::from(b) * (1.0 - alpha)).round() as u8;
        Color32::from_rgb(
            mix(fg.r(), bg.r()),
            mix(fg.g(), bg.g()),
            mix(fg.b(), bg.b()),
        )
    }
}
