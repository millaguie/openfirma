//! Decoding PDF streams.
//!
//! This exists because a document that iText wrote cannot be read without it:
//! the cross-reference table is a compressed stream and most of the objects
//! live inside compressed object streams. Until this was written, signing one
//! meant re-saving the file with an external tool first.
//!
//! Only the filters that carry document *structure* are implemented. The image
//! filters (`DCTDecode`, `JPXDecode`, `CCITTFaxDecode`) are deliberately left
//! out: we never render a page, we only look for the catalog, the page tree and
//! the signature dictionaries, and none of those live in an image. Pretending
//! otherwise would mean shipping a JPEG decoder to sign a PDF.

use std::io::Read;

use openfirma_core::{Error, Result};

use crate::pdf;

/// Decodes the raw bytes of a stream according to its dictionary.
///
/// Filters compose, and `/DecodeParms` is a parallel list, so the nth
/// parameter set belongs to the nth filter. The cap applies to the whole
/// chain and after every stage: `/FlateDecode` refuses past it on its own,
/// but `/RunLengthDecode` multiplies what the previous filter produced by up
/// to 128 per input byte, and each intermediate stage is an allocation — a
/// chain that only checked its last output would still OOM in the middle of
/// it. Checking after every stage bounds peak memory to roughly two stages,
/// because an expansion is refused at the cap before it grows past it.
pub fn decode(dict: &[u8], raw: &[u8]) -> Result<Vec<u8>> {
    decode_capped(dict, raw, MAX_DECODED_STREAM)
}

fn apply(name: &str, data: &[u8], parms: Option<&[u8]>, cap: usize) -> Result<Vec<u8>> {
    match name {
        "/FlateDecode" => {
            let inflated = inflate_capped(data, cap)?;
            apply_predictor(&inflated, parms)
        }
        "/LZWDecode" => Err(Error::Pdf(
            "LZWDecode is not implemented; it is a legacy filter and a modern writer \
             will not use it. Re-save the file with qpdf if you need to sign it."
                .into(),
        )),
        "/ASCIIHexDecode" => ascii_hex(data),
        "/ASCII85Decode" => ascii85(data),
        // not reached through decode_capped, which handles this filter itself
        // so it can pass the chain's cap; kept for the direct-call shape
        "/RunLengthDecode" => run_length(data, cap),
        other => Err(Error::Pdf(format!(
            "stream filter {other} is not supported. The image filters are left out on \
             purpose, nothing that carries document structure uses them."
        ))),
    }
}

/// Shared by `decode` and the bounded unit tests below: run every filter of
/// `dict` over `raw`. `cap` is the ceiling; `MAX_DECODED_STREAM` is what real
/// decoding uses, and a test passes a small one to exercise the refusal of a
/// chain without materializing a real bomb.
fn decode_capped(dict: &[u8], raw: &[u8], cap: usize) -> Result<Vec<u8>> {
    let filters = filter_names(dict)?;
    let parms = parameter_sets(dict);
    let mut data = raw.to_vec();
    for (i, name) in filters.iter().enumerate() {
        data = apply(name, &data, parms.get(i).copied().flatten(), cap)?;
        check_stage(name, &data, cap)?;
    }
    Ok(data)
}

/// One stage's output must fit the cap: named refusal in the same words as
/// `inflate_capped`'s, because `/RunLengthDecode` (×128) and the ASCII
/// filters can each multiply what a capped earlier stage legally produced.
fn check_stage(name: &str, data: &[u8], cap: usize) -> Result<()> {
    if data.len() > cap {
        return Err(Error::Pdf(format!(
            "{name} expands the stream to more than {} bytes, the most openfirma decodes \
             from one stream: a structural stream this large is a decompression bomb, not \
             a document",
            cap
        )));
    }
    Ok(())
}

/// The most a single decoded stream may expand to.
///
/// The streams openfirma decodes carry document *structure*: a cross-reference
/// table, an object stream. Kilobytes in every real document, even a huge one.
/// A 40 KB compressed stream that unpacks to gigabytes is a decompression
/// bomb, and reading it to the end before deciding is how a signing tool ends
/// up an out of memory victim. The cap is generous enough that no legitimate
/// document comes near it.
pub const MAX_DECODED_STREAM: usize = 256 * 1024 * 1024;

/// The most any one `/Colors`, `/BitsPerComponent` or `/Columns` predictor
/// parameter may claim. These numbers multiply into an allocation, so they are
/// bounded before anything is computed from them; 65536 columns of 65536
/// colours is already a nonsense image, let alone a PDF structure stream.
const MAX_PREDICTOR_PARM: i64 = 65_536;

/// PDF's `FlateDecode` is zlib format, RFC 1950, not raw deflate.
///
/// Inflate with a ceiling, so the refusal is testable without materializing a
/// real 256 MiB stream. The cap is the chain's (`decode_capped`), not a
/// constant, because an earlier stage of a chain may have produced far less
/// than the global ceiling and this stage still has to be bounded by the same
/// one the caller asked for.
fn inflate_capped(data: &[u8], cap: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    // one byte over the cap is read so "exactly at the cap" still succeeds and
    // anything past it is provably past it, without draining a gigabyte bomb
    flate2::read::ZlibDecoder::new(data)
        .take(cap as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| Error::Pdf(format!("FlateDecode failed: {e}")))?;
    if out.len() > cap {
        return Err(Error::Pdf(format!(
            "FlateDecode expands to more than {} bytes, the most openfirma decodes from \
             one stream: a structural stream this large is a decompression bomb, not a \
             document",
            cap
        )));
    }
    Ok(out)
}

/// The names in `/Filter`, which is either a single name or an array.
fn filter_names(dict: &[u8]) -> Result<Vec<String>> {
    let Some(value) = pdf::get(dict, "/Filter") else {
        return Ok(Vec::new());
    };
    let value = pdf::trim_ws(value);
    if value.starts_with(b"/") {
        return Ok(vec![String::from_utf8_lossy(value).into_owned()]);
    }
    if value.starts_with(b"[") {
        let mut out = Vec::new();
        let mut i = 1;
        while i < value.len() {
            i = pdf::skip_ws(value, i);
            if i >= value.len() || value[i] == b']' {
                break;
            }
            // whole value, not a bare token: a filter name starts with '/',
            // which is a delimiter, so token_end_pub would return `i` itself
            // and this loop would never advance — a `/Filter [/FlateDecode]`
            // array, which is legal and appears in real documents, used to
            // spin forever pushing empty strings until the allocator died
            let end = pdf::value_end(value, i)?;
            if end <= i {
                return Err(Error::Pdf(
                    "/Filter holds an element that is not a value".into(),
                ));
            }
            out.push(String::from_utf8_lossy(&value[i..end]).into_owned());
            i = end;
        }
        return Ok(out);
    }
    Err(Error::Pdf("/Filter is neither a name nor an array".into()))
}

/// `/DecodeParms`, or its abbreviation `/DP`, as a list of optional dictionaries.
fn parameter_sets(dict: &[u8]) -> Vec<Option<&[u8]>> {
    let value = pdf::get(dict, "/DecodeParms")
        .or_else(|| pdf::get(dict, "/DP"))
        .map(pdf::trim_ws);
    let Some(value) = value else {
        return Vec::new();
    };
    if value.starts_with(b"<<") {
        return vec![Some(value)];
    }
    if value.starts_with(b"[") {
        // elements may be "null", meaning no parameters for that filter
        let mut out = Vec::new();
        let mut i = 1;
        while i < value.len() {
            i = pdf::skip_ws(value, i);
            if i >= value.len() || value[i] == b']' {
                break;
            }
            // same trap as filter_names: a `<<…>>` or `null` element is a
            // whole value whose first byte is a delimiter, and asking for a
            // bare token there would not advance. Stop on anything unparsable
            // rather than spin: the missing sets then leave the corresponding
            // filter without parameters, which is the safe reading.
            let Ok(end) = pdf::value_end(value, i) else {
                break;
            };
            if end <= i {
                break;
            }
            let tok = &value[i..end];
            out.push(if tok == b"null" { None } else { Some(tok) });
            i = end;
        }
        return out;
    }
    Vec::new()
}

fn int_parm(parms: Option<&[u8]>, key: &str) -> Option<i64> {
    let dict = parms?;
    let value = pdf::get(dict, key)?;
    std::str::from_utf8(pdf::trim_ws(value))
        .ok()?
        .trim()
        .parse::<i64>()
        .ok()
}

/// Undo the predictor, if one was applied.
///
/// Predictor 1 means none. Predictor 2 is the TIFF horizontal differencing.
/// Predictors 10 to 15 are the PNG filters, where every row carries a tag byte
/// saying which filter that row uses, so a single stream can mix them.
fn apply_predictor(data: &[u8], parms: Option<&[u8]>) -> Result<Vec<u8>> {
    let predictor = bounded_parm(parms, "/Predictor", 1)?;
    match predictor {
        1 => Ok(data.to_vec()),
        2 => {
            let colors = bounded_parm(parms, "/Colors", 1)?;
            let bpc = bounded_parm(parms, "/BitsPerComponent", 8)?;
            let columns = bounded_parm(parms, "/Columns", 1)?;
            tiff_predictor(data, colors, bpc, columns)
        }
        10..=15 => {
            let colors = bounded_parm(parms, "/Colors", 1)?;
            let bpc = bounded_parm(parms, "/BitsPerComponent", 8)?;
            let columns = bounded_parm(parms, "/Columns", 1)?;
            png_predictor(data, colors, bpc, columns)
        }
        other => Err(Error::Pdf(format!("unknown predictor {other}"))),
    }
}

/// A `/DecodeParms` integer, bounded before it becomes a `usize`: the value is
/// the document's claim, it is signed in the file, and an `as usize` of a
/// negative or an absurd one turns into an allocation.
fn bounded_parm(parms: Option<&[u8]>, key: &str, default: i64) -> Result<usize> {
    let value = int_parm(parms, key).unwrap_or(default);
    if !(1..=MAX_PREDICTOR_PARM).contains(&value) {
        return Err(Error::Pdf(format!(
            "{key} is {value}, outside the 1..={MAX_PREDICTOR_PARM} openfirma accepts: \
             the predictor parameters size an allocation and are not trusted as written"
        )));
    }
    Ok(value as usize)
}

fn tiff_predictor(data: &[u8], colors: usize, bpc: usize, columns: usize) -> Result<Vec<u8>> {
    if bpc != 8 {
        return Err(Error::Pdf(format!(
            "the TIFF predictor is only implemented for 8 bits per component, got {bpc}"
        )));
    }
    if colors == 0 || columns == 0 {
        return Err(Error::Pdf(
            "the TIFF predictor needs non-zero /Colors and /Columns".into(),
        ));
    }
    // both parameters are bounded by MAX_PREDICTOR_PARM, so this cannot
    // actually fail; checked because the numbers came out of a file
    let Some(row_bytes) = colors.checked_mul(columns) else {
        return Err(Error::Pdf(
            "the TIFF predictor's /Colors and /Columns multiply past any row size".into(),
        ));
    };
    let mut out = data.to_vec();
    for row in out.chunks_mut(row_bytes) {
        for i in colors..row.len() {
            row[i] = row[i].wrapping_add(row[i - colors]);
        }
    }
    Ok(out)
}

fn png_predictor(data: &[u8], colors: usize, bpc: usize, columns: usize) -> Result<Vec<u8>> {
    if colors == 0 || bpc == 0 || columns == 0 {
        return Err(Error::Pdf(
            "a PNG predictor needs non-zero /Colors, /BitsPerComponent and /Columns".into(),
        ));
    }
    // every factor is the file's claim, bounded by MAX_PREDICTOR_PARM and
    // multiplied with checks: the product sizes the allocation below
    let sample_bits = colors
        .checked_mul(bpc)
        .and_then(|x| x.checked_mul(columns))
        .ok_or_else(|| {
            Error::Pdf(
                "the PNG predictor's /Colors, /BitsPerComponent and /Columns multiply past \
                 any row size"
                    .into(),
            )
        })?;
    let row_bytes = sample_bits.div_ceil(8);
    // a "pixel" for the Sub and Paeth filters is one sample position, and it
    // cannot be narrower than a byte
    let bpp = colors
        .checked_mul(bpc)
        .map(|x| x.div_ceil(8))
        .unwrap_or(1)
        .max(1);
    let Some(stride) = row_bytes.checked_add(1) else {
        return Err(Error::Pdf(
            "the PNG predictor's row size does not fit in an offset".into(),
        ));
    };
    let rows = data.len() / stride;
    if rows == 0 {
        return Err(Error::Pdf(format!(
            "a PNG predicted stream holds {stride} byte rows but is only {} bytes long",
            data.len()
        )));
    }

    // rows * row_bytes is at most data.len(): every output row is paid for by
    // a stride byte input row, so the allocation stays inside the (capped)
    // decoded stream
    let Some(total) = rows.checked_mul(row_bytes) else {
        return Err(Error::Pdf(
            "the PNG predictor's output does not fit in an allocation".into(),
        ));
    };
    let mut out = vec![0u8; total];
    let mut prev = vec![0u8; row_bytes];
    for r in 0..rows {
        let row = &data[r * stride..(r + 1) * stride];
        let tag = row[0];
        let dst = &mut out[r * row_bytes..(r + 1) * row_bytes];
        dst.copy_from_slice(&row[1..]);
        match tag {
            0 => {} // None
            1 => {
                for i in bpp..row_bytes {
                    dst[i] = dst[i].wrapping_add(dst[i - bpp]);
                }
            }
            2 => {
                for i in 0..row_bytes {
                    dst[i] = dst[i].wrapping_add(prev[i]);
                }
            }
            3 => {
                for i in 0..row_bytes {
                    let left = if i >= bpp { dst[i - bpp] as u16 } else { 0 };
                    let up = prev[i] as u16;
                    dst[i] = dst[i].wrapping_add(((left + up) / 2) as u8);
                }
            }
            4 => {
                for i in 0..row_bytes {
                    let a = if i >= bpp { dst[i - bpp] } else { 0 };
                    let b = prev[i];
                    let c = if i >= bpp { prev[i - bpp] } else { 0 };
                    dst[i] = dst[i].wrapping_add(paeth(a, b, c));
                }
            }
            other => {
                return Err(Error::Pdf(format!(
                    "row {r} of a PNG predicted stream has filter tag {other}, only 0 to 4 exist"
                )));
            }
        }
        prev.copy_from_slice(dst);
    }
    Ok(out)
}

/// The PNG Paeth predictor function, byte for byte as the specification gives it.
fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let (a, b, c) = (i32::from(a), i32::from(b), i32::from(c));
    let p = a + b - c;
    let (pa, pb, pc) = ((p - a).abs(), (p - b).abs(), (p - c).abs());
    if pa <= pb && pa <= pc {
        a as u8
    } else if pb <= pc {
        b as u8
    } else {
        c as u8
    }
}

fn ascii_hex(data: &[u8]) -> Result<Vec<u8>> {
    let end = data.iter().position(|b| *b == b'>').unwrap_or(data.len());
    let mut hex: Vec<u8> = data[..end]
        .iter()
        .copied()
        .filter(|b| b.is_ascii_hexdigit())
        .collect();
    // an odd number of digits means a trailing zero, per the specification
    if hex.len() % 2 == 1 {
        hex.push(b'0');
    }
    hex::decode(&hex).map_err(|e| Error::Pdf(format!("ASCIIHexDecode failed: {e}")))
}

fn ascii85(data: &[u8]) -> Result<Vec<u8>> {
    let start = data
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(0);
    let end = data.iter().position(|b| *b == b'~').unwrap_or(data.len());
    let mut out = Vec::new();
    let mut group: u32 = 0;
    let mut count = 0;
    for b in &data[start..end] {
        if b.is_ascii_whitespace() {
            continue;
        }
        if *b == b'z' && count == 0 {
            out.extend_from_slice(&[0, 0, 0, 0]);
            continue;
        }
        if !(33..=117).contains(b) {
            return Err(Error::Pdf(format!(
                "ASCII85Decode found byte {b} outside the 33..117 range"
            )));
        }
        // checked: five 'u' characters (84) accumulate to 85^5 - 1, which is
        // one past the largest value a group can hold, 0xffffffff ("s8W-!")
        group = accumulate85(group, u32::from(b - 33))?;
        count += 1;
        if count == 5 {
            out.extend_from_slice(&group.to_be_bytes());
            group = 0;
            count = 0;
        }
    }
    if count > 0 {
        // a partial group is padded with 'u' (84) and the extra bytes dropped
        for _ in count..5 {
            group = accumulate85(group, 84)?;
        }
        out.extend_from_slice(&group.to_be_bytes()[..count - 1]);
    }
    Ok(out)
}

/// One base 85 digit of an ASCII85 group, with the overflow the format itself
/// forbids reported instead of wrapped around.
fn accumulate85(group: u32, digit: u32) -> Result<u32> {
    group
        .checked_mul(85)
        .and_then(|g| g.checked_add(digit))
        .ok_or_else(|| {
            Error::Pdf(
                "ASCII85Decode: a group of five characters exceeds 32 bits; the largest \
                 legal group is s8W-! (0xffffffff), so the stream is corrupt or hostile"
                    .into(),
            )
        })
}

/// `RunLengthDecode` with the cap enforced *as it decodes*: a repeat run is
/// worth up to 128 output bytes per input byte, so an earlier stage's (capped)
/// output can demand gigabytes from it. Growing `out` past the ceiling is
/// refused at the run that crosses it — never allocated first and then judged.
fn run_length(data: &[u8], cap: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let len = data[i];
        i += 1;
        if len == 128 {
            break; // end of data
        }
        // one run's output: a literal copy of len+1 bytes (len < 128) or a
        // repeat of 256-len+1 copies of the next byte (len > 127); both are
        // paid for against the ceiling before anything is written
        let (repeat, n) = if len < 128 {
            (false, len as usize + 1)
        } else {
            (true, 256 - len as usize + 1)
        };
        if repeat && i >= data.len() {
            return Err(Error::Pdf(
                "RunLengthDecode has a repeat with no byte to repeat".into(),
            ));
        }
        if !repeat && i + n > data.len() {
            return Err(Error::Pdf(
                "RunLengthDecode runs past the end of the stream".into(),
            ));
        }
        // checked_add against the ceiling: an expansion bomb dies here rather
        // than in the allocator
        let grown = out
            .len()
            .checked_add(n)
            .ok_or_else(|| Error::Pdf("RunLengthDecode expands past any allocation".into()))?;
        if grown > cap {
            return Err(Error::Pdf(format!(
                "RunLengthDecode expands to more than {} bytes, the most openfirma decodes \
                 from one stream: a structural stream this large is a decompression bomb, \
                 not a document",
                cap
            )));
        }
        if repeat {
            out.resize(grown, data[i]);
            i += 1;
        } else {
            out.extend_from_slice(&data[i..i + n]);
            i += n;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn deflate(bytes: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(bytes).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn flate_round_trips() {
        let raw = b"the quick brown fox jumps over the lazy dog, twice, twice";
        let dict = b"<< /Filter /FlateDecode /Length 20 >>";
        assert_eq!(decode(dict, &deflate(raw)).unwrap(), raw);
    }

    #[test]
    fn no_filter_is_the_identity() {
        assert_eq!(decode(b"<< /Length 3 >>", b"abc").unwrap(), b"abc");
    }

    #[test]
    fn the_png_predictor_undoes_every_filter_tag() {
        // one row per filter type, 4 bytes per row, bpp 1
        let rows: Vec<(u8, Vec<u8>)> = vec![
            (0, vec![1, 2, 3, 4]),
            (1, vec![10, 1, 1, 1]), // Sub: each byte adds the one to its left
            (2, vec![1, 1, 1, 1]),  // Up: each byte adds the one above
            (3, vec![2, 0, 0, 0]),  // Average
            (4, vec![0, 0, 0, 0]),  // Paeth
        ];
        let row_bytes = 4;
        let mut filtered = Vec::new();
        let mut prev = vec![0u8; row_bytes];
        let mut expected = Vec::new();
        for (tag, mut row) in rows {
            let raw = row.clone();
            match tag {
                0 => {}
                1 => {
                    let orig = row.clone();
                    for i in (1..row_bytes).rev() {
                        row[i] = orig[i].wrapping_sub(orig[i - 1]);
                    }
                }
                2 => {
                    for i in 0..row_bytes {
                        row[i] = raw[i].wrapping_sub(prev[i]);
                    }
                }
                3 => {
                    let orig = row.clone();
                    for i in 0..row_bytes {
                        let left = if i >= 1 { orig[i - 1] as u16 } else { 0 };
                        row[i] = orig[i].wrapping_sub(((left + prev[i] as u16) / 2) as u8);
                    }
                }
                4 => {
                    let orig = row.clone();
                    for i in 0..row_bytes {
                        let a = if i >= 1 { orig[i - 1] } else { 0 };
                        let c = if i >= 1 { prev[i - 1] } else { 0 };
                        row[i] = orig[i].wrapping_sub(paeth(a, prev[i], c));
                    }
                }
                _ => unreachable!(),
            }
            filtered.push(tag);
            filtered.extend_from_slice(&row);
            expected.extend_from_slice(&raw);
            prev = raw;
        }

        let dict = b"<< /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 4 >> >>";
        let got = decode(dict, &deflate(&filtered)).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn the_tiff_predictor_accumulates_across_colors() {
        // predictor parameters belong to a filter, so without /Filter nothing
        // is decoded and they must be ignored
        let dict =
            b"<< /Filter /FlateDecode /DecodeParms << /Predictor 2 /Colors 3 /Columns 2 >> >>";
        // two pixels of three colours, stored as differences from the previous
        // sample of the same colour
        let stored = vec![10, 20, 30, 1, 2, 3];
        assert_eq!(
            decode(dict, &deflate(&stored)).unwrap(),
            vec![10, 20, 30, 11, 22, 33]
        );
    }

    #[test]
    fn decode_parms_without_a_filter_are_ignored() {
        let dict = b"<< /DecodeParms << /Predictor 2 /Colors 3 /Columns 2 >> >>";
        assert_eq!(decode(dict, b"abcdef").unwrap(), b"abcdef");
    }

    #[test]
    fn ascii_hex_stops_at_the_angle_bracket_and_pads_an_odd_length() {
        assert_eq!(
            decode(b"<< /Filter /ASCIIHexDecode >>", b"4869>").unwrap(),
            b"Hi"
        );
        // an odd number of digits gets a zero nibble appended, so "486" is 0x48 0x60
        assert_eq!(
            decode(b"<< /Filter /ASCIIHexDecode >>", b"486>").unwrap(),
            vec![0x48, 0x60]
        );
    }

    #[test]
    fn run_length_expands_and_copies() {
        // 2 bytes literal "AB", then repeat the next byte 4 times, then EOD
        let stored = vec![1, b'A', b'B', 253, b'x', 128];
        assert_eq!(
            decode(b"<< /Filter /RunLengthDecode >>", &stored).unwrap(),
            b"ABxxxx"
        );
    }

    #[test]
    fn ascii85_decodes_the_canonical_example() {
        // "Man " is the example from the specification
        assert_eq!(
            decode(b"<< /Filter /ASCII85Decode >>", b"9jqo^~>").unwrap(),
            b"Man "
        );
    }

    /// The largest group the format defines, s8W-! = 0xffffffff, decodes, and
    /// one step past it is a typed error instead of a debug panic or, worse,
    /// a silent wrap that invents four bytes of stream.
    #[test]
    fn ascii85_accepts_the_largest_legal_group_and_refuses_the_next() {
        let dict = b"<< /Filter /ASCII85Decode >>";
        assert_eq!(decode(dict, b"s8W-!~>").unwrap(), [0xff, 0xff, 0xff, 0xff]);
        let err = decode(dict, b"uuuuu~>").unwrap_err().to_string();
        assert!(err.contains("exceeds 32 bits"), "{err}");
        // a partial group is padded with 'u', and "uuuu" padded reaches past
        // 32 bits exactly like the full group does
        let err = decode(dict, b"uuuu~>").unwrap_err().to_string();
        assert!(err.contains("exceeds 32 bits"), "{err}");
    }

    #[test]
    fn inflate_stops_at_the_cap_and_names_it() {
        // 4 KiB of zeros compresses to nothing; the cap under test is small
        // so the refusal is exercised without materializing a real bomb
        let bomb = deflate(&vec![0u8; 4096]);
        assert_eq!(inflate_capped(&bomb, 4096).unwrap().len(), 4096);
        let err = inflate_capped(&bomb, 1024).unwrap_err().to_string();
        assert!(err.contains("1024 bytes"), "{err}");
        assert!(err.contains("decompression bomb"), "{err}");
    }

    /// The chain the review's runlength-bomb PoC is: flate to a legal (capped)
    /// intermediate, then RunLengthDecode ×128. The expansion is refused at
    /// the cap during decoding, not allocated and then judged — the same test
    /// shape as `inflate_stops_at_the_cap_and_names_it`, one stage further.
    #[test]
    fn a_runlength_stage_past_the_cap_is_refused_without_allocating_it() {
        // 700 zero bytes inflate fine under a 1 KiB cap; encoded as RLE each
        // is the head of a 128-fold repeat, so the stage wants ~87 KiB from
        // what flate delivered legitimately.
        let dict = b"<< /Filter [/FlateDecode /RunLengthDecode] >>";
        // a legal RLE of one 128-fold repeat: 128 zeros, well under the cap
        assert_eq!(
            decode_capped(dict, &deflate(&[129u8, 0u8]), 1024).unwrap(),
            vec![0u8; 128]
        );
        // 100 repeat pairs is 200 bytes inflated — legal under the 1 KiB cap —
        // and asks RunLengthDecode for 12800, which is not
        let mut rle = Vec::new();
        for _ in 0..100 {
            rle.push(129u8); // repeat the next byte 128 times
            rle.push(0);
        }
        rle.push(128); // end of data marker — never reached, the cap trips first
        let err = decode_capped(dict, &deflate(&rle), 1024)
            .unwrap_err()
            .to_string();
        assert!(err.contains("RunLengthDecode"), "{err}");
        assert!(err.contains("1024 bytes"), "the cap must be named: {err}");
    }

    /// A single /RunLengthDecode (no flate before it) is subject to the same
    /// ceiling: every `129 x` pair decodes to 128 copies, so a few hundred of
    /// them cross a 4 KiB cap and are refused instead of grown.
    #[test]
    fn a_runlength_stage_alone_respects_the_cap_too() {
        let mut bomb = Vec::new();
        for _ in 0..64 {
            bomb.push(129u8); // -127: repeat the next byte 128 times
            bomb.push(b'x');
        }
        bomb.push(128); // end of data, past where the cap trips
        let dict = b"<< /Filter /RunLengthDecode >>";
        // three pairs are 384 bytes and fit; the full stream does not
        assert_eq!(decode_capped(dict, &bomb[..6], 4096).unwrap().len(), 384);
        let err = decode_capped(dict, &bomb, 4096).unwrap_err().to_string();
        assert!(err.contains("RunLengthDecode"), "{err}");
        assert!(err.contains("4096 bytes"), "the cap must be named: {err}");
    }

    /// The other expansion filters are checked per stage as well: ASCIIHex
    /// doubles its input, and a chain of them after a capped flate must not
    /// multiply past the ceiling unchecked.
    #[test]
    fn every_stage_of_a_chain_is_checked() {
        let hex = vec![b'4'; 3000]; // 1500 bytes out: fine under 2 KiB, over 1 KiB
        let dict = b"<< /Filter [/ASCIIHexDecode] >>";
        assert_eq!(decode_capped(dict, &hex, 2048).unwrap().len(), 1500);
        let err = decode_capped(dict, &hex, 1024).unwrap_err().to_string();
        assert!(err.contains("ASCIIHexDecode"), "{err}");
        assert!(err.contains("1024 bytes"), "the cap must be named: {err}");
    }

    /// The predictor parameters come out of the file and size an allocation,
    /// so they are bounded before anything is computed from them. A negative
    /// /Columns used to become a near-usize::MAX row width through an
    /// `as usize`, and an absurd one an allocation attempt of the same size.
    #[test]
    fn predictor_parameters_outside_the_bounds_are_refused() {
        let data = deflate(&[0u8; 64]);
        for dict in [
            b"<< /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns -1 >> >>".as_slice(),
            b"<< /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 99999999 >> >>",
            b"<< /Filter /FlateDecode /DecodeParms << /Predictor 2 /Colors -3 /Columns 4 >> >>",
        ] {
            let err = decode(dict, &data).unwrap_err().to_string();
            assert!(err.contains("65536"), "the cap must be named: {err}");
        }
    }

    #[test]
    fn an_unsupported_filter_says_which() {
        let err = decode(b"<< /Filter /DCTDecode >>", b"x")
            .unwrap_err()
            .to_string();
        assert!(err.contains("DCTDecode"), "{err}");
    }
}
