use crate::{error::Error, rectangle::Rectangle, signature_options::SignatureAnchorMode};
use lopdf::{content::Content, Document, Object, ObjectId};

// ---------------------------------------------------------------------------
// Helvetica glyph-width table (width / 1000 units, per Adobe AFM spec).
// Covers printable ASCII 0x20..0x7E.  For characters outside this range we
// fall back to 500/1000 (the standard "average" width).
// ---------------------------------------------------------------------------
const HELVETICA_WIDTHS: [u16; 95] = [
    278, // 0x20 space
    278, // 0x21 !
    355, // 0x22 "
    556, // 0x23 #
    556, // 0x24 $
    889, // 0x25 %
    667, // 0x26 &
    191, // 0x27 '
    333, // 0x28 (
    333, // 0x29 )
    389, // 0x2A *
    584, // 0x2B +
    278, // 0x2C ,
    333, // 0x2D -
    278, // 0x2E .
    278, // 0x2F /
    556, // 0x30 0
    556, // 0x31 1
    556, // 0x32 2
    556, // 0x33 3
    556, // 0x34 4
    556, // 0x35 5
    556, // 0x36 6
    556, // 0x37 7
    556, // 0x38 8
    556, // 0x39 9
    278, // 0x3A :
    278, // 0x3B ;
    584, // 0x3C <
    584, // 0x3D =
    584, // 0x3E >
    556, // 0x3F ?
    1015,// 0x40 @
    667, // 0x41 A
    667, // 0x42 B
    722, // 0x43 C
    722, // 0x44 D
    667, // 0x45 E
    611, // 0x46 F
    778, // 0x47 G
    722, // 0x48 H
    278, // 0x49 I
    500, // 0x4A J
    667, // 0x4B K
    556, // 0x4C L
    833, // 0x4D M
    722, // 0x4E N
    778, // 0x4F O
    667, // 0x50 P
    778, // 0x51 Q
    722, // 0x52 R
    667, // 0x53 S
    611, // 0x54 T
    722, // 0x55 U
    667, // 0x56 V
    944, // 0x57 W
    667, // 0x58 X
    667, // 0x59 Y
    611, // 0x5A Z
    278, // 0x5B [
    278, // 0x5C backslash
    278, // 0x5D ]
    469, // 0x5E ^
    556, // 0x5F _
    333, // 0x60 `
    556, // 0x61 a
    556, // 0x62 b
    500, // 0x63 c
    556, // 0x64 d
    556, // 0x65 e
    278, // 0x66 f
    556, // 0x67 g
    556, // 0x68 h
    222, // 0x69 i
    222, // 0x6A j
    500, // 0x6B k
    222, // 0x6C l
    833, // 0x6D m
    556, // 0x6E n
    556, // 0x6F o
    556, // 0x70 p
    556, // 0x71 q
    333, // 0x72 r
    500, // 0x73 s
    278, // 0x74 t
    556, // 0x75 u
    500, // 0x76 v
    722, // 0x77 w
    500, // 0x78 x
    500, // 0x79 y
    500, // 0x7A z
    334, // 0x7B {
    260, // 0x7C |
    334, // 0x7D }
    584, // 0x7E ~
];

/// Return the width of a single character in 1/1000 units of font size,
/// using the Helvetica AFM metrics.  Falls back to 500 for unknown chars.
fn glyph_width_1000(ch: char) -> f64 {
    let code = ch as u32;
    if (0x20..=0x7E).contains(&code) {
        HELVETICA_WIDTHS[(code - 0x20) as usize] as f64
    } else {
        500.0 // fallback for non-ASCII
    }
}

/// Compute the rendered width of `text` at `font_size` in PDF user-space
/// points, using per-glyph Helvetica metrics and the current horizontal
/// scale factor from the text matrix.
fn estimate_text_width(font_size: f64, text: &str, h_scale: f64) -> f64 {
    let raw: f64 = text.chars().map(|c| glyph_width_1000(c)).sum();
    // width_in_1000 * font_size / 1000 * horizontal_scale
    raw * font_size / 1000.0 * h_scale
}

// ---------------------------------------------------------------------------
// Text state tracker — tracks position through the full Tm matrix
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct TextState {
    /// Current text-line x (from Tm e, or accumulated Td)
    tx: f64,
    /// Current text-line y (from Tm f, or accumulated Td)
    ty: f64,
    /// Horizontal scale factor from the text matrix (Tm a element).
    /// Defaults to 1.0.  Affected by `Tm` and the `Tz` operator.
    h_scale: f64,
    /// Vertical scale factor from the text matrix (Tm d element).
    v_scale: f64,
    /// Text leading (set by TL or TD)
    leading: f64,
    /// Current font size from Tf
    font_size: f64,
    /// Character spacing (set by Tc)
    char_spacing: f64,
    /// Word spacing (set by Tw)
    word_spacing: f64,
}

impl Default for TextState {
    fn default() -> Self {
        Self {
            tx: 0.0,
            ty: 0.0,
            h_scale: 1.0,
            v_scale: 1.0,
            leading: 0.0,
            font_size: 12.0,
            char_spacing: 0.0,
            word_spacing: 0.0,
        }
    }
}

fn obj_as_f64(obj: &Object) -> Option<f64> {
    match obj {
        Object::Integer(i) => Some(*i as f64),
        Object::Real(f) => Some(*f as f64),
        _ => None,
    }
}

fn decode_pdf_text(obj: &Object) -> Option<String> {
    match obj {
        Object::String(bytes, _) => Some(String::from_utf8_lossy(bytes).into_owned()),
        _ => None,
    }
}

fn extract_text_from_tj_array(obj: &Object) -> Option<String> {
    let arr = obj.as_array().ok()?;
    let mut out = String::new();
    for item in arr {
        if let Some(part) = decode_pdf_text(item) {
            out.push_str(&part);
        }
    }
    Some(out)
}

/// Compute x-offset of the tag start within `text`, accounting for
/// per-glyph widths, character spacing, and word spacing.
fn text_prefix_width(state: &TextState, text: &str) -> f64 {
    let glyph_w: f64 = text.chars().map(|c| glyph_width_1000(c)).sum();
    let base = glyph_w * state.font_size / 1000.0 * state.h_scale;
    let n = text.chars().count() as f64;
    let spaces = text.chars().filter(|&c| c == ' ').count() as f64;
    base + n * state.char_spacing + spaces * state.word_spacing
}

/// Result of anchor resolution: (x, y, effective_font_size, h_scale)
type AnchorHit = (f64, f64, f64, f64);

fn resolve_anchor_position(page_content: &[u8], tag: &str) -> Result<Option<AnchorHit>, Error> {
    let content = Content::decode(page_content)?;
    let mut state = TextState::default();

    for op in content.operations {
        match op.operator.as_ref() {
            "BT" => {
                // Begin Text — reset text matrix to identity
                state.tx = 0.0;
                state.ty = 0.0;
                state.h_scale = 1.0;
                state.v_scale = 1.0;
            }
            "Tf" => {
                if op.operands.len() >= 2 {
                    if let Some(size) = obj_as_f64(&op.operands[1]) {
                        state.font_size = size.abs(); // always positive
                    }
                }
            }
            "TL" => {
                if let Some(lead) = op.operands.first().and_then(obj_as_f64) {
                    state.leading = lead;
                }
            }
            "Tc" => {
                if let Some(tc) = op.operands.first().and_then(obj_as_f64) {
                    state.char_spacing = tc;
                }
            }
            "Tw" => {
                if let Some(tw) = op.operands.first().and_then(obj_as_f64) {
                    state.word_spacing = tw;
                }
            }
            "Tz" => {
                // Horizontal scaling percentage (100 = normal)
                if let Some(pct) = op.operands.first().and_then(obj_as_f64) {
                    state.h_scale = pct / 100.0;
                }
            }
            "Tm" => {
                // Full text matrix: [a b c d e f]
                if op.operands.len() >= 6 {
                    if let (Some(a), Some(d), Some(e), Some(f)) = (
                        obj_as_f64(&op.operands[0]),
                        obj_as_f64(&op.operands[3]),
                        obj_as_f64(&op.operands[4]),
                        obj_as_f64(&op.operands[5]),
                    ) {
                        state.h_scale = a;
                        state.v_scale = d;
                        state.tx = e;
                        state.ty = f;
                    }
                }
            }
            "Td" | "TD" => {
                if op.operands.len() >= 2 {
                    if let (Some(dx), Some(dy)) = (obj_as_f64(&op.operands[0]), obj_as_f64(&op.operands[1])) {
                        state.tx += dx;
                        state.ty += dy;
                        if op.operator == "TD" {
                            state.leading = -dy;
                        }
                    }
                }
            }
            "T*" => {
                state.ty -= state.leading;
            }
            "Tj" => {
                if let Some(text) = op.operands.first().and_then(decode_pdf_text) {
                    if let Some(idx) = text.find(tag) {
                        let before = &text[..idx];
                        let x = state.tx + text_prefix_width(&state, before);
                        return Ok(Some((x, state.ty, state.font_size, state.h_scale)));
                    }
                }
            }
            "TJ" => {
                if let Some(text) = op.operands.first().and_then(extract_text_from_tj_array) {
                    if let Some(idx) = text.find(tag) {
                        let before = &text[..idx];
                        let x = state.tx + text_prefix_width(&state, before);
                        return Ok(Some((x, state.ty, state.font_size, state.h_scale)));
                    }
                }
            }
            "'" => {
                state.ty -= state.leading;
                if let Some(text) = op.operands.first().and_then(decode_pdf_text) {
                    if let Some(idx) = text.find(tag) {
                        let before = &text[..idx];
                        let x = state.tx + text_prefix_width(&state, before);
                        return Ok(Some((x, state.ty, state.font_size, state.h_scale)));
                    }
                }
            }
            "\"" => {
                // Set word/char spacing, then move to next line, then show text
                if op.operands.len() >= 3 {
                    if let Some(aw) = obj_as_f64(&op.operands[0]) {
                        state.word_spacing = aw;
                    }
                    if let Some(ac) = obj_as_f64(&op.operands[1]) {
                        state.char_spacing = ac;
                    }
                }
                state.ty -= state.leading;
                if op.operands.len() >= 3 {
                    if let Some(text) = decode_pdf_text(&op.operands[2]) {
                        if let Some(idx) = text.find(tag) {
                            let before = &text[..idx];
                            let x = state.tx + text_prefix_width(&state, before);
                            return Ok(Some((x, state.ty, state.font_size, state.h_scale)));
                        }
                    }
                }
            }
            _ => {}
        }
    }

    Ok(None)
}

/// Typical font descent ratio (negative, relative to 1.0 = font_size).
/// Helvetica descent is -207/1000 ≈ -0.207.
const FONT_DESCENT_RATIO: f64 = 0.207;

pub fn resolve_rect_from_tag(
    prev_doc: &Document,
    page_ref: ObjectId,
    tag: &str,
    mode: &SignatureAnchorMode,
    width: f64,
    height: f64,
) -> Result<Rectangle, Error> {
    if width <= 0.0 || height <= 0.0 {
        return Err(Error::Other("signature anchor width/height must be > 0".to_owned()));
    }

    let page_content = prev_doc.get_page_content(page_ref)?;
    let found = resolve_anchor_position(&page_content, tag)?;

    let (x, y, font_size, h_scale) = found.ok_or_else(|| {
        Error::Other(format!(
            "signature anchor tag '{}' was not found on page object {:?}",
            tag, page_ref
        ))
    })?;

    // y is the text baseline.  Place the rectangle so its bottom
    // aligns with the font descent and its top extends by `height`.
    let y_bottom = y - font_size * FONT_DESCENT_RATIO;

    let tag_rendered_width = estimate_text_width(font_size, tag, h_scale);

    let rect = match mode {
        SignatureAnchorMode::Overlay => Rectangle {
            x1: x,
            y1: y_bottom,
            x2: x + width,
            y2: y_bottom + height,
        },
        SignatureAnchorMode::InFront => {
            let start_x = x + tag_rendered_width;
            Rectangle {
                x1: start_x,
                y1: y_bottom,
                x2: start_x + width,
                y2: y_bottom + height,
            }
        }
    };

    Ok(rect)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature_options::SignatureAnchorMode;
    use lopdf::Document;

    // -----------------------------------------------------------------------
    // Helper: build a synthetic page-content stream that contains `tag` text
    // at a known position controlled by Tm, Td, etc.
    // -----------------------------------------------------------------------

    fn make_content_with_tag(tag: &str) -> Vec<u8> {
        format!(
            "BT\n\
             /F1 12 Tf\n\
             1 0 0 1 72 700 Tm\n\
             (This is line one.) Tj\n\
             1 0 0 1 72 620 Tm\n\
             (Signature: {tag}) Tj\n\
             ET\n"
        ).into_bytes()
    }

    fn make_content_with_td(tag: &str) -> Vec<u8> {
        format!(
            "BT\n\
             /F1 10 Tf\n\
             100 500 Td\n\
             (Before {tag} After) Tj\n\
             ET\n"
        ).into_bytes()
    }

    fn make_content_no_tag() -> Vec<u8> {
        b"BT\n/F1 12 Tf\n1 0 0 1 72 700 Tm\n(No special marker here.) Tj\nET\n".to_vec()
    }

    fn make_content_with_tj_array(tag: &str) -> Vec<u8> {
        // TJ array: [(Signa) 10 (ture: ) 20 (#SIGN_HERE)]
        // We include the tag as a separate string element in the TJ array.
        format!(
            "BT\n\
             /F1 12 Tf\n\
             1 0 0 1 72 620 Tm\n\
             [(Signature: ) 10 ({tag})] TJ\n\
             ET\n"
        ).into_bytes()
    }

    // -----------------------------------------------------------------------
    // Unit tests: resolve_anchor_position
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_anchor_position_with_tm_and_tj() {
        let content = make_content_with_tag("#SIGN_HERE");
        let result = resolve_anchor_position(&content, "#SIGN_HERE").unwrap();
        assert!(result.is_some(), "Tag should be found");

        let (x, y, font_size, h_scale) = result.unwrap();
        // Tm is `1 0 0 1 72 620` so h_scale = 1.0
        assert!((font_size - 12.0).abs() < 0.01, "font_size should be 12, got {}", font_size);
        assert!((h_scale - 1.0).abs() < 0.01, "h_scale should be 1.0, got {}", h_scale);
        assert!((y - 620.0).abs() < 0.01, "y should be 620, got {}", y);
        let expected_x = 72.0 + estimate_text_width(12.0, "Signature: ", 1.0);
        assert!(
            (x - expected_x).abs() < 0.01,
            "x should be ~{}, got {}",
            expected_x,
            x
        );
    }

    #[test]
    fn test_resolve_anchor_position_with_td() {
        let content = make_content_with_td("#SIGN");
        let result = resolve_anchor_position(&content, "#SIGN").unwrap();
        assert!(result.is_some(), "Tag should be found with Td operator");

        let (x, y, font_size, h_scale) = result.unwrap();
        assert!((font_size - 10.0).abs() < 0.01, "font_size should be 10, got {}", font_size);
        assert!((h_scale - 1.0).abs() < 0.01, "h_scale should be 1.0, got {}", h_scale);
        assert!((y - 500.0).abs() < 0.01, "y should be 500, got {}", y);
        let expected_x = 100.0 + estimate_text_width(10.0, "Before ", 1.0);
        assert!(
            (x - expected_x).abs() < 0.01,
            "x should be ~{}, got {}",
            expected_x,
            x
        );
    }

    #[test]
    fn test_resolve_anchor_position_tag_not_found() {
        let content = make_content_no_tag();
        let result = resolve_anchor_position(&content, "#SIGN_HERE").unwrap();
        assert!(result.is_none(), "Tag should NOT be found");
    }

    #[test]
    fn test_resolve_anchor_position_with_tj_array() {
        let content = make_content_with_tj_array("#SIGN_HERE");
        let result = resolve_anchor_position(&content, "#SIGN_HERE").unwrap();
        assert!(result.is_some(), "Tag should be found in TJ array");

        let (x, y, font_size, _h_scale) = result.unwrap();
        assert!((font_size - 12.0).abs() < 0.01);
        assert!((y - 620.0).abs() < 0.01);
        let expected_x = 72.0 + estimate_text_width(12.0, "Signature: ", 1.0);
        assert!(
            (x - expected_x).abs() < 0.01,
            "x should be ~{}, got {}",
            expected_x,
            x
        );
    }

    #[test]
    fn test_resolve_anchor_position_empty_tag() {
        // An empty tag matches the very start of the first text string
        let content = make_content_with_tag("#SIGN_HERE");
        let result = resolve_anchor_position(&content, "").unwrap();
        assert!(result.is_some(), "Empty tag should match start of first text");
    }

    // -----------------------------------------------------------------------
    // Unit tests: resolve_rect_from_tag  (requires a real Document)
    // -----------------------------------------------------------------------

    /// Load the test PDF that contains "#SIGN_HERE" in its content stream.
    fn load_tag_test_pdf() -> Document {
        let pdf_bytes = std::fs::read("examples/assets/sample-tag-sign.pdf")
            .expect("sample-tag-sign.pdf must exist – run generate_tag_pdf.py first");
        Document::load_mem(&pdf_bytes).expect("Failed to parse sample-tag-sign.pdf")
    }

    fn first_page_id(doc: &Document) -> ObjectId {
        let root_ref = doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
        let root_dict = doc.get_object(root_ref).unwrap().as_dict().unwrap();
        let pages_ref = root_dict.get(b"Pages").unwrap().as_reference().unwrap();
        let pages_dict = doc.get_object(pages_ref).unwrap().as_dict().unwrap();
        let kids = pages_dict.get(b"Kids").unwrap().as_array().unwrap();
        kids[0].as_reference().unwrap()
    }

    #[test]
    fn test_resolve_rect_from_tag_in_front_mode() {
        let doc = load_tag_test_pdf();
        let page_id = first_page_id(&doc);

        let rect = resolve_rect_from_tag(
            &doc,
            page_id,
            "#SIGN_HERE",
            &SignatureAnchorMode::InFront,
            180.0,
            64.0,
        )
        .expect("resolve_rect_from_tag should succeed");

        // In InFront mode, x1 should be offset past the tag text
        let _tag_width = estimate_text_width(12.0, "#SIGN_HERE", 1.0);
        assert!(
            rect.x1 > 72.0,
            "x1 should be > page left margin 72, got {}",
            rect.x1
        );
        assert!(
            (rect.x2 - rect.x1 - 180.0).abs() < 0.01,
            "Width should be 180, got {}",
            rect.x2 - rect.x1
        );
        assert!(
            (rect.y2 - rect.y1 - 64.0).abs() < 0.01,
            "Height should be 64, got {}",
            rect.y2 - rect.y1
        );
        println!(
            "InFront rect: x1={:.1}, y1={:.1}, x2={:.1}, y2={:.1}",
            rect.x1, rect.y1, rect.x2, rect.y2
        );
    }

    #[test]
    fn test_resolve_rect_from_tag_overlay_mode() {
        let doc = load_tag_test_pdf();
        let page_id = first_page_id(&doc);

        let rect = resolve_rect_from_tag(
            &doc,
            page_id,
            "#SIGN_HERE",
            &SignatureAnchorMode::Overlay,
            120.0,
            48.0,
        )
        .expect("resolve_rect_from_tag should succeed in overlay mode");

        // In overlay mode, x1 should be at the tag start position (past "Signature: ")
        assert!(
            (rect.x2 - rect.x1 - 120.0).abs() < 0.01,
            "Width should be 120, got {}",
            rect.x2 - rect.x1
        );
        assert!(
            (rect.y2 - rect.y1 - 48.0).abs() < 0.01,
            "Height should be 48, got {}",
            rect.y2 - rect.y1
        );
        println!(
            "Overlay rect: x1={:.1}, y1={:.1}, x2={:.1}, y2={:.1}",
            rect.x1, rect.y1, rect.x2, rect.y2
        );
    }

    #[test]
    fn test_resolve_rect_from_tag_not_found_returns_error() {
        let doc = load_tag_test_pdf();
        let page_id = first_page_id(&doc);

        let result = resolve_rect_from_tag(
            &doc,
            page_id,
            "#NONEXISTENT_TAG",
            &SignatureAnchorMode::InFront,
            100.0,
            50.0,
        );
        assert!(result.is_err(), "Should return error for missing tag");

        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("#NONEXISTENT_TAG"),
            "Error should mention the missing tag, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_resolve_rect_invalid_dimensions() {
        let doc = load_tag_test_pdf();
        let page_id = first_page_id(&doc);

        let result = resolve_rect_from_tag(
            &doc,
            page_id,
            "#SIGN_HERE",
            &SignatureAnchorMode::InFront,
            0.0,
            50.0,
        );
        assert!(result.is_err(), "Should error on zero width");

        let result2 = resolve_rect_from_tag(
            &doc,
            page_id,
            "#SIGN_HERE",
            &SignatureAnchorMode::InFront,
            100.0,
            -10.0,
        );
        assert!(result2.is_err(), "Should error on negative height");
    }

    // -----------------------------------------------------------------------
    // Integration test: full signing with tag anchor
    // -----------------------------------------------------------------------

    #[test]
    fn test_end_to_end_sign_with_tag_anchor() {
        use crate::signature_options::{SignatureFormat, PadesLevel};
        use crate::{PDFSigningDocument, SignatureOptions, UserSignatureInfo};
        use cryptographic_message_syntax::SignerBuilder;
        use x509_certificate::{CapturedX509Certificate, InMemorySigningKeyPair};

        // Load cert + key
        let cert_pem = std::fs::read_to_string("examples/assets/keystore-local-chain.pem")
            .expect("cert PEM");
        let x509_certs = CapturedX509Certificate::from_pem_multiple(&cert_pem)
            .expect("parse certs");
        let key_pem = std::fs::read_to_string("examples/assets/keystore-local-key.pem")
            .expect("key PEM");
        let private_key = InMemorySigningKeyPair::from_pkcs8_pem(&key_pem)
            .expect("parse key");
        let signer = SignerBuilder::new(&private_key, x509_certs[0].clone());

        let sig_image = std::fs::read("examples/assets/sig1.png").expect("sig image");
        let pdf_bytes = std::fs::read("examples/assets/sample-tag-sign.pdf")
            .expect("sample-tag-sign.pdf");

        let user_info = UserSignatureInfo {
            user_id: "tag-test".to_owned(),
            user_name: "TagTester".to_owned(),
            user_email: "tag@test.com".to_owned(),
            user_signature: sig_image,
            user_signing_keys: signer,
            user_certificate_chain: x509_certs,
        };

        let opts = SignatureOptions {
            format: SignatureFormat::PKCS7,
            timestamp_url: None, // skip TSA for test speed
            signature_size: 30_000,
            include_dss: false,
            signed_attribute_include_crl: false,
            signed_attribute_include_ocsp: false,
            signature_page: Some(1),
            signature_rect: None,
            visible_signature: true,
            signature_anchor_tag: Some("#SIGN_HERE".to_owned()),
            signature_anchor_width: Some(180.0),
            signature_anchor_height: Some(64.0),
            signature_anchor_mode: SignatureAnchorMode::InFront,
            pades_level: PadesLevel::B_B,
        };

        let mut pdf_doc = PDFSigningDocument::read_from(&*pdf_bytes, "sample-tag-sign.pdf".to_owned())
            .expect("load PDF");

        let signed_pdf = pdf_doc
            .sign_document_no_placeholder(&user_info, &opts)
            .expect("signing with tag anchor should succeed");

        assert!(
            signed_pdf.len() > pdf_bytes.len(),
            "Signed PDF ({} bytes) should be larger than input ({} bytes)",
            signed_pdf.len(),
            pdf_bytes.len()
        );

        // Write to disk for manual inspection
        let out_path = "examples/assets/result-tag-sign.pdf";
        std::fs::write(out_path, &signed_pdf).expect("write signed PDF");
        println!(
            "✅ Tag-anchored signed PDF written to {} ({} bytes)",
            out_path,
            signed_pdf.len()
        );

        // Verify the signed PDF is loadable
        let reload = Document::load_mem(&signed_pdf);
        assert!(reload.is_ok(), "Signed PDF should be parseable");
    }

    #[test]
    fn test_sign_by_tag_convenience_api() {
        use crate::signature_options::{SignatureFormat, PadesLevel};
        use crate::{PDFSigningDocument, SignatureOptions, UserSignatureInfo};
        use cryptographic_message_syntax::SignerBuilder;
        use x509_certificate::{CapturedX509Certificate, InMemorySigningKeyPair};

        let cert_pem = std::fs::read_to_string("examples/assets/keystore-local-chain.pem")
            .expect("cert PEM");
        let x509_certs = CapturedX509Certificate::from_pem_multiple(&cert_pem)
            .expect("parse certs");
        let key_pem = std::fs::read_to_string("examples/assets/keystore-local-key.pem")
            .expect("key PEM");
        let private_key = InMemorySigningKeyPair::from_pkcs8_pem(&key_pem)
            .expect("parse key");
        let signer = SignerBuilder::new(&private_key, x509_certs[0].clone());

        let sig_image = std::fs::read("examples/assets/sig1.png").expect("sig image");
        let pdf_bytes = std::fs::read("examples/assets/sample-tag-sign.pdf")
            .expect("sample-tag-sign.pdf");

        let user_info = UserSignatureInfo {
            user_id: "convenience-test".to_owned(),
            user_name: "ConvTester".to_owned(),
            user_email: "conv@test.com".to_owned(),
            user_signature: sig_image,
            user_signing_keys: signer,
            user_certificate_chain: x509_certs,
        };

        let opts = SignatureOptions {
            format: SignatureFormat::PKCS7,
            timestamp_url: None,
            signature_size: 30_000,
            include_dss: false,
            signed_attribute_include_crl: false,
            signed_attribute_include_ocsp: false,
            signature_page: Some(1),
            signature_rect: None,
            visible_signature: false, // will be overridden by convenience API
            signature_anchor_tag: None,
            signature_anchor_width: None,
            signature_anchor_height: None,
            signature_anchor_mode: SignatureAnchorMode::InFront,
            pades_level: PadesLevel::B_B,
        };

        let mut pdf_doc = PDFSigningDocument::read_from(&*pdf_bytes, "sample-tag-sign.pdf".to_owned())
            .expect("load PDF");

        let signed_pdf = pdf_doc
            .sign_document_no_placeholder_visible_by_tag(
                &user_info,
                &opts,
                "#SIGN_HERE",
                200.0,
                72.0,
            )
            .expect("convenience sign_by_tag should succeed");

        assert!(
            signed_pdf.len() > pdf_bytes.len(),
            "Signed PDF should be larger than input"
        );
        println!(
            "✅ Convenience API signed PDF: {} bytes",
            signed_pdf.len()
        );
    }

    #[test]
    fn test_sign_with_missing_tag_returns_error() {
        use crate::signature_options::{SignatureFormat, PadesLevel};
        use crate::{PDFSigningDocument, SignatureOptions, UserSignatureInfo};
        use cryptographic_message_syntax::SignerBuilder;
        use x509_certificate::{CapturedX509Certificate, InMemorySigningKeyPair};

        let cert_pem = std::fs::read_to_string("examples/assets/keystore-local-chain.pem")
            .expect("cert PEM");
        let x509_certs = CapturedX509Certificate::from_pem_multiple(&cert_pem)
            .expect("parse certs");
        let key_pem = std::fs::read_to_string("examples/assets/keystore-local-key.pem")
            .expect("key PEM");
        let private_key = InMemorySigningKeyPair::from_pkcs8_pem(&key_pem)
            .expect("parse key");
        let signer = SignerBuilder::new(&private_key, x509_certs[0].clone());

        let sig_image = std::fs::read("examples/assets/sig1.png").expect("sig image");
        let pdf_bytes = std::fs::read("examples/assets/sample-tag-sign.pdf")
            .expect("sample-tag-sign.pdf");

        let user_info = UserSignatureInfo {
            user_id: "err-test".to_owned(),
            user_name: "ErrTester".to_owned(),
            user_email: "err@test.com".to_owned(),
            user_signature: sig_image,
            user_signing_keys: signer,
            user_certificate_chain: x509_certs,
        };

        let opts = SignatureOptions {
            format: SignatureFormat::PKCS7,
            timestamp_url: None,
            signature_size: 30_000,
            include_dss: false,
            signed_attribute_include_crl: false,
            signed_attribute_include_ocsp: false,
            signature_page: Some(1),
            signature_rect: None,
            visible_signature: true,
            signature_anchor_tag: Some("#DOES_NOT_EXIST".to_owned()),
            signature_anchor_width: Some(100.0),
            signature_anchor_height: Some(50.0),
            signature_anchor_mode: SignatureAnchorMode::InFront,
            pades_level: PadesLevel::B_B,
        };

        let mut pdf_doc = PDFSigningDocument::read_from(&*pdf_bytes, "sample-tag-sign.pdf".to_owned())
            .expect("load PDF");

        let result = pdf_doc.sign_document_no_placeholder(&user_info, &opts);
        assert!(
            result.is_err(),
            "Signing with non-existent tag should fail"
        );

        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("#DOES_NOT_EXIST"),
            "Error should mention the missing tag: {}",
            err_msg
        );
        println!("✅ Missing tag correctly returned error: {}", err_msg);
    }
}
