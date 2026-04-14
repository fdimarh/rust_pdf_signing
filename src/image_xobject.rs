// This code is inspired by https://github.com/fschutt/printpdf/blob/2bebdc65d06dafbe926ed4b43fedd10f966c59d3/src/xobject.rs

use crate::Error;
use lopdf::ObjectId;
use png::{BitDepth, ColorType};
use std::io::{BufRead, Read, Seek};

/// Detected image format used to choose the right decoding path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    /// JPEG / JFIF — embedded as-is with a `DCTDecode` PDF filter.
    Jpeg,
    /// PNG — decoded with the `png` crate to preserve the alpha channel.
    Png,
    /// Any other format supported by the `image` crate (BMP, GIF, TIFF, WebP …).
    Other,
}

/// Detect the image format from the first bytes of the data.
pub fn detect_image_format(data: &[u8]) -> ImageFormat {
    if data.len() >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
        return ImageFormat::Jpeg;
    }
    if data.len() >= 8
        && data[0] == 0x89
        && &data[1..4] == b"PNG"
        && data[4] == 0x0D
        && data[5] == 0x0A
        && data[6] == 0x1A
        && data[7] == 0x0A
    {
        return ImageFormat::Png;
    }
    ImageFormat::Other
}

/// An image resource ready to be embedded in a PDF as an `XObject`.
///
/// For JPEG images the raw encoded bytes are stored directly in `image_data`
/// and `is_jpeg` is set to `true`; the PDF stream will use a `DCTDecode`
/// filter so no quality is lost.  For all other formats the image is
/// decoded to raw RGB/Gray pixel data first.
#[derive(Debug, Clone)]
pub struct ImageXObject {
    /// Width of the image (original width, not scaled width).
    pub width: u32,
    /// Height of the image (original height, not scaled height).
    pub height: u32,
    /// Color space (Greyscale, RGB, CMYK).
    pub color_space: ColorType,
    /// Bits per color component (1, 2, 4, 8, 16).
    pub bits_per_component: BitDepth,
    /// Whether to apply bilinear interpolation when the image is scaled.
    pub interpolate: bool,
    /// Raw or encoded image bytes (depending on `is_jpeg`).
    pub image_data: Vec<u8>,
    /// `true` when `image_data` contains JPEG-encoded bytes (DCTDecode).
    pub is_jpeg: bool,
    /// Object-ID of the soft-mask (alpha channel) image, if present.
    pub s_mask: Option<ObjectId>,
}

impl ImageXObject {
    // ──────────────────────────────────────────────────────────────────────────
    // Constructors
    // ──────────────────────────────────────────────────────────────────────────

    /// Build an `ImageXObject` from raw image bytes, automatically detecting
    /// the format (JPEG, PNG, BMP, GIF, TIFF, WebP, …).
    ///
    /// Returns `(color_image, Option<alpha_mask_image>)`.
    pub fn from_bytes(data: &[u8]) -> Result<(Self, Option<Self>), Error> {
        match detect_image_format(data) {
            ImageFormat::Jpeg => Self::from_jpeg_bytes(data),
            ImageFormat::Png => {
                let cursor = std::io::Cursor::new(data);
                let decoder = png::Decoder::new(cursor);
                Self::try_from_png(decoder)
            }
            ImageFormat::Other => Self::from_generic_bytes(data),
        }
    }

    /// Build from a reader by buffering all bytes and calling [`from_bytes`].
    pub fn from_reader<R: Read>(mut reader: R) -> Result<(Self, Option<Self>), Error> {
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .map_err(|e| Error::Other(format!("Failed to read image: {}", e)))?;
        Self::from_bytes(&buf)
    }

    // ──────────────────────────────────────────────────────────────────────────
    // JPEG — embed as-is with DCTDecode
    // ──────────────────────────────────────────────────────────────────────────

    /// Embed a JPEG image directly without re-encoding.
    ///
    /// JPEG dimensions and colour type are parsed from the SOF marker so we
    /// do not need to fully decode the image.
    fn from_jpeg_bytes(data: &[u8]) -> Result<(Self, Option<Self>), Error> {
        let (width, height, components) = Self::parse_jpeg_dimensions(data)
            .ok_or_else(|| Error::Other("Could not parse JPEG dimensions".to_owned()))?;

        let color_space = match components {
            1 => ColorType::Grayscale,
            3 => ColorType::Rgb,
            // 4-component JPEGs are CMYK — treat as RGB for now (rare in practice)
            _ => ColorType::Rgb,
        };

        Ok((
            Self {
                width,
                height,
                color_space,
                bits_per_component: BitDepth::Eight,
                interpolate: false,
                image_data: data.to_vec(),
                is_jpeg: true,
                s_mask: None,
            },
            None, // JPEG does not carry an alpha channel
        ))
    }

    /// Minimal JPEG SOF (Start Of Frame) parser to extract width/height/components.
    fn parse_jpeg_dimensions(data: &[u8]) -> Option<(u32, u32, u8)> {
        let mut i = 0usize;
        // Skip SOI marker (FF D8)
        if data.len() < 2 || data[0] != 0xFF || data[1] != 0xD8 {
            return None;
        }
        i += 2;
        while i + 3 < data.len() {
            if data[i] != 0xFF {
                return None;
            }
            let marker = data[i + 1];
            i += 2;
            // SOF markers: C0..C3, C5..C7, C9..CB, CD..CF
            let is_sof = matches!(
                marker,
                0xC0 | 0xC1 | 0xC2 | 0xC3 | 0xC5 | 0xC6 | 0xC7 | 0xC9 | 0xCA | 0xCB | 0xCD
                    | 0xCE | 0xCF
            );
            // Markers without a length field
            if marker == 0xD8 || marker == 0xD9 {
                continue;
            }
            if i + 2 > data.len() {
                return None;
            }
            let length = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
            if is_sof && length >= 8 && i + length <= data.len() {
                // precision(1) + height(2) + width(2) + components(1)
                let height = u16::from_be_bytes([data[i + 3], data[i + 4]]) as u32;
                let width = u16::from_be_bytes([data[i + 5], data[i + 6]]) as u32;
                let components = data[i + 7];
                return Some((width, height, components));
            }
            i += length;
        }
        None
    }

    // ──────────────────────────────────────────────────────────────────────────
    // PNG — use the `png` crate directly (preserves alpha)
    // ──────────────────────────────────────────────────────────────────────────

    /// Decode a PNG image.  This is the original implementation, kept for
    /// correctness when the alpha channel must be split out.
    pub fn try_from_png<R: BufRead + Seek>(
        image_decoder: png::Decoder<R>,
    ) -> Result<(Self, Option<Self>), Error> {
        let mut image_reader = image_decoder
            .read_info()
            .map_err(|e| Error::Other(format!("PNG read_info: {}", e)))?;
        let mut buf = vec![0u8; image_reader.output_buffer_size().unwrap_or(0)];
        let info = image_reader
            .next_frame(&mut buf)
            .map_err(|e| Error::Other(format!("PNG next_frame: {}", e)))?;
        let image_data = Vec::from(&buf[..info.buffer_size()]);

        let mut color_type = info.color_type;
        let (image_color_data, alpha_data) = match info.color_type {
            ColorType::Rgba => {
                color_type = ColorType::Rgb;
                (
                    Self::rgba_to_rgb(&image_data),
                    Some(Self::rgba_to_a(&image_data)),
                )
            }
            ColorType::GrayscaleAlpha => {
                color_type = ColorType::Grayscale;
                (
                    Self::grayscale_alpha_to_grayscale(&image_data),
                    Some(Self::grayscale_alpha_to_a(&image_data)),
                )
            }
            _ => (image_data, None),
        };

        Ok((
            Self {
                width: info.width,
                height: info.height,
                color_space: color_type,
                bits_per_component: info.bit_depth,
                image_data: image_color_data,
                interpolate: false,
                is_jpeg: false,
                s_mask: None,
            },
            alpha_data.map(|a| Self {
                width: info.width,
                height: info.height,
                color_space: ColorType::Grayscale,
                bits_per_component: info.bit_depth,
                image_data: a,
                interpolate: false,
                is_jpeg: false,
                s_mask: None,
            }),
        ))
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Generic formats via the `image` crate (BMP, GIF, TIFF, WebP, …)
    // ──────────────────────────────────────────────────────────────────────────

    /// Decode any image format supported by the `image` crate into raw RGB(A)
    /// pixel data, then split the alpha channel the same way the PNG path does.
    fn from_generic_bytes(data: &[u8]) -> Result<(Self, Option<Self>), Error> {
        use image::DynamicImage;

        let img = image::load_from_memory(data)
            .map_err(|e| Error::Other(format!("Unsupported image format: {}", e)))?;

        let (width, height) = (img.width(), img.height());

        // Convert to the simplest lossless form: RGBA8 or Luma8
        let (color_space, image_color_data, alpha_data) = match &img {
            DynamicImage::ImageLuma8(_) => {
                let raw = img.to_luma8().into_raw();
                (ColorType::Grayscale, raw, None)
            }
            DynamicImage::ImageLumaA8(_) => {
                let la = img.to_luma_alpha8();
                let raw = la.as_raw();
                let gray: Vec<u8> = raw.chunks(2).map(|c| c[0]).collect();
                let alpha: Vec<u8> = raw.chunks(2).map(|c| c[1]).collect();
                (ColorType::Grayscale, gray, Some(alpha))
            }
            _ => {
                // Default: convert to RGBA8 then split
                let rgba = img.to_rgba8();
                let raw = rgba.as_raw();
                let rgb = Self::rgba_to_rgb(raw);
                let alpha = Self::rgba_to_a(raw);
                // Only include alpha mask when the image is not fully opaque
                let has_alpha = alpha.iter().any(|&a| a != 255);
                let alpha_opt = if has_alpha { Some(alpha) } else { None };
                (ColorType::Rgb, rgb, alpha_opt)
            }
        };

        Ok((
            Self {
                width,
                height,
                color_space,
                bits_per_component: BitDepth::Eight,
                interpolate: false,
                image_data: image_color_data,
                is_jpeg: false,
                s_mask: None,
            },
            alpha_data.map(|a| Self {
                width,
                height,
                color_space: ColorType::Grayscale,
                bits_per_component: BitDepth::Eight,
                image_data: a,
                interpolate: false,
                is_jpeg: false,
                s_mask: None,
            }),
        ))
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Channel-splitting helpers (8-bit only)
    // ──────────────────────────────────────────────────────────────────────────

    /// Extract RGB channels from interleaved RGBA data (8 bpc).
    fn rgba_to_rgb(data: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(data.len() / 4 * 3);
        for chunk in data.chunks(4) {
            output.extend_from_slice(&chunk[..3]);
        }
        output
    }

    /// Extract alpha channel from interleaved RGBA data (8 bpc).
    fn rgba_to_a(data: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(data.len() / 4);
        for chunk in data.chunks(4) {
            output.push(chunk[3]);
        }
        output
    }

    /// Extract grayscale channel from interleaved Grayscale+Alpha data (8 bpc).
    fn grayscale_alpha_to_grayscale(data: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(data.len() / 2);
        for chunk in data.chunks(2) {
            output.push(chunk[0]);
        }
        output
    }

    /// Extract alpha channel from interleaved Grayscale+Alpha data (8 bpc).
    fn grayscale_alpha_to_a(data: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(data.len() / 2);
        for chunk in data.chunks(2) {
            output.push(chunk[1]);
        }
        output
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Conversion to lopdf types
// ──────────────────────────────────────────────────────────────────────────────

// Inspired and derived from:
// https://github.com/fschutt/printpdf/blob/2bebdc65d06dafbe926ed4b43fedd10f966c59d3/src/xobject.rs#L245
impl From<ImageXObject> for lopdf::Stream {
    fn from(image: ImageXObject) -> Self {
        use lopdf::Object::*;

        let cs: &'static str = match image.color_space {
            ColorType::Rgb => "DeviceRGB",
            ColorType::Grayscale => "DeviceGray",
            ColorType::Indexed => "Indexed",
            ColorType::Rgba | ColorType::GrayscaleAlpha => "DeviceN",
        };

        let identity_matrix: Vec<f64> = vec![1.0, 0.0, 0.0, 1.0, 0.0, 0.0];
        let bbox: lopdf::Object = Array(
            identity_matrix
                .into_iter()
                .map(|a| Real(a as f32))
                .collect(),
        );

        let mut dict = lopdf::Dictionary::from_iter(vec![
            ("Type", Name("XObject".as_bytes().to_vec())),
            ("Subtype", Name("Image".as_bytes().to_vec())),
            ("Width", Integer(image.width as i64)),
            ("Height", Integer(image.height as i64)),
            ("Interpolate", image.interpolate.into()),
            ("BitsPerComponent", Integer(image.bits_per_component as i64)),
            ("ColorSpace", Name(cs.as_bytes().to_vec())),
            ("BBox", bbox),
            (
                "Resources",
                lopdf::Object::Dictionary(lopdf::Dictionary::new()),
            ),
        ]);

        // JPEG images are embedded as-is using the DCTDecode filter.
        if image.is_jpeg {
            dict.set("Filter", Name(b"DCTDecode".to_vec()));
        }

        if let Some(s_mask) = image.s_mask {
            dict.set("SMask", Reference(s_mask));
        }

        lopdf::Stream::new(dict, image.image_data)
    }
}

impl From<ImageXObject> for lopdf::Object {
    fn from(image: ImageXObject) -> Self {
        lopdf::Object::Stream(image.into())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ──────────────────────────────────────────────────────────────

    /// Build a minimal valid 1×1 white RGB PNG in-memory.
    fn make_png_1x1_rgb() -> Vec<u8> {
        use std::io::Cursor;
        let mut buf = Vec::new();
        {
            let mut encoder = png::Encoder::new(Cursor::new(&mut buf), 1, 1);
            encoder.set_color(png::ColorType::Rgb);
            encoder.set_depth(png::BitDepth::Eight);
            let mut writer = encoder.write_header().unwrap();
            writer.write_image_data(&[255u8, 255, 255]).unwrap();
        }
        buf
    }

    /// Build a minimal valid 2×2 RGBA PNG (semi-transparent red pixels).
    fn make_png_2x2_rgba() -> Vec<u8> {
        use std::io::Cursor;
        let mut buf = Vec::new();
        {
            let mut encoder = png::Encoder::new(Cursor::new(&mut buf), 2, 2);
            encoder.set_color(png::ColorType::Rgba);
            encoder.set_depth(png::BitDepth::Eight);
            let mut writer = encoder.write_header().unwrap();
            // 4 pixels × 4 channels: R=255, G=0, B=0, A=128
            writer
                .write_image_data(&[255, 0, 0, 128, 255, 0, 0, 128, 255, 0, 0, 128, 255, 0, 0, 128])
                .unwrap();
        }
        buf
    }

    /// Build the smallest valid JPEG (1×1 white pixel) without depending on an
    /// encoder: use a pre-computed minimal JFIF byte sequence.
    fn make_jpeg_1x1() -> Vec<u8> {
        // This is a valid 1×1 white JPEG generated offline and stored as bytes.
        vec![
            0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43, 0x00, 0x08, 0x06, 0x06,
            0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09, 0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D,
            0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12, 0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D,
            0x1A, 0x1C, 0x1C, 0x20, 0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28,
            0x37, 0x29, 0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27, 0x39, 0x3D, 0x38, 0x32,
            0x3C, 0x2E, 0x33, 0x34, 0x32, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01, 0x00, 0x01,
            0x01, 0x01, 0x11, 0x00, 0xFF, 0xC4, 0x00, 0x1F, 0x00, 0x00, 0x01, 0x05, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02,
            0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0xFF, 0xC4, 0x00, 0xB5, 0x10,
            0x00, 0x02, 0x01, 0x03, 0x03, 0x02, 0x04, 0x03, 0x05, 0x05, 0x04, 0x04, 0x00, 0x00,
            0x01, 0x7D, 0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06,
            0x13, 0x51, 0x61, 0x07, 0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xA1, 0x08, 0x23, 0x42,
            0xB1, 0xC1, 0x15, 0x52, 0xD1, 0xF0, 0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0A, 0x16,
            0x17, 0x18, 0x19, 0x1A, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3A, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x53, 0x54, 0x55,
            0x56, 0x57, 0x58, 0x59, 0x5A, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x73,
            0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
            0x8A, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6,
            0xA7, 0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xC2,
            0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
            0xD8, 0xD9, 0xDA, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xF1,
            0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFF, 0xDA, 0x00, 0x08, 0x01,
            0x01, 0x00, 0x00, 0x3F, 0x00, 0xFB, 0xD3, 0xFF, 0xD9,
        ]
    }

    /// Build a minimal 1×1 BMP (white pixel) via the `image` crate.
    fn make_bmp_1x1() -> Vec<u8> {
        use image::{ImageBuffer, Rgb};
        let img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::from_pixel(1, 1, Rgb([255u8, 255, 255]));
        let mut buf = Vec::new();
        img.write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::Bmp)
            .unwrap();
        buf
    }

    // ── detect_image_format ───────────────────────────────────────────────────

    #[test]
    fn test_detect_jpeg() {
        let data = make_jpeg_1x1();
        assert_eq!(detect_image_format(&data), ImageFormat::Jpeg);
    }

    #[test]
    fn test_detect_png() {
        let data = make_png_1x1_rgb();
        assert_eq!(detect_image_format(&data), ImageFormat::Png);
    }

    #[test]
    fn test_detect_bmp() {
        let data = make_bmp_1x1();
        // BMP magic bytes are 0x42 0x4D ('BM'), not JPEG or PNG
        assert_eq!(detect_image_format(&data), ImageFormat::Other);
    }

    #[test]
    fn test_detect_empty_is_other() {
        assert_eq!(detect_image_format(&[]), ImageFormat::Other);
    }

    // ── JPEG loading ─────────────────────────────────────────────────────────

    #[test]
    fn test_from_bytes_jpeg_is_embedded_as_is() {
        let data = make_jpeg_1x1();
        let (img, mask) = ImageXObject::from_bytes(&data).expect("JPEG load failed");
        assert!(img.is_jpeg, "JPEG image should have is_jpeg=true");
        assert_eq!(img.image_data, data, "JPEG bytes must be stored verbatim");
        assert!(mask.is_none(), "JPEG should have no alpha mask");
        assert_eq!(img.width, 1);
        assert_eq!(img.height, 1);
        assert_eq!(img.bits_per_component, BitDepth::Eight);
    }

    #[test]
    fn test_jpeg_stream_has_dctdecode_filter() {
        let data = make_jpeg_1x1();
        let (img, _) = ImageXObject::from_bytes(&data).expect("JPEG load failed");
        let stream: lopdf::Stream = img.into();
        let filter = stream.dict.get(b"Filter").expect("Filter key missing");
        assert_eq!(
            filter.as_name().unwrap(),
            b"DCTDecode",
            "JPEG stream must use DCTDecode filter"
        );
    }

    // ── PNG loading ───────────────────────────────────────────────────────────

    #[test]
    fn test_from_bytes_png_rgb() {
        let data = make_png_1x1_rgb();
        let (img, mask) = ImageXObject::from_bytes(&data).expect("PNG RGB load failed");
        assert!(!img.is_jpeg);
        assert_eq!(img.width, 1);
        assert_eq!(img.height, 1);
        assert_eq!(img.color_space, ColorType::Rgb);
        assert_eq!(img.image_data, vec![255u8, 255, 255]);
        assert!(mask.is_none(), "Opaque RGB PNG should have no mask");
    }

    #[test]
    fn test_from_bytes_png_rgba_splits_alpha() {
        let data = make_png_2x2_rgba();
        let (img, mask) = ImageXObject::from_bytes(&data).expect("PNG RGBA load failed");
        assert!(!img.is_jpeg);
        assert_eq!(img.color_space, ColorType::Rgb, "color should be Rgb after split");
        assert!(mask.is_some(), "RGBA PNG must produce a soft-mask image");
        let mask = mask.unwrap();
        assert_eq!(mask.color_space, ColorType::Grayscale);
        // 4 pixels × alpha = 128
        assert_eq!(mask.image_data, vec![128u8; 4]);
        // RGB data: 4 pixels × 3 channels
        assert_eq!(img.image_data.len(), 12);
    }

    #[test]
    fn test_png_stream_has_no_filter_key() {
        let data = make_png_1x1_rgb();
        let (img, _) = ImageXObject::from_bytes(&data).expect("PNG load failed");
        let stream: lopdf::Stream = img.into();
        assert!(
            stream.dict.get(b"Filter").is_err(),
            "Non-JPEG stream must NOT have a Filter key"
        );
    }

    // ── Generic (BMP via `image` crate) ──────────────────────────────────────

    #[test]
    fn test_from_bytes_bmp_via_image_crate() {
        let data = make_bmp_1x1();
        let (img, _mask) = ImageXObject::from_bytes(&data).expect("BMP load failed");
        assert!(!img.is_jpeg);
        assert_eq!(img.width, 1);
        assert_eq!(img.height, 1);
        assert_eq!(img.bits_per_component, BitDepth::Eight);
    }

    // ── from_reader ───────────────────────────────────────────────────────────

    #[test]
    fn test_from_reader_png() {
        let data = make_png_1x1_rgb();
        let cursor = std::io::Cursor::new(&data);
        let (img, _) = ImageXObject::from_reader(cursor).expect("from_reader PNG failed");
        assert_eq!(img.width, 1);
        assert_eq!(img.height, 1);
    }

    #[test]
    fn test_from_reader_jpeg() {
        let data = make_jpeg_1x1();
        let cursor = std::io::Cursor::new(&data);
        let (img, _) = ImageXObject::from_reader(cursor).expect("from_reader JPEG failed");
        assert!(img.is_jpeg);
    }

    // ── parse_jpeg_dimensions ────────────────────────────────────────────────

    #[test]
    fn test_parse_jpeg_dimensions_1x1() {
        let data = make_jpeg_1x1();
        let dims = ImageXObject::parse_jpeg_dimensions(&data);
        assert!(dims.is_some(), "Dimensions must be parseable");
        let (w, h, _) = dims.unwrap();
        assert_eq!(w, 1);
        assert_eq!(h, 1);
    }

    #[test]
    fn test_parse_jpeg_dimensions_invalid_returns_none() {
        let bogus = vec![0x00u8; 32];
        assert!(ImageXObject::parse_jpeg_dimensions(&bogus).is_none());
    }

    // ── lopdf Stream dict keys ────────────────────────────────────────────────

    #[test]
    fn test_stream_dict_contains_required_keys() {
        let data = make_png_1x1_rgb();
        let (img, _) = ImageXObject::from_bytes(&data).unwrap();
        let stream: lopdf::Stream = img.into();
        assert!(stream.dict.get(b"Width").is_ok());
        assert!(stream.dict.get(b"Height").is_ok());
        assert!(stream.dict.get(b"ColorSpace").is_ok());
        assert!(stream.dict.get(b"BitsPerComponent").is_ok());
        assert!(stream.dict.get(b"Subtype").is_ok());
    }

    // ── channel splitting helpers ─────────────────────────────────────────────

    #[test]
    fn test_rgba_to_rgb_strips_alpha() {
        // 2 pixels: (R=1,G=2,B=3,A=4) and (R=5,G=6,B=7,A=8)
        let rgba = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let rgb = ImageXObject::rgba_to_rgb(&rgba);
        assert_eq!(rgb, vec![1, 2, 3, 5, 6, 7]);
    }

    #[test]
    fn test_rgba_to_a_extracts_alpha() {
        let rgba = vec![1u8, 2, 3, 99, 5, 6, 7, 200];
        let alpha = ImageXObject::rgba_to_a(&rgba);
        assert_eq!(alpha, vec![99, 200]);
    }

    #[test]
    fn test_grayscale_alpha_to_grayscale() {
        let ga = vec![50u8, 100, 75, 200];
        let g = ImageXObject::grayscale_alpha_to_grayscale(&ga);
        assert_eq!(g, vec![50, 75]);
    }

    #[test]
    fn test_grayscale_alpha_to_a() {
        let ga = vec![50u8, 100, 75, 200];
        let a = ImageXObject::grayscale_alpha_to_a(&ga);
        assert_eq!(a, vec![100, 200]);
    }

    // ── real asset files (if present) ────────────────────────────────────────

    #[test]
    fn test_real_sig1_png_loads() {
        let path = "examples/assets/sig1.png";
        if !std::path::Path::new(path).exists() {
            return; // skip if asset not present
        }
        let data = std::fs::read(path).unwrap();
        let result = ImageXObject::from_bytes(&data);
        assert!(result.is_ok(), "sig1.png should load without error: {:?}", result.err());
        let (img, _) = result.unwrap();
        assert!(!img.is_jpeg);
        assert!(img.width > 0 && img.height > 0);
    }

    #[test]
    fn test_real_jpeg_asset_loads() {
        let path = "examples/assets/ac477f73-0fad-4ed7-826f-f207a0362e48.jpeg";
        if !std::path::Path::new(path).exists() {
            return; // skip if asset not present
        }
        let data = std::fs::read(path).unwrap();
        let result = ImageXObject::from_bytes(&data);
        assert!(result.is_ok(), "JPEG asset should load without error: {:?}", result.err());
        let (img, mask) = result.unwrap();
        assert!(img.is_jpeg, "JPEG asset should be detected as JPEG");
        assert!(img.width > 0 && img.height > 0);
        assert!(mask.is_none(), "JPEG should have no alpha mask");
    }
}

