# PDF Signing

[![Crates.io](https://img.shields.io/crates/v/pdf_signing)](https://crates.io/crates/pdf_signing/)
[![API Docs](https://img.shields.io/badge/docs.rs-pdf_signing-blue)](https://docs.rs/pdf_signing/latest/)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](LICENSE-MIT)

A Rust library for digitally signing PDF documents with support for **PKCS#7** and **PAdES** (B-B, B-T, B-LT, B-LTA) signature formats, **signature validation**, **modification detection**, and **certificate trust verification**.

Built on top of [`lopdf`][lopdf] for PDF manipulation and [`cryptographic-message-syntax`][cms] for CMS/PKCS#7 operations.

## Features

- **Digital Signing** — Sign PDF documents using X.509 certificates (PEM or PKCS#12)
- **Signature Formats**
  - `adbe.pkcs7.detached` — Legacy PKCS#7 signatures (Adobe compatible)
  - `ETSI.CAdES.detached` — PAdES signatures (ETSI EN 319 142)
- **PAdES Conformance Levels**
  - **B-B** — Basic: ESS signing-certificate-v2 attribute
  - **B-T** — Timestamp: Adds RFC 3161 signature timestamp from a TSA
  - **B-LT** — Long-Term: Adds DSS dictionary with CRL/OCSP/certificate data
  - **B-LTA** — Long-Term Archival: Adds document-level timestamp on top of B-LT
- **Visible & Invisible Signatures** — Embed signature images (PNG) at a specified page/position, or sign invisibly
- **Multi-Signature Support** — Apply multiple signatures via incremental updates (each signer gets their own revision)
- **Encrypted PDF Support** — Verify signatures in password-protected PDFs (user password and owner-only permission restrictions)
- **Signature Validation**
  - CMS/PKCS#7 envelope integrity verification
  - SHA-256 digest verification against ByteRange
  - Certificate chain structural validation
  - **Certificate trust verification** — Warns when signers use self-signed or unrecognized CA certificates (similar to Adobe Reader)
  - **Modification detection** — Detects unauthorized changes after signing (content tampering, object deletion) while allowing permitted changes (new signatures, DSS, annotations)
  - LTV (Long-Term Validation) status checking
  - Document timestamp (RFC 3161) verification
- **Security Attack Defenses** ([pdf-insecurity.org](https://pdf-insecurity.org))
  - **USF** (Universal Signature Forgery) — ByteRange structural validation
  - **SWA** (Signature Wrapping Attack) — Contents hex-string location cross-check
  - **ISA** (Incremental Saving Attack) — Revision comparison with change classification
  - **Shadow Attack** — Content reference swap, OCG visibility, and page tree detection
  - **EAA** (Evil Annotation Attack) — Dangerous annotation type filtering
  - **Certification Attack** — MDP permission level enforcement
- **DSS (Document Security Store)** — Embeds CRL, OCSP responses, and CA certificates at the document level for offline validation
- **LTV Support** — Embeds revocation data for long-term signature verification

## Quick Start

### Signing a PDF

```rust
use pdf_signing::{PDFSigningDocument, SignatureOptions, UserSignatureInfo, Rectangle};
use pdf_signing::signature_options::SignatureFormat;

// Load certificate and key
let cert_pem = std::fs::read("cert-chain.pem").unwrap();
let key_pem = std::fs::read("private-key.pem").unwrap();

// Configure signature
let sig_options = SignatureOptions {
    format: SignatureFormat::PADES,
    pades_level: Some(pdf_signing::signature_options::PadesLevel::B_T),
    ..Default::default()
};

let user_info = UserSignatureInfo {
    signer_name: "Alice".into(),
    reason: "Approval".into(),
    ..Default::default()
};
```

### Validating a Signed PDF

```rust
use pdf_signing::signature_validator::{SignatureValidator, ValidationResult};

let pdf_bytes = std::fs::read("signed.pdf").unwrap();
let results = SignatureValidator::validate(&pdf_bytes).unwrap();

for r in &results {
    println!("Signer: {:?}", r.signer_name);
    println!("  CMS valid:      {}", r.cms_signature_valid);
    println!("  Digest match:   {}", r.digest_match);
    println!("  Chain trusted:  {}", r.certificate_chain_trusted);
    println!("  No tampering:   {}", r.no_unauthorized_modifications);
    println!("  LTV enabled:    {}", r.is_ltv_enabled);
    println!("  Encrypted:      {}", r.is_encrypted);
    println!("  Overall valid:  {}", r.is_valid());
}

// For password-protected PDFs:
let results = SignatureValidator::validate_with_password(
    &pdf_bytes,
    Some(b"mypassword"),
).unwrap();
```

## CLI Examples

### Sign a Document

```bash
cargo run --example sign_doc -- input.pdf [options]
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output <path>` | Output file path | `<input>-signed.pdf` |
| `-c, --cert <path>` | Certificate chain PEM | `examples/assets/keystore-local-chain.pem` |
| `-k, --key <path>` | Private key PEM | `examples/assets/keystore-local-key.pem` |
| `-i, --image <path>` | Signature image (PNG) | `examples/assets/sig1.png` |
| `-f, --format <pkcs7\|pades>` | Signature format | `pades` |
| `-l, --level <b-b\|b-t\|b-lt\|b-lta>` | PAdES conformance level | `b-t` |
| `-p, --page <num>` | Page number (1-based) | `1` |
| `-r, --rect <x1,y1,x2,y2>` | Signature rectangle | `50,50,250,100` |
| `--invisible` | Invisible signature (no image) | — |
| `--name <name>` | Signer name | `Signer` |
| `--reason <text>` | Signing reason | `Digital Signature` |
| `--dss` | Include DSS dictionary | — |
| `--crl` / `--no-crl` | Include/exclude CRL in CMS | auto |
| `--ocsp` | Include OCSP in CMS | — |

**Examples:**

```bash
# PAdES B-T with visible signature
cargo run --example sign_doc -- document.pdf -f pades -l b-t

# PAdES B-LTA with invisible signature
cargo run --example sign_doc -- document.pdf -f pades -l b-lta --invisible

# PKCS#7 with custom signer name
cargo run --example sign_doc -- document.pdf -f pkcs7 --name "Alice" --invisible

# Custom certificate and output path
cargo run --example sign_doc -- document.pdf -c my-cert.pem -k my-key.pem -o signed.pdf

# Multi-signature (sign the output of a previous signing)
cargo run --example sign_doc -- document.pdf -o first.pdf --name Alice --invisible
cargo run --example sign_doc -- first.pdf -o second.pdf --name Bob --invisible
```

### Verify a Signed PDF

```bash
cargo run --example verify_pdf -- signed.pdf
```

**Options:**

| Option | Description |
|--------|-------------|
| `--json, -j` | Output results in JSON format |
| `--password, -P <pass>` | Password for encrypted/protected PDFs |
| `--help, -h` | Show help |

**Password-protected PDFs:**

```bash
# Verify encrypted PDF with user password
cargo run --example verify_pdf -- encrypted-signed.pdf --password mysecret

# JSON output with password
cargo run --example verify_pdf -- encrypted-signed.pdf -P mysecret --json

# Owner-only encrypted PDFs (permission restrictions only) are auto-decrypted
cargo run --example verify_pdf -- owner-protected.pdf
```

> **Note:** PDFs with only an owner password (permission restrictions, no user password) are automatically decrypted without requiring `--password`. Only PDFs with a user password need the `--password` flag.

The verifier checks and reports:

- ✅ CMS signature integrity
- ✅ SHA-256 digest match against ByteRange
- ✅ Certificate chain validity and **trust status** (warns for self-signed / unknown CA)
- ✅ Unauthorized modification detection (like Adobe Reader)
- ✅ LTV status (DSS, CRL, OCSP, timestamps)
- ✅ Document timestamp verification (RFC 3161)
- 🛡️ **Security attack detection** (USF, SWA, ISA, Shadow, EAA, Certification attacks)

**Example output:**

```
══════════════════════════════════════════════
  Verifying: result_pades_blta.pdf
══════════════════════════════════════════════

  Found 2 signature(s)

─────────────────────────────────────────────
Signature #1: ✅ VALID (Digital Signature)
─────────────────────────────────────────────
  SubFilter:          ETSI.CAdES.detached — PAdES (CAdES-based, ETSI standard)
  Signer:             Signer
  Digest match:       yes ✅
  CMS signature:      valid ✅
  Certificate chain:  valid ✅
  Chain trusted:      NOT TRUSTED ⚠️  — signer identity cannot be verified
    ⚠️  Root CA 'CN=test-ca' is self-signed but not recognized
  Modification check: no unauthorized changes ✅
  LTV enabled:        YES ✅

─────────────────────────────────────────────
Signature #2: ✅ VALID (Document Timestamp)
─────────────────────────────────────────────
  SubFilter:          ETSI.RFC3161 — RFC 3161 Document Timestamp
  Certificate chain:  valid ✅
  Chain trusted:      yes — signed by a recognized Certificate Authority ✅

══════════════════════════════════════════════
  SUMMARY
══════════════════════════════════════════════
  Total signatures:   2
  All CMS valid:      yes ✅
  All digests match:  yes ✅
  All chains trusted: NO ⚠️  (one or more signers not from a recognized CA)
  Overall:            ✅ ALL SIGNATURES VALID
```

### Verify PAdES Conformance

```bash
cargo run --bin verify_pades -- signed.pdf
```

Inspects CMS signed attributes to verify PAdES-specific requirements (ESS signing-certificate-v2, content type, timestamp tokens).

### Inspect PDF Structure

```bash
cargo run --bin inspect_pdf -- signed.pdf
```

## Signature Validation Details

### Modification Detection

The validator performs Adobe-like modification detection by comparing PDF revisions:

| Change Type | Status |
|-------------|--------|
| New signature fields & widgets | ✅ Permitted |
| AcroForm `/Fields` extended | ✅ Permitted |
| Page `/Annots` extended | ✅ Permitted |
| DSS dictionary added/updated | ✅ Permitted |
| Catalog `/DSS`, `/Perms` added | ✅ Permitted |
| Signature appearance XObjects | ✅ Permitted |
| Page content streams modified | ❌ Unauthorized |
| Form field values changed | ❌ Unauthorized |
| Objects deleted | ❌ Unauthorized |
| Fonts/images/resources modified | ❌ Unauthorized |

### Certificate Trust

The validator distinguishes between **chain validity** (structural consistency) and **chain trust** (recognized CA):

- **`certificate_chain_valid`** — The chain is internally consistent (issuer linkage) and no certs are expired. This affects `is_valid()`.
- **`certificate_chain_trusted`** — The root CA is a recognized public Certificate Authority. This is a **warning only** — it does NOT affect `is_valid()`, matching Adobe Reader's behavior.
- **`chain_warnings`** — Detailed messages about trust issues (self-signed root, unknown issuer, etc.)

Recognized root CAs include DigiCert, GlobalSign, Let's Encrypt, Comodo/Sectigo, Entrust, Google Trust Services, Amazon, and many others.

### Security Attack Defenses (pdf-insecurity.org)

The validator includes defenses against all six known PDF signature attack classes documented by researchers at [pdf-insecurity.org](https://pdf-insecurity.org):

#### 1. Universal Signature Forgery (USF)

**Attack**: Manipulates ByteRange values to make the signature cover different data than what's displayed.

**Defense** (`byte_range_valid`):
- ByteRange must start at offset 0 (covers file beginning)
- All values must be non-negative
- No overlapping ranges
- Gap between ranges must contain only a valid hex-encoded Contents string (`<hex...>`)
- Ranges must not exceed file size
- First range must be reasonably sized (not suspiciously short)

#### 2. Signature Wrapping Attack (SWA)

**Attack**: Moves the original signature to a different location and inserts a forged signature at the expected offset.

**Defense** (`signature_not_wrapped`):
- Verifies `/Contents<` pattern appears immediately before the ByteRange gap
- Detects suspicious duplication of large `/Contents<hex>` strings in the file

#### 3. Incremental Saving Attack (ISA)

**Attack**: Appends malicious incremental updates after signing that change visible content.

**Defense** (`no_unauthorized_modifications`):
- Compares PDF object state between each signature's revision and the final document
- Classifies every new, modified, and deleted object
- Detects content stream replacement (`[ISA]` tag)
- Detects form field value changes on non-signature fields (`[ISA]` tag)
- Only permits: new signature fields, DSS/VRI data, AcroForm field list extensions, page annotation extensions

#### 4. Shadow Attack

**Attack**: Prepares hidden content that gets revealed after signing (hide, replace, or hide-and-replace variants).

**Defense** (tagged `[Shadow]` in modification notes):
- Detects `/Contents` reference changes on pages (content stream swap)
- Detects `/OCProperties` changes (optional content group visibility manipulation)
- Detects `/Pages` tree modifications (page reordering/swapping)
- Detects `/MediaBox`/`/CropBox` changes (page dimension manipulation)
- Flags new image XObjects added after signing
- Flags new content streams with `/Resources`/`/BBox` (overlay content)
- Flags new object streams (`/ObjStm`) that could hide shadow content

#### 5. Evil Annotation Attack (EAA)

**Attack**: Adds annotations after signing that overlay or obscure original content.

**Defense** (tagged `[EAA]` in modification notes):
- Only permits `/Subtype /Widget` annotations (signature field widgets)
- Explicitly rejects dangerous annotation types: `FreeText`, `Stamp`, `Redact`, `Watermark`, `Square`, `Circle`, `Line`, `Ink`, `FileAttachment`, `RichMedia`, `Screen`, `3D`, `Sound`, `Movie`, `Text`, `Highlight`, `Underline`, `StrikeOut`, and others
- Detects non-append-only `/Annots` modifications (existing annotations changed/removed)

#### 6. PDF Certification Attack

**Attack**: Exploits certified documents (MDP level) to bypass permission restrictions.

**Defense** (`certification_permission_ok`):
- Reads `/Perms` → `/DocMDP` from the catalog
- Extracts MDP permission level from `/TransformParams`/`/P`
- Enforces restrictions based on level:
  - **Level 1**: No changes allowed — any modification is a violation
  - **Level 2**: Only form fill-in and signing — rejects content/annotation changes
  - **Level 3**: Form fill-in, signing, and annotations — rejects content changes

#### Security fields in `ValidationResult`

| Field | Type | Description |
|-------|------|-------------|
| `byte_range_valid` | `bool` | ByteRange structure is valid (USF defense) |
| `signature_not_wrapped` | `bool` | Signature not relocated (SWA defense) |
| `no_unauthorized_modifications` | `bool` | No unauthorized changes (ISA/Shadow/EAA defense) |
| `certification_level` | `Option<u8>` | MDP level if document is certified |
| `certification_permission_ok` | `bool` | MDP permissions respected |
| `security_warnings` | `Vec<String>` | Detailed security warnings |

All security checks affect `is_valid()` — a signature is considered invalid if any attack indicator is triggered.

## PAdES Conformance Levels

| Level | Description | What's Added |
|-------|-------------|--------------|
| **B-B** | Basic | ESS signing-certificate-v2 signed attribute |
| **B-T** | Timestamp | + RFC 3161 signature timestamp from TSA |
| **B-LT** | Long-Term | + DSS dictionary with CRL/OCSP/certificates |
| **B-LTA** | Long-Term Archival | + Document-level timestamp (4th incremental revision) |

B-LTA produces a 4-revision PDF:
1. Original document
2. Digital signature (CAdES)
3. DSS dictionary (revocation data + certificates)
4. Document timestamp (RFC 3161)

## Project Structure

```
src/
├── lib.rs                   # Public API and PDFSigningDocument
├── digitally_sign.rs        # Core signing logic (PKCS#7, PAdES, B-LTA)
├── signature_validator.rs   # Signature verification, trust, modification detection
├── signature_placeholder.rs # Signature field and placeholder creation
├── signature_options.rs     # SignatureOptions, SignatureFormat, PadesLevel
├── user_signature_info.rs   # UserSignatureInfo configuration
├── ltv.rs                   # LTV support (DSS, CRL, OCSP, timestamps)
├── acro_form.rs             # AcroForm manipulation
├── byte_range.rs            # ByteRange calculation
├── image_insert.rs          # Image embedding into PDF
├── image_xobject.rs         # Image XObject creation
├── signature_image.rs       # Signature appearance generation
├── rectangle.rs             # Rectangle type for positioning
├── error.rs                 # Error types
├── bin/
│   ├── verify_pades.rs      # PAdES conformance checker CLI
│   └── inspect_pdf.rs       # PDF structure inspector CLI
examples/
├── sign_doc.rs              # Full-featured signing CLI
├── verify_pdf.rs            # Signature verification CLI
└── assets/                  # Test certificates, keys, sample PDFs, signature images
```

## Creating Test Certificates

See [`Create_Cert.md`](Create_Cert.md) for instructions on creating self-signed certificates for testing.

Alternatively, use the **DSS PKI Factory** to generate test certificates with a full CA chain, CRL/OCSP endpoints, and LTV support — see [`DSS_PKI_Factory.md`](DSS_PKI_Factory.md).

Quick command:

```bash
openssl req \
  -newkey rsa:4096 -x509 -sha256 \
  -days 365 -nodes \
  -out cert.crt -keyout key.pem \
  -addext extendedKeyUsage=1.3.6.1.4.1.311.80.1,1.2.840.113583.1.1.5 \
  -addext keyUsage=digitalSignature,keyAgreement
```

## Running Tests

```bash
cargo test
```

The test suite includes:
- Signature placeholder creation and insertion
- Digital signature validation (CMS integrity, digest match)
- Certificate chain trust warning verification
- Modification detection (legitimate changes vs. tampering)
- PAdES conformance validation
- **Security attack defenses** (USF ByteRange validation, SWA detection, ISA content stream tampering, EAA annotation filtering)
- **Encrypted PDF verification** (correct password, wrong password, no password, owner-only auto-decrypt)

## Dependencies

| Crate | Purpose |
|-------|---------|
| [`lopdf`][lopdf] | PDF parsing and incremental updates |
| [`cryptographic-message-syntax`][cms] | CMS/PKCS#7 SignedData creation and parsing |
| [`x509-certificate`](https://crates.io/crates/x509-certificate) | X.509 certificate handling |
| [`x509-parser`](https://crates.io/crates/x509-parser) | Certificate metadata extraction |
| [`sha2`](https://crates.io/crates/sha2) | SHA-256 digest computation |
| [`reqwest`](https://crates.io/crates/reqwest) | HTTP client for TSA/CRL/OCSP |
| [`chrono`](https://crates.io/crates/chrono) | Date/time handling |
| [`png`](https://crates.io/crates/png) | PNG image decoding for signature images |

## License

Licensed under either of:

- **MIT License** ([LICENSE-MIT](LICENSE-MIT))
- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

All contributions, code and documentation, to this project will be similarly licensed.

[lopdf]: https://github.com/J-F-Liu/lopdf
[cms]: https://crates.io/crates/cryptographic-message-syntax

