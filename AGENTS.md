# PDF Reference Resolution — Robustness Improvements

## Problem

PDF specifications (ISO 32000-1) allow certain dictionary entries to be either
**indirect references** (e.g. `12 0 R`) or **inline (direct) dictionaries**.
Many PDF producers emit inline dictionaries for entries like `/AcroForm`,
`/Pages`, and `/V` (signature value dictionary).

The codebase used `.as_reference()` with hard `?` propagation in several places,
assuming these entries are always indirect references. This caused the error:

```
object has wrong type; expected type Reference but found type Dictionary
```

## Fix Pattern

Use `PdfObjectDeref::deref()` (from `src/pdf_object.rs`) instead of
chaining `.as_reference()?` + `.get_object()?.as_dict()?`:

```rust
// Before (brittle — assumes Reference):
let root_ref = doc.trailer.get(b"Root")?.as_reference()?;
let root_dict = doc.get_object(root_ref)?.as_dict()?;

// After (robust — handles both Reference and inline Dictionary):
let root_dict = doc.trailer.get(b"Root")?.deref(doc)?.as_dict()?;
```

The `deref()` method resolves indirect references automatically and passes
through inline objects unchanged.

## Files Fixed

| File | Lines | Entries |
|------|-------|---------|
| `src/signature_validator.rs` | 380–387 | `Root`, `AcroForm` |
| `src/signature_validator.rs` | 416–457 | `V` (inline dict) |
| `src/bin/inspect_pdf.rs` | 10–16, 44 | `Root`, `AcroForm`, `V` |
| `src/bin/verify_pades.rs` | 52–54, 87 | `Root`, `AcroForm`, `V` |
| `src/digitally_sign.rs` | 332–355 | `Root`, `AcroForm` |
| `src/lib.rs` | 289–292 | `Root`, `AcroForm` |
| `src/signature_info.rs` | 22–23 | `Root` |
| `src/signature_placeholder.rs` | 43–45 | `Root`, `Pages` |

## Build & Test

```bash
cargo build
cargo run --example verify_pdf "/path/to/document.pdf"
cargo run --bin inspect_pdf "/path/to/document.pdf"
```

---

# CMS Signing Time Detection

## Problem

The `verify_pdf` tool displayed the PDF `/M` metadata field for signing time,
but did not differentiate between PDF metadata (alterable) and the
cryptographically protected CMS `id-signingTime` signed attribute.

## Feature: `cms_has_signing_time`

A new `bool` field on `ValidationResult` (in `signature_validator.rs`) that is
`true` when the CMS `SignedData` contains the `id-signingTime` OID
(`1.2.840.113549.1.9.5`) in its signed attributes.

## Feature: `cms_timestamp_value`

An `Option<String>` field on `ValidationResult` that contains the raw
`genTime` value from the TSTInfo inside the RFC 3161 timestamp token
(`id-smime-aa-signatureTimeStampToken` unsigned attribute). `None` when no
timestamp token is present or the time cannot be extracted.

### Detection Method

Uses the same DER pattern-matching approach as `check_cms_timestamp`:

```rust
fn check_cms_signing_time(cms_der: &[u8]) -> bool {
    let oid: &[u8] = &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05];
    cms_der.windows(oid.len()).any(|w| w == oid)
}
```

Timestamp value extraction finds the timestamp OID in the CMS DER then scans
forward for the first `GeneralizedTime` (tag `0x18`):

```rust
fn extract_cms_timestamp_time(cms_der: &[u8]) -> Option<String> {
    // ... finds OID 1.2.840.113549.1.9.16.2.14
    // ... scans forward for tag 0x18, extracts the time string
}
```

### Files modified

| File | What |
|------|------|
| `src/signature_validator.rs` | Added `cms_has_signing_time` field + `check_cms_signing_time()` method + `cms_timestamp_value` field + `extract_cms_timestamp_time()` method |
| `examples/verify_pdf.rs` | Added display + JSON fields for both `cms_has_signing_time` and `cms_timestamp_value` |

---

# ROADMAP: Password-Protected Digital Signatures (TTE Encrypted PDF)

## Feature Overview
Implement the ability to digitally sign PDFs that are password-protected (encrypted), as well as the ability to assign a password (protect) an unencrypted PDF at the exact moment of signing.

## The Challenge (PDF Security vs Signing)
According to ISO 32000, PDF Encryption (`/Encrypt`) affects streams and strings globally, **BUT** the digital signature dictionary (specifically the `/Contents` field holding the CMS PKCS#7 hex string) **MUST NOT** be encrypted. Otherwise, validators cannot read the signature without the password.

Currently, `rust_pdf_signing` relies on `lopdf` `0.39` which has basic decryption but **lacks flexible stream-level encryption bypass mechanisms** needed for signature injection.

## Implementation Plan (Opsi A: Pure Rust / Local Leverage)

### 1. Module Extension: `crypto`
Instead of rewriting complex AES/RC4 logic, we will adapt the modern cryptographic handlers recently built in the local `rust-pdfbox` project (`src/crypto/handlers.rs`).
- Implement RC4 and AES-128 / AES-256 (Revision 5/6) encryption routines.
- Port these into a new `src/encryption.rs` module in `rust_pdf_signing`.

### 2. Skenario A: Signing an Already Encrypted PDF
When the input PDF has an existing `/Encrypt` dictionary:
1. **Decrypt (Load):** Use `lopdf::Document::decrypt(password)` to read the structure.
2. **Inject Signature:** Create the `/V` signature field and placeholder.
3. **Re-Encrypt (Save):** Modify the `lopdf::Document::save_to` byte-writer. Apply the original AES/RC4 cipher to all objects **EXCEPT** the object ID representing the Signature Value (`/Contents`).

### 3. Skenario B: Adding a Password While Signing
When the input PDF is unprotected but needs protection upon signing, the process **MUST** follow the ISO 32000-1 Incremental Update specification for encrypted files.

**CRITICAL ARCHITECTURAL DECISION:**
The `rust_pdf_signing` library (built on `lopdf`) **lacks the architectural capability** to properly serialize an encrypted PDF and then cleanly append an Incremental Update (TTE) without corrupting the ByteRange hash or the `xref` table. In-memory bypass hacks lead to Adobe Acrobat rejecting the signature due to `/Contents` corruption or byte offset mismatches.

**Solution:** **Migrate the Password-Protected TTE feature to `rust-pdfbox`!**
The local `rust-pdfbox` library is vastly superior for this task because:
1. It has full support for Advanced Cryptography (RC4, AES-128, AES-256 Rev 6).
2. It natively understands Document Decryption (can load a password-protected PDF).
3. It supports standard Java-like Save Pipelines for clean Incremental Updates.

#### The `rust-pdfbox` Workflow Plan:
1. **Phase 1 (Encryption):** Load the plaintext PDF using `rust-pdfbox`. Apply the `StandardSecurityHandler` (e.g., Owner/User password `admin123`). Serialize and save the encrypted PDF to a buffer. (The document is now legitimately locked).
2. **Phase 2 (Decryption & Signing):** Load the encrypted buffer back into `rust-pdfbox`, passing the `admin123` password to unlock the parser. 
3. **Phase 3 (Incremental Update):** Use `rust-pdfbox`'s native `sign_pdf` functionality to append the `/AcroForm` signature field and inject the CMS PKCS#7 hash. Save the result as an **Incremental Update** (appending new objects to the end of the file without touching the encrypted byte stream).

This guarantees 100% Adobe/Foxit compatibility, as the TTE Hex String is appended cleanly and the ByteRange remains mathematically accurate.

### Action Items for Next Sprint
- [x] Port `rust-pdfbox` encryption logic to `rust_pdf_signing` (Achieved via `cargo add rust-pdfbox --path ...`).
- [x] Override `lopdf`'s object serialization loop (Achieved via Custom Serializer Bypass - Proof of Concept).
- [x] Write implementation Proof of Concept (`sign_password.rs`).
- [x] **Feasibility Study Completed:** Concluded that `lopdf` writer architecture blocks Adobe-compliant Encrypted TTE.
- [ ] **NEXT:** Transition the Password-TTE implementation fully to the `rust-pdfbox` repository.
- [ ] **NEXT:** Implement Phase 1 (Encrypt & Save) in `rust-pdfbox`.
- [ ] **NEXT:** Implement Phase 2 (Load Encrypted & Sign via Incremental Update) in `rust-pdfbox`.
- [ ] Refactor `digitally_sign.rs` to inherently compute and bypass Signature Object IDs before writing ByteRange gap.
- [ ] Implement robust `EncryptionState` integration inside the native `rust_pdf_signing` library struct API for full CMS certificate payload insertion.