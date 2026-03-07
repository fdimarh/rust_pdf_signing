# Development Journey — `rust_pdf_signing`

> **Period:** March 6–7, 2026  
> **From:** A basic PDF signing library  
> **To:** A full-featured PDF signing & verification toolkit with PKCS#7, PAdES (B-B/B-T/B-LT/B-LTA), LTV, security attack defenses, CLI tools, and Adobe/Foxit-compatible output  
> **Final codebase:** ~8,500+ lines of Rust across 20 source files

---

## Phase 1 — Signature Placeholder & Basic Signing

### 1.1 Create Signature Placeholder
- Created `src/signature_placeholder.rs` — code to insert an empty signature field into a PDF document
- This is the foundation: a PDF needs a `/Sig` dictionary with a `/ByteRange` and `/Contents` placeholder before actual cryptographic signing can happen

### 1.2 First Test with `sample.pdf`
- Created cargo test `test_create_signature_field_and_insert_v_on_sample_pdf`
- Used `examples/assets/sample.pdf` (a PDF with no existing signature placeholders)
- Test creates a signature field, inserts the `/V` (value) reference, and writes the signed output

### 1.3 Problem: No Digital Signature Information
- The output PDF contained a signature placeholder but the `/Contents` object was all zeros — no actual digital signature data
- **Fix:** Connected the signing pipeline so `UserSignatureInfo` (certificate, private key, signer name) actually computes the CMS/PKCS#7 signature and writes it into the `/Contents` hex string

### 1.4 Problem: Placeholder Has 0 Bytes, Not Signature
- The content object still had empty placeholder data
- **Fix:** Implemented the full `digitally_sign_document()` flow:
  1. Write PDF with placeholder `/Contents <00...00>`
  2. Compute `ByteRange` (everything except the `/Contents` hex)
  3. Hash the byte-range data with SHA-256
  4. Create CMS `SignedData` with the hash
  5. Write the DER-encoded signature back into `/Contents`

### 1.5 Problem: Signature Integrity Invalid & Image Not Appearing
- The digital signature was present but PDF viewers reported invalid integrity
- Signature image wasn't rendering
- **Root cause:** ByteRange calculation was off, and image XObject wasn't properly referenced in the page resources
- **Fix:** Corrected byte-range offsets and ensured image resources (`/XObject`) were added to the page's resource dictionary

### 1.6 Problem: PDF Not Standard-Compliant
- Errors like:
  - `The name Cs1 of a color space resource is unknown`
  - `The name F1.0/F2.0/F3.0 of a font resource is unknown`
  - `The document does not conform to PDF 1.3 standard`
- **Fix:** Ensured all resources (color spaces, fonts) referenced in content streams were properly defined in the page's `/Resources` dictionary

---

## Phase 2 — Signature Image & Page Selection

### 2.1 Embed Signature Image on Selected Page
- Added option to place the visible signature image on any page (not just page 1)
- Signature rectangle coordinates (`x1, y1, x2, y2`) configurable
- Image embedded as PNG XObject with proper `/Filter` and `/ColorSpace`

### 2.2 Invisible Signatures
- Added `--invisible` option for signing without a visible image
- Creates a zero-area signature annotation (no visual footprint)

---

## Phase 3 — Signature Field Naming

### 3.1 Random Signature Names
- Changed signature field names from static `"Signature1"` to `"Signature<RandomNumber>"`
- Prevents naming conflicts when applying multiple signatures to the same PDF

---

## Phase 4 — Digital Signature Validation

### 4.1 Created `src/signature_validator.rs`
- New class to validate digital signatures in PDF documents
- Checks:
  - ByteRange integrity (correct offsets, no gaps)
  - SHA-256 digest match (hash of signed content matches CMS digest)
  - CMS/PKCS#7 envelope validity (signature verification with public key)
  - Certificate chain structural validation

### 4.2 Created `examples/verify_pdf.rs`
- CLI tool to verify any signed PDF: `cargo run --example verify_pdf -- input.pdf`
- Prints detailed verification report for each signature

### 4.3 Signature Panel Not Showing in Adobe
- After opening the signed PDF, Adobe didn't show the signature panel
- **Root cause:** The `/Sig` dictionary was missing required entries or the `/AcroForm` wasn't properly linked
- **Fix:** Ensured `/AcroForm` → `/Fields` → signature field → `/V` → `/Sig` dictionary chain was complete and the `/SigFlags` was set to `3` (SignaturesExist + AppendOnly)

---

## Phase 5 — Removing Compiler Warnings

- Cleaned up unused imports, variables, and dead code
- Ensured `cargo build` produced zero warnings

---

## Phase 6 — PAdES Support

### 6.1 PAdES vs PKCS#7
- **PKCS#7** (`adbe.pkcs7.detached`): Adobe's legacy format
- **PAdES** (`ETSI.CAdES.detached`): EU standard, based on CAdES
- Key difference: PAdES uses ESS `signing-certificate-v2` attribute and different SubFilter

### 6.2 PAdES B-B (Basic)
- SubFilter: `ETSI.CAdES.detached`
- Adds `signing-certificate-v2` signed attribute
- No timestamp, no revocation data

### 6.3 PAdES B-T (Timestamp)
- Adds RFC 3161 signature timestamp from a TSA (Time Stamping Authority)
- Default TSA: `http://timestamp.digicert.com`
- Timestamp token placed in CMS unsigned attributes

### 6.4 PAdES B-LT (Long-Term)
- Adds DSS (Document Security Store) dictionary at document level
- DSS contains CRL responses, OCSP responses, and CA certificates
- Enables offline validation after certificate expiry

### 6.5 PAdES B-LTA (Long-Term Archival)
- Everything from B-LT plus a **document-level timestamp**
- Second signature: `ETSI.RFC3161` SubFilter with a timestamp covering the entire document including DSS
- Protects against future algorithm compromise

### 6.6 Verify PAdES Output
- Verified `result_pades.pdf` was truly PAdES-compliant
- SubFilter `ETSI.CAdES.detached` confirmed

---

## Phase 7 — CLI Application

### 7.1 `sign_doc.rs` as CLI
- Converted `examples/sign_doc.rs` into a full CLI app with argument parsing
- Options: `--cert`, `--key`, `--output`, `--format`, `--level`, `--page`, `--rect`, `--image`, `--invisible`, `--name`, `--email`, `--reason`, `--dss`, `--crl`, `--ocsp`, `--no-crl`

### 7.2 `verify_pdf.rs` as CLI
- `cargo run --example verify_pdf -- input.pdf`
- Supports `--json` output format
- Supports `--password` for encrypted PDFs

---

## Phase 8 — LTV (Long-Term Validation) Verification

### 8.1 LTV Detection in Verifier
- Added LTV status checking to `signature_validator.rs`
- Checks for:
  - `adbe-revocationInfoArchival` in CMS attributes
  - DSS dictionary presence (CRLs, OCSPs, Certs)
  - Timestamp presence
- Reports LTV method: "Adobe Pre-PAdES" or "PAdES (ETSI EN 319 142)"

---

## Phase 9 — PAdES Signing Variants (All Levels)

### 9.1 Implementation of All Four Levels
- `SignatureOptions.pades_level`: `B_B`, `B_T`, `B_LT`, `B_LTA`
- Each level incrementally adds more validation data
- B-LTA creates two signatures: main signature + document timestamp

---

## Phase 10 — Understanding Adobe's LTV for PKCS#7

### 10.1 The Question
> "How does Adobe determine if a signature is LTV when using `adbe.pkcs7` before PAdES standard?"

### 10.2 The Answer
Adobe checks for `adbe-revocationInfoArchival` (OID `1.2.840.113583.1.1.8`) attribute containing CRL/OCSP data, plus a timestamp token. This is the "Adobe Pre-PAdES" LTV mechanism.

---

## Phase 11 — Multi-Signature Testing

### 11.1 Two-Signer Scenario
- Tested signing a PDF with two different signers sequentially
- Each signature is an incremental update (preserves previous signatures)
- Verified both signatures remain valid after the second signing

---

## Phase 12 — PAdES B-LTA Timestamp Issue

### 12.1 Problem: Document Timestamp Shows as Unsigned Field
- After opening `result_pades_blta.pdf` in Adobe, the timestamp appeared as an unsigned signature field
- **Root cause:** The document timestamp signature was not properly structured as an `ETSI.RFC3161` timestamp
- **Fix:** Implemented `append_document_timestamp()` that creates a proper RFC 3161 document-level timestamp via incremental update

---

## Phase 13 — Modification Detection & Security Attacks

### 13.1 Implemented Detection for pdf-insecurity.org Attacks
- **USF** (Universal Signature Forgery): Validates ByteRange structure
- **SWA** (Signature Wrapping Attack): Cross-checks `/Contents` hex location
- **ISA** (Incremental Saving Attack): Compares revisions, classifies changes as permitted/unauthorized
- **Shadow Attack**: Detects content reference swaps, OCG visibility changes, page tree manipulation
- **EAA** (Evil Annotation Attack): Filters dangerous annotation types (JS, URI, Launch, etc.)
- **Certification Attack**: Enforces MDP permission levels

### 13.2 Certificate Trust Verification
- Warns when signer certificate is self-signed or from unrecognized CA
- Similar behavior to Adobe Reader's trust model

---

## Phase 14 — JSON Output & Encrypted PDF Support

### 14.1 JSON Verification Output
- `cargo run --example verify_pdf -- input.pdf --json`
- Returns structured JSON with all verification details

### 14.2 Password-Protected PDF Verification
- `cargo run --example verify_pdf -- encrypted.pdf --password "secret"`
- Decrypts PDF before validating signatures

---

## Phase 15 — Dependency Upgrades

### 15.1 Upgraded All Dependencies
- Updated `Cargo.toml` with latest compatible versions
- Resolved breaking API changes across dependencies
- Re-tested all functionality after upgrade

---

## Phase 16 — DSS PKI Factory Documentation

### 16.1 Created `DSS_PKI_Factory.md`
- Step-by-step guide to use https://dss.nowina.lu/pki-factory/
- How to download test certificates for signing
- How to extract PEM files from `.p12`

### 16.2 Signing with `ee-good-user.p12`
- Downloaded from PKI Factory with password `ks-password`
- Extracted chain PEM and key PEM
- Successfully signed PDFs with the test certificate

---

## Phase 17 — Testing Multiple Certificate Types

### 17.1 `good-user-ocsp-fail.p12`
- Certificate where OCSP check intentionally fails
- Tested PAdES all variants to verify behavior with broken OCSP

### 17.2 `good-user-crl-ocsp.p12`
- Certificate with both CRL Distribution Points and OCSP responder
- Used for all subsequent LTV testing
- Extracted to `crl-ocsp-chain.pem` and `crl-ocsp-key.pem`

---

## Phase 18 — All Signing Variants with CRL-OCSP Certificate

### 18.1 Full Matrix
Signed with all variants:

| # | Format | Level | Flags |
|---|--------|-------|-------|
| 1 | PAdES | B-B | — |
| 2 | PAdES | B-T | — |
| 3 | PAdES | B-LT | — |
| 4 | PAdES | B-LTA | — |
| 5 | PKCS#7 | — | `--crl` |
| 6 | PKCS#7 | — | `--crl --invisible` |

---

## Phase 19 — PKCS#7 LTV Problem

### 19.1 The Problem
> "Why after signing with PKCS#7, LTV is not active?"

### 19.2 Initial Diagnosis
- PKCS#7 was signed with `--no-crl` — no revocation data embedded
- LTV requires: revocation data (CRL/OCSP) + timestamp

### 19.3 First Fix: Add `--crl`
- Signing with `--crl` embedded CRL data in CMS signed attributes
- Our verifier showed LTV ✅
- **But Adobe/Foxit still showed NOT LTV** ❌

---

## Phase 20 — PKCS#7 LTV Deep Investigation (4 Attempts)

### 20.1 Attempt 1: OCSP Only in Signed Attributes
- Signed with `--ocsp --no-crl` for size efficiency
- OCSP response (~1-5 KB) vs CRL (~hundreds of KB)
- **Result:** ❌ Adobe did not recognize as LTV

### 20.2 Attempt 2: Move Revocation to Unsigned Attributes
- **Hypothesis:** "Adobe expects revocation data in CMS unsigned attributes"
- Built `inject_unsigned_attribute_into_cms()` — a DER ASN.1 parser/rebuilder that:
  1. Walks: `ContentInfo → SignedData → SignerInfos → SignerInfo`
  2. Finds or creates `unsignedAttrs [1]`
  3. Appends the `adbe-revocationInfoArchival` attribute alongside timestamp
  4. Re-encodes all outer DER lengths
- **Result:** ❌ Still not LTV in Adobe

### 20.3 Attempt 3: Fix ASN.1 Encoding Bug
- Discovered `Captured.encode()` in `bcder` crate wraps content in OCTET STRING (tag `0x04`)
- Adobe expects a bare SEQUENCE (tag `0x30`) inside the SET
- Created `RawDerBytes` helper implementing `bcder::encode::Values` to pass raw DER through
- **Before:** `SET { OCTET STRING { ... } }` ❌
- **After:** `SET { SEQUENCE { ... } }` ✅
- **Result:** ❌ Encoding fixed, but still not LTV (wrong location + missing CRL)

### 20.4 Attempt 4: Compare with Working Reference Document
- Compared with a known LTV PDF from BSRE/BSSN Indonesia
- Used `openssl asn1parse` to compare DER structures side-by-side

**Discovery:**

| Aspect | Reference (working LTV) | Our output |
|--------|------------------------|------------|
| Revocation location | **Signed attributes** | Unsigned attributes ❌ |
| Revocation content | **CRL + OCSP (both)** | OCSP only ❌ |
| Timestamp location | Unsigned attributes | Unsigned attributes ✅ |
| DSS dictionary | None | None ✅ |

### 20.5 Final Fix
1. **Reverted** revocation data back to CMS **signed attributes** (matching reference)
2. For PKCS#7, when user requests any revocation, automatically include **both CRL and OCSP**
3. Timestamp remains in **unsigned attributes**

### 20.6 Result
✅ **Adobe and Foxit now recognize PKCS#7 signatures as LTV!**

### 20.7 The Formula for PKCS#7 LTV
```
SignerInfo {
  signedAttrs [0] {
    contentType, messageDigest, signingTime,
    signing-certificate-v2,
    adbe-revocationInfoArchival {      ← CRL + OCSP here
      crl  [0]: CRL data
      ocsp [1]: OCSP response
    }
  }
  signature: ...
  unsignedAttrs [1] {                 ← timestamp here
    id-smime-aa-timeStampToken: RFC 3161 TST
  }
}
```

---

## Key Lessons Learned

### 1. Always Compare with a Working Reference
Don't rely solely on spec interpretation. Extract the CMS blob from a known-working LTV PDF and compare ASN.1 structures with `openssl asn1parse`.

### 2. Adobe PKCS#7 LTV Requires Both CRL AND OCSP
OCSP alone is not enough. CRL alone may work, but both together is the reliable approach.

### 3. `bcder::Captured.encode()` Wraps in OCTET STRING
When you need raw DER bytes passed through in the `bcder` crate, use a custom `Values` implementation — don't call `.encode()` on `Captured`.

### 4. Signed Attributes vs Unsigned Attributes
For `adbe.pkcs7.detached`:
- `adbe-revocationInfoArchival` → **signed attributes**
- `id-smime-aa-timeStampToken` → **unsigned attributes**

### 5. Test with the Target Application
Our custom verifier said LTV ✅ while Adobe said ❌. Always validate with the actual PDF viewer (Adobe Acrobat, Foxit).

### 6. Incremental Updates Preserve Signatures
Each new signature is appended via incremental update. Previous signatures remain untouched and valid.

### 7. PDF Security Attacks Are Real
The pdf-insecurity.org attacks (USF, SWA, ISA, Shadow, EAA) represent real vulnerabilities. Implementing defenses requires careful revision comparison and change classification.

---

## Files Created During This Journey

### Source Files
| File | Lines | Purpose |
|------|-------|---------|
| `src/signature_placeholder.rs` | ~100 | Create empty signature fields |
| `src/signature_validator.rs` | ~3,000 | Full signature verification engine |
| `src/digitally_sign.rs` | ~600 | CMS/PKCS#7 signing logic |
| `src/ltv.rs` | ~550 | LTV: CRL/OCSP fetch, DSS dict, revocation encoding |
| `src/signature_options.rs` | ~50 | Configuration (format, level, flags) |
| `src/signature_info.rs` | ~260 | Signature metadata (name, reason, time) |
| `src/acro_form.rs` | ~280 | AcroForm field management |
| `src/signature_image.rs` | ~120 | Visible signature appearance stream |
| `src/image_xobject.rs` | ~140 | PNG → PDF XObject conversion |
| `src/user_signature_info.rs` | ~30 | User identity for signing |
| `src/error.rs` | ~40 | Error types |

### Example / CLI Tools
| File | Purpose |
|------|---------|
| `examples/sign_doc.rs` | CLI tool to sign PDFs |
| `examples/verify_pdf.rs` | CLI tool to verify signed PDFs |
| `src/bin/verify_pades.rs` | PAdES-specific verification |
| `src/bin/inspect_pdf.rs` | PDF structure inspector |

### Documentation
| File | Purpose |
|------|---------|
| `README.md` | Project overview, features, quick start |
| `Create_Cert.md` | Self-signed certificate creation |
| `DSS_PKI_Factory.md` | Using DSS PKI Factory for test certs |
| `PKCS7_LTV_JOURNEY.md` | Detailed PKCS#7 LTV debugging story |
| `DEVELOPMENT_JOURNEY.md` | This file — full project history |

### Test Assets
| File | Purpose |
|------|---------|
| `examples/assets/sample.pdf` | Unsigned test PDF |
| `examples/assets/sample-signed.pdf` | Pre-signed test PDF |
| `examples/assets/sig1.png`, `sig2.png`, `sig3.png` | Signature images |
| `examples/assets/crl-ocsp-chain.pem` | Certificate chain (from DSS PKI Factory) |
| `examples/assets/crl-ocsp-key.pem` | Private key |
| `examples/assets/good-user-crl-ocsp.p12` | PKCS#12 keystore |
| `examples/assets/result-*.pdf` | Signed output samples |

---

## Final State — Feature Summary

```
✅ PKCS#7 signing (adbe.pkcs7.detached)
✅ PAdES signing (ETSI.CAdES.detached) — B-B, B-T, B-LT, B-LTA
✅ Visible signatures with PNG image
✅ Invisible signatures
✅ Multi-signature support (incremental updates)
✅ Signature validation (CMS, digest, chain, trust)
✅ LTV support — Adobe-compatible PKCS#7 with CRL+OCSP
✅ DSS dictionary (document-level revocation data)
✅ Document timestamps (RFC 3161)
✅ Security attack defenses (USF, SWA, ISA, Shadow, EAA, Certification)
✅ Certificate trust verification
✅ Encrypted PDF verification
✅ JSON output format
✅ CLI tools (sign_doc, verify_pdf)
✅ 22 passing unit tests
✅ Zero compiler warnings
```

---

*Documented on March 7, 2026*

