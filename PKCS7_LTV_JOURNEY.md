# PKCS#7 LTV (Long-Term Validation) — Journey & Lessons Learned

> **Date:** March 7, 2026  
> **Project:** `rust_pdf_signing`  
> **Goal:** Make `adbe.pkcs7.detached` digital signatures recognized as LTV-enabled by Adobe Acrobat and Foxit Reader.

---

## Table of Contents

1. [Background](#1-background)
2. [Initial State — LTV Not Active](#2-initial-state--ltv-not-active)
3. [Attempt 1 — OCSP Only in Signed Attributes](#3-attempt-1--ocsp-only-in-signed-attributes)
4. [Attempt 2 — Move Revocation to Unsigned Attributes](#4-attempt-2--move-revocation-to-unsigned-attributes)
5. [Attempt 3 — Fix ASN.1 Encoding (OCTET STRING → SEQUENCE)](#5-attempt-3--fix-asn1-encoding-octet-string--sequence)
6. [Attempt 4 — Compare with Working LTV Reference Document](#6-attempt-4--compare-with-working-ltv-reference-document)
7. [Final Solution — CRL + OCSP in Signed Attributes](#7-final-solution--crl--ocsp-in-signed-attributes)
8. [Key Takeaways](#8-key-takeaways)
9. [CMS Structure Reference](#9-cms-structure-reference)

---

## 1. Background

### What is LTV?

**Long-Term Validation (LTV)** ensures a digital signature can be validated even after:
- The signer's certificate has expired
- The CA's CRL/OCSP services are no longer available
- Certificate revocation information is no longer accessible online

LTV requires **two components**:
1. **Revocation data** (CRL and/or OCSP response) — proves the certificate wasn't revoked at signing time
2. **Timestamp** — anchors the validation time to prove the signature was made while the certificate was still valid

### PKCS#7 vs PAdES

| Aspect | `adbe.pkcs7.detached` | `ETSI.CAdES.detached` (PAdES) |
|--------|----------------------|-------------------------------|
| Standard | Adobe legacy (pre-PAdES) | ETSI EN 319 142 |
| LTV mechanism | `adbe-revocationInfoArchival` in CMS + timestamp | DSS dictionary at document level |
| SubFilter | `adbe.pkcs7.detached` | `ETSI.CAdES.detached` |
| Widely used by | Government systems (e.g., BSRE/BSSN Indonesia) | EU eIDAS, modern PKI |

---

## 2. Initial State — LTV Not Active

### Problem

When signing with `--ocsp --no-crl`, the PKCS#7 signatures showed:
- ✅ Valid signature
- ✅ Timestamp present
- ❌ **LTV not recognized by Adobe/Foxit**

### Root Cause (discovered later)

Two issues:
1. **Missing CRL** — Only OCSP was embedded, Adobe needs **both CRL + OCSP**
2. **Wrong attribute placement** (attempted in later iterations)

### CLI Command Used

```bash
cargo run --example sign_doc -- sample.pdf \
  -c chain.pem -k key.pem -o result-pkcs7.pdf \
  -f pkcs7 --name "signer" --reason "test" \
  -i sig.png --ocsp --no-crl
```

---

## 3. Attempt 1 — OCSP Only in Signed Attributes

### Hypothesis

> "OCSP is smaller than CRL, so let's embed only OCSP for size efficiency."

### What We Did

- Signed with `--ocsp --no-crl`
- `adbe-revocationInfoArchival` attribute contained only OCSP response (no CRL)
- Placed in CMS **signed attributes**

### Result

❌ **Adobe/Foxit did NOT show LTV**

### Lesson

> Adobe requires **both CRL and OCSP** for `adbe.pkcs7.detached` LTV. OCSP alone is not sufficient.

---

## 4. Attempt 2 — Move Revocation to Unsigned Attributes

### Hypothesis

> "Maybe Adobe expects `adbe-revocationInfoArchival` in CMS **unsigned attributes**, not signed attributes. Unsigned attributes can be updated post-signing, which aligns with LTV philosophy."

### What We Did

1. Created `inject_unsigned_attribute_into_cms()` function:
   - Parses the DER-encoded CMS `SignedData` structure
   - Locates the `SignerInfo`'s unsigned attributes section
   - Injects the revocation attribute alongside the existing timestamp token
   - Rebuilds all outer DER lengths

2. Changed PKCS#7 flow:
   ```
   Before: revocation → signed attrs → sign → timestamp (unsigned)
   After:  sign → timestamp (unsigned) → inject revocation (unsigned)
   ```

3. The CMS `inject_unsigned_attribute_into_cms` function had to:
   - Walk the ASN.1 structure: `ContentInfo → SignedData → SignerInfos → SignerInfo`
   - Find the `unsignedAttrs [1]` section
   - Append new attribute bytes
   - Re-encode all outer SEQUENCE/SET lengths from inside out

### Result

❌ **Adobe/Foxit STILL did not show LTV**

### Lesson

> The assumption that "unsigned attributes" is the correct location was **wrong**. Adobe actually checks **signed attributes** for `adbe-revocationInfoArchival`.

---

## 5. Attempt 3 — Fix ASN.1 Encoding (OCTET STRING → SEQUENCE)

### Hypothesis

> "Maybe the ASN.1 encoding is wrong. The `RevocationInfoArchival` value might be wrapped in an OCTET STRING instead of being a bare SEQUENCE."

### What We Found

Using `openssl asn1parse`:

**Our output (broken):**
```
OID: 1.2.840.113583.1.1.8
SET {
  OCTET STRING: <encoded data>     ← WRONG! (tag 0x04)
}
```

**Expected:**
```
OID: 1.2.840.113583.1.1.8
SET {
  SEQUENCE {                        ← CORRECT! (tag 0x30)
    cont [0]: CRL data
    cont [1]: OCSP data
  }
}
```

### Root Cause

When using `bcder`:
```rust
// WRONG: .encode() on Captured wraps in OCTET STRING
bcder::encode::set(encoded_revocation_info.encode())

// CORRECT: Use raw bytes directly
struct RawDerBytes(Vec<u8>);
impl Values for RawDerBytes { /* emit bytes as-is */ }
bcder::encode::set(RawDerBytes(rev_info_bytes.to_vec()))
```

### What We Did

Created `RawDerBytes` helper struct implementing `bcder::encode::Values` to emit pre-encoded DER bytes without any additional wrapping.

### Result

❌ **Fixed the encoding, but still no LTV in Adobe** (because we were still in unsigned attributes with OCSP only)

### Lesson

> `Captured.encode()` in the `bcder` crate wraps content in an OCTET STRING. When you need raw DER bytes passed through, use a custom `Values` implementation.

---

## 6. Attempt 4 — Compare with Working LTV Reference Document

### The Breakthrough

Compared our PKCS#7 output with a **known working LTV document** from BSRE/BSSN Indonesia:

```bash
# Extract signature from working LTV PDF
openssl asn1parse -inform DER -in /tmp/ltv_ref_sig.der

# Compare structures side by side
```

### Key Findings from Reference Document

| Aspect | Reference (working LTV) | Our output |
|--------|------------------------|------------|
| SubFilter | `adbe.pkcs7.detached` | `adbe.pkcs7.detached` ✅ |
| Revocation location | **Signed attributes** | Unsigned attributes ❌ |
| Revocation content | **CRL + OCSP (both!)** | OCSP only ❌ |
| Timestamp location | Unsigned attributes | Unsigned attributes ✅ |
| DSS dictionary | None | None ✅ |
| Has `/VRI` | No | No ✅ |

### The Reference CMS Structure (ASN.1)

```
ContentInfo SEQUENCE
└── SignedData SEQUENCE
    ├── version: 1
    ├── digestAlgorithms
    ├── encapContentInfo (pkcs7-data)
    ├── certificates [0]
    └── signerInfos SET OF
        └── SignerInfo SEQUENCE
            ├── version: 1
            ├── issuerAndSerialNumber
            ├── digestAlgorithm (sha256)
            ├── signedAttrs [0]          ← REVOCATION HERE
            │   ├── contentType
            │   ├── messageDigest
            │   ├── signingTime
            │   └── adbe-revocationInfoArchival (1.2.840.113583.1.1.8)
            │       └── SEQUENCE (RevocationInfoArchival)
            │           ├── [0] CRL data     ← CRL present!
            │           └── [1] OCSP data    ← OCSP present!
            ├── signatureAlgorithm
            ├── signature
            └── unsignedAttrs [1]        ← TIMESTAMP HERE
                └── id-smime-aa-timeStampToken
                    └── SignedData (RFC 3161 TST)
```

### Lesson

> **Always compare with a known working reference document** rather than relying on spec interpretation alone. The spec may be ambiguous, but a working implementation tells the truth.

---

## 7. Final Solution — CRL + OCSP in Signed Attributes

### Changes Made

**`src/digitally_sign.rs`:**

```rust
} else {
    // PKCS7: Adobe determines LTV by checking for
    // adbe-revocationInfoArchival in CMS **signed attributes**
    // (with CRL+OCSP) plus a timestamp in unsigned attributes.
    let wants_revocation = signature_options.signed_attribute_include_crl
        || signature_options.signed_attribute_include_ocsp;
    include_cms_revocation = wants_revocation;
    include_timestamp = signature_options.timestamp_url.is_some();
    include_dss = signature_options.include_dss;
}

// For PKCS7: always include BOTH CRL and OCSP
let crl_flag = if is_pades { /* ... */ } else { true };
let ocsp_flag = if is_pades { /* ... */ } else { true };
```

### Why It Works

Adobe's LTV check for `adbe.pkcs7.detached` requires:

1. ✅ `adbe-revocationInfoArchival` (OID `1.2.840.113583.1.1.8`) in **signed attributes**
2. ✅ Contains **both CRL and OCSP** revocation data
3. ✅ Timestamp token (`id-smime-aa-timeStampToken`) in **unsigned attributes**
4. ✅ Full certificate chain embedded in CMS `certificates` field

### CLI Command for LTV PKCS#7

```bash
# --ocsp flag triggers both CRL+OCSP for PKCS7 automatically
cargo run --example sign_doc -- input.pdf \
  -c chain.pem -k key.pem -o output.pdf \
  -f pkcs7 --name "Signer" --reason "Signing" \
  -i signature.png --ocsp
```

### Verification

```bash
# Our verifier
cargo run --example verify_pdf -- output.pdf

# OpenSSL ASN.1 inspection
openssl asn1parse -inform DER -in signature.der
```

---

## 8. Key Takeaways

### ✅ Do's

1. **Always compare with a working reference** — Don't just read the spec. Get a real working LTV PDF and compare byte-by-byte.

2. **Include both CRL and OCSP for PKCS#7** — Adobe expects both revocation methods, not just one.

3. **Use `openssl asn1parse`** — Essential for debugging DER/ASN.1 encoding issues.

4. **Test with the actual viewer** — Our custom verifier passed, but Adobe/Foxit didn't. Always validate with the target application.

5. **Extract and inspect the CMS blob directly** — Use Python to extract `/Contents` hex from PDF, then inspect with OpenSSL.

### ❌ Don'ts

1. **Don't assume unsigned attributes** — For `adbe.pkcs7.detached`, Adobe checks signed attributes for revocation data.

2. **Don't use `Captured.encode()` when you need raw DER** — The `bcder` crate wraps `Captured` in OCTET STRING. Use a custom `Values` impl instead.

3. **Don't embed OCSP only** — CRL is required alongside OCSP for Adobe LTV recognition in PKCS#7.

4. **Don't rely on DSS dictionary for PKCS#7 LTV** — DSS is the PAdES approach. PKCS#7 uses CMS-embedded revocation data.

### 🔑 The Formula for PKCS#7 LTV

```
LTV = adbe-revocationInfoArchival(CRL + OCSP) in signed_attrs
    + timestamp_token in unsigned_attrs
    + full certificate chain in CMS certificates
```

---

## 9. CMS Structure Reference

### OIDs Used

| OID | Name | Purpose |
|-----|------|---------|
| `1.2.840.113583.1.1.8` | `adbe-revocationInfoArchival` | Embeds CRL/OCSP revocation data |
| `1.2.840.113549.1.9.16.2.14` | `id-smime-aa-timeStampToken` | RFC 3161 timestamp token |
| `1.2.840.113549.1.7.2` | `pkcs7-signedData` | CMS SignedData container |
| `1.2.840.113549.1.9.3` | `contentType` | Signed attribute |
| `1.2.840.113549.1.9.4` | `messageDigest` | Signed attribute |
| `1.2.840.113549.1.9.5` | `signingTime` | Signed attribute |

### RevocationInfoArchival ASN.1

```asn1
RevocationInfoArchival ::= SEQUENCE {
  crl         [0] EXPLICIT SEQUENCE OF CRLs          OPTIONAL,
  ocsp        [1] EXPLICIT SEQUENCE OF OCSPResponse   OPTIONAL,
  otherRevInfo [2] EXPLICIT SEQUENCE OF OtherRevInfo  OPTIONAL
}
```

### Debugging Commands

```bash
# Extract signature hex from PDF
python3 -c "
import re
data = open('signed.pdf', 'rb').read()
m = re.search(rb'/Contents\s*<([0-9a-fA-F]+)>', data)
sig = bytes.fromhex(m.group(1).decode().rstrip('0'))
open('sig.der', 'wb').write(sig)
"

# Inspect full ASN.1 structure
openssl asn1parse -inform DER -in sig.der

# Check for specific OID
openssl asn1parse -inform DER -in sig.der | grep "1.2.840.113583"

# Check signed vs unsigned attributes location
openssl asn1parse -inform DER -in sig.der | grep "cont \["

# Check if PDF has DSS dictionary
python3 -c "
data = open('signed.pdf', 'rb').read()
print('DSS:', b'/DSS' in data)
print('VRI:', b'/VRI' in data)
"
```

---

## Timeline of Attempts

| # | Approach | Revocation Location | Content | Result |
|---|----------|-------------------|---------|--------|
| 1 | OCSP in signed attrs | Signed attributes | OCSP only | ❌ Not LTV |
| 2 | Move to unsigned attrs | Unsigned attributes | OCSP only | ❌ Not LTV |
| 3 | Fix ASN.1 encoding | Unsigned attributes | OCSP only (fixed encoding) | ❌ Not LTV |
| 4 | Compare with reference | **Signed attributes** | **CRL + OCSP** | ✅ **LTV!** |

> **Total iterations: 4**  
> **Key insight: Always compare with a working reference document.**

---

*Generated from the development journey of `rust_pdf_signing` — March 7, 2026*

