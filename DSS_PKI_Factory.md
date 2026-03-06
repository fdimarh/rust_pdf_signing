# Using DSS PKI Factory for Digital Signatures

> **URL:** <https://dss.nowina.lu/pki-factory/>

## What is DSS PKI Factory?

The **DSS (Digital Signature Service) PKI Factory** is a free online tool provided by Nowina/European Commission that generates **test certificates, keys, and keystores** for digital signature development and testing. It is part of the [eu-dss](https://github.com/esig/dss) ecosystem.

> ⚠️ **Important:** Certificates from PKI Factory are for **testing and development only** — they are NOT trusted by Adobe, browsers, or any real PKI. Do not use them in production.

---

## Why Use PKI Factory?

| Use Case | Description |
|----------|-------------|
| **Test PDF signing** | Generate certificates with the correct EKU (Extended Key Usage) for Adobe document signing |
| **PAdES development** | Test PAdES B-B, B-T, B-LT, B-LTA signature levels |
| **Multi-signer testing** | Create multiple signer identities quickly |
| **Certificate chain testing** | Get certificates issued by a CA chain (Root → Intermediate → End-Entity) |
| **LTV testing** | Certificates include CRL/OCSP distribution points for revocation testing |

---

## Step-by-Step Guide

### Step 1: Open PKI Factory

Navigate to: **<https://dss.nowina.lu/pki-factory/>**

You will see a form to configure your test certificate.

### Step 2: Configure Certificate Parameters

Fill in the form fields:

| Field | Recommended Value | Description |
|-------|-------------------|-------------|
| **Subject Serial Number** | *(leave default or enter any value)* | Unique serial for the subject |
| **Common Name (CN)** | `Test Signer` | Name of the signer (appears in PDF signature panel) |
| **Country (C)** | `US` or your country code | 2-letter ISO country code |
| **Key Algorithm** | `RSA` | Algorithm for the key pair (`RSA`, `ECDSA`, `Ed25519`) |
| **Key Size / Curve** | `2048` or `4096` | Key size for RSA; or named curve for ECDSA |
| **Digest Algorithm** | `SHA256` | Hash algorithm (`SHA256`, `SHA384`, `SHA512`) |
| **Certificate Type** | `SIGN` | Choose `SIGN` for document signing certificates |
| **Keystore Type** | `PKCS12` | Output format: `PKCS12` (.p12), `JKS`, or `PEM` |
| **Password** | `ks-password` | Password to protect the keystore |

### Step 3: Download the Keystore

Click **"Generate"** (or the submit button). The browser will download a `.p12` (PKCS#12) file containing:

- ✅ **Private key** (for signing)
- ✅ **End-entity certificate** (signer's certificate)
- ✅ **CA chain** (Intermediate CA + Root CA certificates)

### Step 4: Extract PEM Files (Optional)

If you need separate PEM files (e.g., for this `rust_pdf_signing` library), extract them from the `.p12`:

```bash
# Extract the private key (PEM format)
openssl pkcs12 -in keystore.p12 -nocerts -nodes -out signer-key.pem \
  -password pass:ks-password

# Extract the certificate chain (PEM format)
openssl pkcs12 -in keystore.p12 -nokeys -out signer-chain.pem \
  -password pass:ks-password

# Extract only the signer's certificate (first cert)
openssl pkcs12 -in keystore.p12 -nokeys -clcerts -out signer-cert.pem \
  -password pass:ks-password

# Extract only the CA certificates
openssl pkcs12 -in keystore.p12 -nokeys -cacerts -out ca-chain.pem \
  -password pass:ks-password
```

### Step 5: Inspect the Certificate

Verify the certificate has the correct properties:

```bash
# View certificate details
openssl x509 -in signer-cert.pem -text -noout

# Check Extended Key Usage (should include document signing OIDs)
openssl x509 -in signer-cert.pem -text -noout | grep -A2 "Extended Key Usage"

# Check Key Usage
openssl x509 -in signer-cert.pem -text -noout | grep -A2 "Key Usage"
```

**Expected output should include:**

```
X509v3 Key Usage: critical
    Digital Signature, Non Repudiation
X509v3 Extended Key Usage:
    (OIDs for document signing)
```

---

## Using with rust_pdf_signing

### Sign a PDF

```bash
cargo run --example sign_doc -- document.pdf \
  -c signer-chain.pem \
  -k signer-key.pem \
  -o signed-output.pdf \
  --name "Test Signer" \
  --reason "Testing with DSS PKI Factory certificate"
```

### Sign with PKCS#12 Directly

If you prefer using the `.p12` file directly, first extract the PEM files as shown in [Step 4](#step-4-extract-pem-files-optional).

### Verify the Signed PDF

```bash
cargo run --example verify_pdf -- signed-output.pdf
```

> **Note:** The verification will show `certificate chain not trusted ⚠️` because the PKI Factory Root CA is not in any trusted store. This is expected for test certificates. The signature integrity (CMS valid + digest match) should still be `✅`.

---

## Using with PAdES Signatures

PKI Factory certificates support all PAdES conformance levels:

```bash
# PAdES B-B (basic)
cargo run --example sign_doc -- document.pdf \
  -c signer-chain.pem -k signer-key.pem \
  -o pades-bb.pdf --pades

# PAdES B-T (with timestamp)
cargo run --example sign_doc -- document.pdf \
  -c signer-chain.pem -k signer-key.pem \
  -o pades-bt.pdf --pades --level t

# PAdES B-LT (with long-term validation data)
cargo run --example sign_doc -- document.pdf \
  -c signer-chain.pem -k signer-key.pem \
  -o pades-blt.pdf --pades --level lt

# PAdES B-LTA (with archival timestamp)
cargo run --example sign_doc -- document.pdf \
  -c signer-chain.pem -k signer-key.pem \
  -o pades-blta.pdf --pades --level lta
```

---

## DSS PKI Factory Certificate Properties

Certificates generated by PKI Factory typically include:

| Property | Value |
|----------|-------|
| **Issuer** | `DSS PKI Factory` intermediate CA |
| **Validity** | Usually valid for 1 year from generation |
| **Key Usage** | `digitalSignature`, `nonRepudiation` |
| **CRL Distribution Points** | Included (for LTV/revocation testing) |
| **Authority Info Access** | OCSP responder URL included |
| **Certificate Chain** | End-Entity → Intermediate CA → Root CA |

---

## Comparison: PKI Factory vs Self-Signed Certificates

| Feature | PKI Factory | Self-Signed (openssl) |
|---------|-------------|----------------------|
| **Certificate chain** | ✅ Full chain (Root → Intermediate → EE) | ❌ Single self-signed cert |
| **CRL/OCSP endpoints** | ✅ Included | ❌ Not included |
| **LTV testing** | ✅ Supports B-LT and B-LTA | ⚠️ Limited (no revocation data) |
| **Ease of use** | ✅ Web form, one click | ⚠️ Multiple openssl commands |
| **Customization** | ⚠️ Limited options | ✅ Full control |
| **Offline usage** | ❌ Requires internet | ✅ Works offline |
| **Production use** | ❌ Test only | ❌ Test only (both are untrusted) |

---

## Troubleshooting

### "Password incorrect" when extracting from .p12
- The default password is typically `ks-password` — check the value you set during generation.

### Certificate not recognized by Adobe Reader
- This is expected. PKI Factory certificates are **not trusted** by Adobe.
- To test trust in Adobe: manually add the Root CA to Adobe's trusted certificate store via `Edit → Preferences → Signatures → Identities & Trusted Certificates`.

### "Extended Key Usage" missing
- Make sure you selected **Certificate Type = SIGN** when generating.

### Expired certificate
- PKI Factory certificates have a limited validity period. Generate a new one if expired.

---

## Additional Resources

- **DSS PKI Factory:** <https://dss.nowina.lu/pki-factory/>
- **DSS Demonstration WebApp:** <https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/>
- **EU DSS Library (Java):** <https://github.com/esig/dss>
- **Self-Signed Cert Guide:** [Create_Cert.md](Create_Cert.md)
- **Adobe Digital Signatures Info:** <https://www.adobe.com/devnet-docs/acrobatetk/tools/DigSig/changes.html>

