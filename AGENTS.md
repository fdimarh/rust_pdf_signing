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
