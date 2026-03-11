#!/usr/bin/env python3
"""Generate a minimal PDF with a #SIGN_HERE tag for testing tag-anchored signing."""

import struct, zlib

def pdf_with_tag():
    objects = []

    # Object 1: Catalog
    objects.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

    # Object 2: Pages
    objects.append(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")

    # Object 3: Page
    objects.append(
        b"3 0 obj\n"
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]\n"
        b"   /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\n"
        b"endobj\n"
    )

    # Object 4: Content stream (uncompressed for simplicity)
    stream = (
        b"BT\n"
        b"/F1 12 Tf\n"
        b"1 0 0 1 72 700 Tm\n"
        b"(This is a test document for signature tag anchoring.) Tj\n"
        b"1 0 0 1 72 670 Tm\n"
        b"(Please sign below at the designated marker.) Tj\n"
        b"1 0 0 1 72 620 Tm\n"
        b"(Signature: #SIGN_HERE) Tj\n"
        b"1 0 0 1 72 580 Tm\n"
        b"(Date: 2026-03-11) Tj\n"
        b"1 0 0 1 72 540 Tm\n"
        b"(Thank you for using pdf_signing!) Tj\n"
        b"ET\n"
    )
    stream_obj = (
        b"4 0 obj\n<< /Length " + str(len(stream)).encode() + b" >>\nstream\n"
        + stream + b"\nendstream\nendobj\n"
    )
    objects.append(stream_obj)

    # Object 5: Font (Helvetica)
    objects.append(
        b"5 0 obj\n"
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\n"
        b"endobj\n"
    )

    # Build PDF
    header = b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n"
    body = b""
    offsets = []

    for obj in objects:
        offsets.append(len(header) + len(body))
        body += obj

    xref_offset = len(header) + len(body)

    xref = b"xref\n"
    xref += f"0 {len(objects)+1}\n".encode()
    xref += b"0000000000 65535 f \n"
    for off in offsets:
        xref += f"{off:010d} 00000 n \n".encode()

    trailer = (
        b"trailer\n<< /Size " + str(len(objects)+1).encode() +
        b" /Root 1 0 R >>\n"
        b"startxref\n" + str(xref_offset).encode() + b"\n%%EOF\n"
    )

    return header + body + xref + trailer


if __name__ == "__main__":
    import os
    out_path = os.path.join(os.path.dirname(__file__), "sample-tag-sign.pdf")
    data = pdf_with_tag()
    with open(out_path, "wb") as f:
        f.write(data)
    print(f"Created {out_path} ({len(data)} bytes)")

