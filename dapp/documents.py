"""
Sinh chứng từ thương mại mẫu (PDF) và metadata NFT vận đơn cho demo.

- 3 loại chứng từ: Bill of Lading (B/L), Commercial Invoice, Certificate of Origin (C/O).
- PDF được viết tay theo chuẩn PDF 1.4 (không cần thư viện ngoài), font Helvetica.
  PDF chuẩn không nhúng font tiếng Việt nên nội dung được bỏ dấu.
- Metadata NFT theo chuẩn ERC-721 Metadata JSON (name, description, attributes…).
"""

from __future__ import annotations

import unicodedata
from typing import Mapping

DOC_TITLES = {
    "BL": "BILL OF LADING",
    "INVOICE": "COMMERCIAL INVOICE",
    "CO": "CERTIFICATE OF ORIGIN",
}
DOC_FILENAMES = {
    "BL": "bill_of_lading.pdf",
    "INVOICE": "commercial_invoice.pdf",
    "CO": "certificate_of_origin.pdf",
}


def _ascii(text: str) -> str:
    text = text.replace("đ", "d").replace("Đ", "D")
    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if not unicodedata.combining(c))
    return text.encode("ascii", "replace").decode("ascii")


def _pdf_escape(text: str) -> str:
    return _ascii(text).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def make_pdf(title: str, lines: list[str]) -> bytes:
    """Tạo một PDF 1 trang A4 gồm tiêu đề và các dòng văn bản."""
    ops = ["BT", "/F2 18 Tf", "56 780 Td", f"({_pdf_escape(title)}) Tj", "/F1 11 Tf", "0 -16 TL", "T*"]
    for line in lines:
        ops.append(f"({_pdf_escape(line)}) '")
    ops.append("ET")
    ops += ["0.6 w", "56 770 m 540 770 l S"]
    stream = "\n".join(ops).encode("latin-1")

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
        b"/Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


def _fmt_amount(value) -> str:
    return f"{float(value):,.2f}"


def generate_trade_documents(lc_id: int | str, terms: Mapping, variant: str = "") -> dict[str, bytes]:
    """
    Sinh 3 chứng từ PDF khớp với điều khoản L/C.
    `variant` (vd "wrong-port") dùng để tạo bộ chứng từ sai lệch khi demo discrepancy.
    """
    port_loading = terms.get("port_of_loading", "Cat Lai, Ho Chi Minh City")
    if variant == "wrong-port":
        port_loading = "Hai Phong"  # cố tình sai so với điều khoản

    common = [
        f"L/C reference: LC-{lc_id}",
        f"Shipper / Exporter: {terms.get('exporter_name', '')}",
        f"Consignee / Importer: {terms.get('importer_name', '')}",
        f"Goods: {terms.get('goods', '')}",
        f"Quantity: {terms.get('quantity', '')}",
    ]
    bl = common + [
        f"B/L No.: BL-{lc_id}-{terms.get('shipment_ref', '001')}",
        f"Vessel: {terms.get('vessel', 'MV TRADE FINANCE')}",
        f"Port of loading: {port_loading}",
        f"Port of discharge: {terms.get('port_of_discharge', '')}",
        f"Shipped on board date: {terms.get('shipment_date', '')}",
        f"Incoterm: {terms.get('incoterm', '')}",
        "Freight: as per charter party",
    ]
    invoice = common + [
        f"Invoice No.: INV-{lc_id}-{terms.get('shipment_ref', '001')}",
        f"Unit price: {terms.get('currency', 'TFUSD')} {_fmt_amount(terms.get('unit_price', 0))}",
        f"Total amount: {terms.get('currency', 'TFUSD')} {_fmt_amount(terms.get('amount', 0))}",
        f"Payment: Documentary Credit LC-{lc_id} (on-chain escrow)",
    ]
    co = common + [
        f"C/O No.: CO-{lc_id}-{terms.get('shipment_ref', '001')}",
        f"Country of origin: {terms.get('origin_country', 'Viet Nam')}",
        "Form: B",
        f"Issued by: {terms.get('co_issuer', 'VCCI')}",
    ]
    return {
        "BL": make_pdf(DOC_TITLES["BL"], bl),
        "INVOICE": make_pdf(DOC_TITLES["INVOICE"], invoice),
        "CO": make_pdf(DOC_TITLES["CO"], co),
    }


def build_ebl_metadata(lc_id: int | str, manifest_cid: str, documents: Mapping[str, Mapping]) -> dict:
    """
    Metadata ERC-721 cho NFT vận đơn điện tử (eBL). Công khai: chỉ chứa CID của bản MÃ HÓA và hash,
    không chứa nội dung chứng từ hay điều khoản thương mại (hàng hóa, giá, cảng… đều nằm trong bản mã).
    """
    return {
        "name": f"Electronic Bill of Lading - LC #{lc_id}",
        "description": (
            "Digital Bill of Lading representing title to the goods under the Letter of Credit. "
            "Documents are AES-256-GCM encrypted on IPFS; SHA-256 hashes are anchored on-chain."
        ),
        "external_url": f"ipfs://{manifest_cid}",
        "attributes": [
            {"trait_type": "LC ID", "value": str(lc_id)},
            {"trait_type": "Document", "value": "Bill of Lading"},
            {"trait_type": "Encryption", "value": "AES-256-GCM + RSA-OAEP"},
        ],
        "properties": {
            "manifest": f"ipfs://{manifest_cid}",
            "documents": {
                k: {"cid": f"ipfs://{v['cid']}", "sha256": v["sha256"]} for k, v in documents.items()
            },
        },
    }
