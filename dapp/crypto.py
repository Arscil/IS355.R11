"""
Module mã hóa cho DApp L/C (Giai đoạn 4 – tiêu chí 2 của rubric).

Mô hình: **mã hóa lai (hybrid encryption / envelope encryption)**

    1. Sinh một khóa AES-256 ngẫu nhiên cho MỖI dữ liệu (điều khoản L/C hoặc một file PDF).
    2. Mã hóa dữ liệu bằng AES-256-GCM (vừa bảo mật vừa phát hiện chỉnh sửa nhờ auth tag).
       AAD (associated data) gắn ngữ cảnh, ví dụ "lc:1:doc:BL", để không thể tráo bản mã giữa các chứng từ.
    3. "Bọc" khóa AES bằng RSA-OAEP (SHA-256) với public key của từng bên ĐƯỢC PHÉP đọc.
       Bên không có tên trong danh sách thì không có cách nào lấy được khóa AES → nền tảng cho RBAC (GĐ5).
    4. Đóng gói tất cả vào một "envelope" JSON để lưu lên IPFS.

Hash dùng để đối chiếu on-chain là SHA-256 của dữ liệu GỐC (chưa mã hóa), dạng "0x" + 64 hex,
khớp với kiểu bytes32 trong contract và ethers.sha256().
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENVELOPE_VERSION = 1
ALGORITHM = "AES-256-GCM+RSA-OAEP-SHA256"
AES_KEY_BYTES = 32  # 256 bit
NONCE_BYTES = 12    # 96 bit, khuyến nghị của NIST SP 800-38D cho GCM
RSA_KEY_BITS = 2048


class DecryptionError(Exception):
    """Không giải mã được: sai khóa, không có quyền, hoặc dữ liệu đã bị chỉnh sửa."""


# --------------------------------------------------------------------------- helpers
def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def sha256_hex(data: bytes) -> str:
    """SHA-256 dạng '0x…' (bytes32) – dùng làm docHashes khi nộp chứng từ lên contract."""
    return "0x" + hashlib.sha256(data).hexdigest()


def sha256_file(path: str | os.PathLike) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return "0x" + h.hexdigest()


# --------------------------------------------------------------------------- AES-256-GCM
def generate_aes_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def aes_encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> tuple[bytes, bytes]:
    """Trả về (nonce, ciphertext||tag). Mỗi lần gọi dùng nonce ngẫu nhiên mới."""
    if len(key) != AES_KEY_BYTES:
        raise ValueError("AES key phải dài 32 byte (AES-256)")
    nonce = os.urandom(NONCE_BYTES)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise DecryptionError("Auth tag không hợp lệ: sai khóa, sai ngữ cảnh hoặc dữ liệu bị sửa") from exc


# --------------------------------------------------------------------------- RSA-OAEP
_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def generate_rsa_keypair(bits: int = RSA_KEY_BITS) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def private_key_to_pem(key: rsa.RSAPrivateKey, passphrase: bytes | None = None) -> bytes:
    enc = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase
        else serialization.NoEncryption()
    )
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)


def public_key_to_pem(key: rsa.RSAPublicKey | rsa.RSAPrivateKey) -> bytes:
    if isinstance(key, rsa.RSAPrivateKey):
        key = key.public_key()
    return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def load_private_key(pem: bytes, passphrase: bytes | None = None) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(pem, password=passphrase)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("Không phải RSA private key")
    return key


def load_public_key(pem: bytes) -> rsa.RSAPublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("Không phải RSA public key")
    return key


def wrap_key(public_key: rsa.RSAPublicKey, aes_key: bytes) -> bytes:
    """Bọc khóa AES bằng RSA-OAEP để chỉ chủ private key tương ứng mở được."""
    return public_key.encrypt(aes_key, _OAEP)


def unwrap_key(private_key: rsa.RSAPrivateKey, wrapped: bytes) -> bytes:
    try:
        return private_key.decrypt(wrapped, _OAEP)
    except ValueError as exc:
        raise DecryptionError("Không mở được khóa AES bằng private key này") from exc


def fingerprint(public_key: rsa.RSAPublicKey) -> str:
    """SHA-256 của public key (DER) – dùng để nhận diện khóa trong envelope."""
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()[:16]


# --------------------------------------------------------------------------- Envelope
@dataclass
class Envelope:
    """Gói dữ liệu đã mã hóa + khóa AES đã bọc cho từng bên được phép."""

    aad: str
    nonce: str
    ciphertext: str
    recipients: dict[str, dict[str, str]] = field(default_factory=dict)  # id -> {wrapped_key, key_fp}
    content_type: str = "application/octet-stream"
    filename: str | None = None
    version: int = ENVELOPE_VERSION
    alg: str = ALGORITHM

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "alg": self.alg,
            "aad": self.aad,
            "content_type": self.content_type,
            "filename": self.filename,
            "nonce": self.nonce,
            "ciphertext": self.ciphertext,
            "recipients": self.recipients,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)

    @classmethod
    def from_dict(cls, d: Mapping) -> "Envelope":
        if d.get("version") != ENVELOPE_VERSION or d.get("alg") != ALGORITHM:
            raise ValueError(f"Envelope không được hỗ trợ: version={d.get('version')} alg={d.get('alg')}")
        return cls(
            aad=d["aad"],
            nonce=d["nonce"],
            ciphertext=d["ciphertext"],
            recipients={k: dict(v) for k, v in d["recipients"].items()},
            content_type=d.get("content_type", "application/octet-stream"),
            filename=d.get("filename"),
        )

    @classmethod
    def from_json(cls, text: str | bytes) -> "Envelope":
        return cls.from_dict(json.loads(text))

    def recipient_ids(self) -> list[str]:
        return sorted(self.recipients)


def seal(
    plaintext: bytes,
    recipients: Mapping[str, rsa.RSAPublicKey],
    aad: str,
    *,
    content_type: str = "application/octet-stream",
    filename: str | None = None,
) -> Envelope:
    """
    Mã hóa `plaintext` cho danh sách `recipients` (id -> public key).
    `aad` là ngữ cảnh bắt buộc (ví dụ "lc:1:doc:BL"); khi mở phải đúng `aad` này.
    """
    if not recipients:
        raise ValueError("Cần ít nhất một bên nhận")
    if not aad:
        raise ValueError("Cần AAD (ngữ cảnh) để chống tráo bản mã")

    aes_key = generate_aes_key()
    nonce, ct = aes_encrypt(aes_key, plaintext, aad.encode("utf-8"))
    wrapped = {
        rid: {"wrapped_key": _b64e(wrap_key(pub, aes_key)), "key_fp": fingerprint(pub)}
        for rid, pub in recipients.items()
    }
    return Envelope(
        aad=aad,
        nonce=_b64e(nonce),
        ciphertext=_b64e(ct),
        recipients=wrapped,
        content_type=content_type,
        filename=filename,
    )


def open_envelope(
    envelope: Envelope,
    recipient_id: str,
    private_key: rsa.RSAPrivateKey,
    expected_aad: str | None = None,
) -> bytes:
    """
    Giải mã envelope bằng private key của `recipient_id`.
    Nếu truyền `expected_aad`, envelope phải thuộc đúng ngữ cảnh đó (chống tráo file giữa các L/C).
    """
    if expected_aad is not None and envelope.aad != expected_aad:
        raise DecryptionError(f"Sai ngữ cảnh: envelope thuộc '{envelope.aad}', cần '{expected_aad}'")
    entry = envelope.recipients.get(recipient_id)
    if entry is None:
        raise DecryptionError(f"'{recipient_id}' không có quyền đọc dữ liệu này")
    if entry.get("key_fp") != fingerprint(private_key.public_key()):
        raise DecryptionError(f"Private key không khớp với khóa đã đăng ký của '{recipient_id}'")

    aes_key = unwrap_key(private_key, _b64d(entry["wrapped_key"]))
    return aes_decrypt(aes_key, _b64d(envelope.nonce), _b64d(envelope.ciphertext), envelope.aad.encode("utf-8"))


# --------------------------------------------------------------------------- tiện ích nghiệp vụ
def seal_terms(terms: Mapping, recipients: Mapping[str, rsa.RSAPublicKey], lc_ref: str) -> Envelope:
    """Mã hóa điều khoản L/C (dict) – AAD 'lc:<ref>:terms'."""
    data = json.dumps(terms, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return seal(data, recipients, f"lc:{lc_ref}:terms", content_type="application/json")


def open_terms(envelope: Envelope, recipient_id: str, private_key: rsa.RSAPrivateKey, lc_ref: str) -> dict:
    data = open_envelope(envelope, recipient_id, private_key, expected_aad=f"lc:{lc_ref}:terms")
    return json.loads(data.decode("utf-8"))


DOC_TYPES = ("BL", "INVOICE", "CO")  # thứ tự khớp docCIDs[0..2] trong contract


def seal_document(
    data: bytes,
    doc_type: str,
    recipients: Mapping[str, rsa.RSAPublicKey],
    lc_ref: str,
    filename: str | None = None,
) -> tuple[Envelope, str]:
    """
    Mã hóa một chứng từ (PDF). Trả về (envelope, sha256 của file gốc).
    Hash này chính là docHashes[i] nộp lên contract.
    """
    if doc_type not in DOC_TYPES:
        raise ValueError(f"doc_type phải thuộc {DOC_TYPES}")
    env = seal(data, recipients, f"lc:{lc_ref}:doc:{doc_type}", content_type="application/pdf", filename=filename)
    return env, sha256_hex(data)


def open_document(
    envelope: Envelope,
    doc_type: str,
    recipient_id: str,
    private_key: rsa.RSAPrivateKey,
    lc_ref: str,
    expected_sha256: str | None = None,
) -> bytes:
    """
    Giải mã chứng từ và (nếu có) đối chiếu SHA-256 với hash on-chain.
    Đây là bước Advising Bank làm trước khi gọi executePayment().
    """
    data = open_envelope(envelope, recipient_id, private_key, expected_aad=f"lc:{lc_ref}:doc:{doc_type}")
    if expected_sha256 is not None and sha256_hex(data).lower() != expected_sha256.lower():
        raise DecryptionError(f"Hash chứng từ {doc_type} không khớp với hash on-chain")
    return data


# --------------------------------------------------------------------------- key store trên đĩa
class KeyStore:
    """
    Lưu cặp khóa RSA của từng bên trong thư mục `keys/`:
        keys/<party>_private.pem  (không commit; mã hóa bằng passphrase nếu có)
        keys/<party>_public.pem
    Passphrase lấy từ biến môi trường KEY_PASSPHRASE (nếu đặt).
    """

    def __init__(self, directory: str | os.PathLike = "keys", passphrase: bytes | None = None):
        self.dir = Path(directory)
        if passphrase is None and os.environ.get("KEY_PASSPHRASE"):
            passphrase = os.environ["KEY_PASSPHRASE"].encode("utf-8")
        self.passphrase = passphrase

    def _priv(self, party: str) -> Path:
        return self.dir / f"{party}_private.pem"

    def _pub(self, party: str) -> Path:
        return self.dir / f"{party}_public.pem"

    def exists(self, party: str) -> bool:
        return self._priv(party).exists() and self._pub(party).exists()

    def generate(self, party: str, overwrite: bool = False) -> rsa.RSAPublicKey:
        if self.exists(party) and not overwrite:
            raise FileExistsError(f"Đã có khóa cho '{party}' trong {self.dir}")
        self.dir.mkdir(parents=True, exist_ok=True)
        key = generate_rsa_keypair()
        self._priv(party).write_bytes(private_key_to_pem(key, self.passphrase))
        self._pub(party).write_bytes(public_key_to_pem(key))
        return key.public_key()

    def private_key(self, party: str) -> rsa.RSAPrivateKey:
        return load_private_key(self._priv(party).read_bytes(), self.passphrase)

    def public_key(self, party: str) -> rsa.RSAPublicKey:
        return load_public_key(self._pub(party).read_bytes())

    def public_keys(self, parties: list[str] | tuple[str, ...]) -> dict[str, rsa.RSAPublicKey]:
        return {p: self.public_key(p) for p in parties}
