import json

import pytest

from dapp import crypto
from dapp.crypto import DecryptionError, Envelope, KeyStore


# --------------------------------------------------------------------------- fixtures
@pytest.fixture(scope="module")
def keys():
    """Cặp khóa RSA cho 4 bên + 1 người ngoài (sinh 1 lần cho cả module vì RSA chậm)."""
    names = ["importer", "issuing_bank", "exporter", "advising_bank", "outsider"]
    return {n: crypto.generate_rsa_keypair() for n in names}


@pytest.fixture
def parties(keys):
    return {n: k.public_key() for n, k in keys.items() if n != "outsider"}


SAMPLE_PDF = b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n" + bytes(range(256)) * 50 + b"\n%%EOF"


# --------------------------------------------------------------------------- SHA-256
def test_sha256_matches_known_vector_and_bytes32_format():
    # Vector chuẩn FIPS 180-2 cho "abc"; cùng giá trị với ethers.sha256(toUtf8Bytes("abc"))
    h = crypto.sha256_hex(b"abc")
    assert h == "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert len(h) == 66  # "0x" + 64 hex = bytes32


def test_sha256_file(tmp_path):
    p = tmp_path / "bl.pdf"
    p.write_bytes(SAMPLE_PDF)
    assert crypto.sha256_file(p) == crypto.sha256_hex(SAMPLE_PDF)


# --------------------------------------------------------------------------- AES-GCM
def test_aes_roundtrip_and_random_nonce():
    key = crypto.generate_aes_key()
    n1, c1 = crypto.aes_encrypt(key, b"secret", b"ctx")
    n2, c2 = crypto.aes_encrypt(key, b"secret", b"ctx")
    assert n1 != n2 and c1 != c2  # cùng dữ liệu nhưng bản mã khác nhau
    assert crypto.aes_decrypt(key, n1, c1, b"ctx") == b"secret"


def test_aes_rejects_wrong_key_length():
    with pytest.raises(ValueError):
        crypto.aes_encrypt(b"short", b"x")


@pytest.mark.parametrize("mutate", ["ciphertext", "aad", "key"])
def test_aes_detects_tampering(mutate):
    key = crypto.generate_aes_key()
    nonce, ct = crypto.aes_encrypt(key, b"Amount: 50000 USD", b"lc:1:terms")
    aad = b"lc:1:terms"
    if mutate == "ciphertext":
        ct = bytes([ct[0] ^ 1]) + ct[1:]
    elif mutate == "aad":
        aad = b"lc:2:terms"
    else:
        key = crypto.generate_aes_key()
    with pytest.raises(DecryptionError):
        crypto.aes_decrypt(key, nonce, ct, aad)


# --------------------------------------------------------------------------- RSA-OAEP
def test_rsa_wrap_unwrap(keys):
    aes_key = crypto.generate_aes_key()
    wrapped = crypto.wrap_key(keys["importer"].public_key(), aes_key)
    assert len(wrapped) == 256  # RSA-2048
    assert crypto.unwrap_key(keys["importer"], wrapped) == aes_key
    with pytest.raises(DecryptionError):
        crypto.unwrap_key(keys["exporter"], wrapped)


def test_pem_roundtrip_with_passphrase(keys):
    k = keys["issuing_bank"]
    pem = crypto.private_key_to_pem(k, b"pass123")
    assert b"ENCRYPTED" in pem
    loaded = crypto.load_private_key(pem, b"pass123")
    assert crypto.fingerprint(loaded.public_key()) == crypto.fingerprint(k.public_key())
    with pytest.raises((ValueError, TypeError)):
        crypto.load_private_key(pem, b"wrong")
    pub = crypto.load_public_key(crypto.public_key_to_pem(k))
    assert crypto.fingerprint(pub) == crypto.fingerprint(k.public_key())


# --------------------------------------------------------------------------- Envelope / RBAC
def test_every_authorized_party_can_open(keys, parties):
    env = crypto.seal(b"hello", parties, "lc:1:test")
    assert env.recipient_ids() == sorted(parties)
    for name in parties:
        assert crypto.open_envelope(env, name, keys[name]) == b"hello"


def test_outsider_cannot_open(keys, parties):
    env = crypto.seal(b"hello", parties, "lc:1:test")
    with pytest.raises(DecryptionError, match="không có quyền"):
        crypto.open_envelope(env, "outsider", keys["outsider"])


def test_party_not_in_recipient_list_cannot_open(keys):
    # Exporter không được đọc điều khoản giá nội bộ giữa Importer và Issuing Bank
    recipients = {"importer": keys["importer"].public_key(), "issuing_bank": keys["issuing_bank"].public_key()}
    env = crypto.seal(b"internal credit terms", recipients, "lc:1:terms")
    with pytest.raises(DecryptionError):
        crypto.open_envelope(env, "exporter", keys["exporter"])


def test_stolen_identity_with_wrong_private_key_fails(keys, parties):
    env = crypto.seal(b"hello", parties, "lc:1:test")
    with pytest.raises(DecryptionError, match="không khớp"):
        crypto.open_envelope(env, "importer", keys["outsider"])


def test_envelope_json_roundtrip_and_tamper_detection(keys, parties):
    env = crypto.seal(b"payload", parties, "lc:7:test")
    text = env.to_json()
    restored = Envelope.from_json(text)
    assert crypto.open_envelope(restored, "advising_bank", keys["advising_bank"]) == b"payload"

    d = json.loads(text)
    d["aad"] = "lc:8:test"  # cố tình đổi ngữ cảnh
    with pytest.raises(DecryptionError):
        crypto.open_envelope(Envelope.from_dict(d), "advising_bank", keys["advising_bank"])


def test_envelope_rejects_unknown_version(parties):
    d = crypto.seal(b"x", parties, "lc:1:t").to_dict()
    d["version"] = 99
    with pytest.raises(ValueError):
        Envelope.from_dict(d)


def test_seal_requires_recipients_and_aad(parties):
    with pytest.raises(ValueError):
        crypto.seal(b"x", {}, "lc:1:t")
    with pytest.raises(ValueError):
        crypto.seal(b"x", parties, "")


# --------------------------------------------------------------------------- nghiệp vụ L/C
def test_terms_roundtrip(keys, parties):
    terms = {"goods": "Cà phê Robusta", "quantity": "20 tấn", "unit_price": 2500, "incoterm": "FOB HCM"}
    env = crypto.seal_terms(terms, parties, "1")
    assert env.content_type == "application/json"
    assert crypto.open_terms(env, "exporter", keys["exporter"], "1") == terms
    with pytest.raises(DecryptionError, match="Sai ngữ cảnh"):
        crypto.open_terms(env, "exporter", keys["exporter"], "2")


def test_document_roundtrip_and_onchain_hash_check(keys, parties):
    env, h = crypto.seal_document(SAMPLE_PDF, "BL", parties, "1", filename="bill_of_lading.pdf")
    assert h == crypto.sha256_hex(SAMPLE_PDF)
    assert env.filename == "bill_of_lading.pdf"

    data = crypto.open_document(env, "BL", "advising_bank", keys["advising_bank"], "1", expected_sha256=h)
    assert data == SAMPLE_PDF

    with pytest.raises(DecryptionError, match="không khớp với hash on-chain"):
        crypto.open_document(
            env, "BL", "advising_bank", keys["advising_bank"], "1", expected_sha256=crypto.sha256_hex(b"other")
        )


def test_documents_cannot_be_swapped_between_types(keys, parties):
    env_invoice, _ = crypto.seal_document(b"invoice", "INVOICE", parties, "1")
    with pytest.raises(DecryptionError):
        crypto.open_document(env_invoice, "BL", "importer", keys["importer"], "1")


def test_invalid_doc_type(parties):
    with pytest.raises(ValueError):
        crypto.seal_document(b"x", "PACKING_LIST", parties, "1")


# --------------------------------------------------------------------------- KeyStore
def test_keystore_generate_load_and_no_overwrite(tmp_path):
    store = KeyStore(tmp_path, passphrase=b"demo-pass")
    pub = store.generate("importer")
    assert store.exists("importer")
    assert crypto.fingerprint(store.public_key("importer")) == crypto.fingerprint(pub)
    assert crypto.fingerprint(store.private_key("importer").public_key()) == crypto.fingerprint(pub)
    assert b"ENCRYPTED" in (tmp_path / "importer_private.pem").read_bytes()
    with pytest.raises(FileExistsError):
        store.generate("importer")

    env = crypto.seal(b"x", store.public_keys(["importer"]), "lc:1:t")
    assert crypto.open_envelope(env, "importer", store.private_key("importer")) == b"x"
