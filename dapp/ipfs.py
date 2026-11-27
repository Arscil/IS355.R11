"""
Module IPFS (Giai đoạn 5 – tiêu chí 3 của rubric).

- `PinataIPFS`: upload (pin) file/JSON lên IPFS qua Pinata và truy xuất qua gateway, có cache cục bộ.
- `MemoryIPFS`: bản giả lập trong bộ nhớ, cùng giao diện, dùng cho unit test (không cần mạng).

Mọi dữ liệu nhạy cảm đều được mã hóa (dapp.crypto) TRƯỚC khi upload; IPFS là mạng công khai,
ai có CID cũng tải được bản mã, nhưng không có khóa thì không đọc được.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Protocol

import requests

PINATA_API = "https://api.pinata.cloud"
DEFAULT_GATEWAYS = (
    "https://gateway.pinata.cloud/ipfs",
    "https://ipfs.io/ipfs",
    "https://dweb.link/ipfs",
)


class IPFSError(Exception):
    pass


class IPFSStore(Protocol):
    def add_bytes(self, data: bytes, name: str, content_type: str = "application/octet-stream") -> str: ...
    def add_json(self, obj: Any, name: str) -> str: ...
    def get_bytes(self, cid: str) -> bytes: ...
    def get_json(self, cid: str) -> Any: ...


def strip_ipfs_uri(cid_or_uri: str) -> str:
    """'ipfs://Qm…/x' -> 'Qm…/x'."""
    return cid_or_uri[len("ipfs://"):] if cid_or_uri.startswith("ipfs://") else cid_or_uri


def gateway_url(cid: str, gateway: str = DEFAULT_GATEWAYS[0]) -> str:
    return f"{gateway.rstrip('/')}/{strip_ipfs_uri(cid)}"


def _json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


class PinataIPFS:
    """Upload qua Pinata (JWT), tải về qua gateway (ưu tiên gateway riêng nếu có)."""

    def __init__(
        self,
        jwt: str | None = None,
        gateway: str | None = None,
        cache_dir: str | os.PathLike | None = ".ipfs_cache",
        timeout: int = 60,
        retries: int = 3,
    ):
        self.jwt = jwt or os.environ.get("PINATA_JWT", "")
        if not self.jwt:
            raise IPFSError("Thiếu PINATA_JWT trong .env")
        gw = gateway or os.environ.get("PINATA_GATEWAY") or DEFAULT_GATEWAYS[0]
        if not gw.rstrip("/").endswith("/ipfs"):
            gw = gw.rstrip("/") + "/ipfs"
        self.gateways = [gw] + [g for g in DEFAULT_GATEWAYS if g != gw]
        self.cache = Path(cache_dir) if cache_dir else None
        self.timeout = timeout
        self.retries = retries
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Bearer {self.jwt}"

    # ------------------------------------------------------------------ upload
    def _post(self, path: str, **kwargs) -> dict:
        last = None
        for attempt in range(self.retries):
            try:
                r = self.session.post(f"{PINATA_API}{path}", timeout=self.timeout, **kwargs)
                if r.status_code == 200:
                    return r.json()
                last = IPFSError(f"Pinata {path} trả về {r.status_code}: {r.text[:200]}")
                if r.status_code < 500 and r.status_code != 429:
                    break
            except requests.RequestException as exc:
                last = IPFSError(f"Lỗi mạng khi gọi Pinata: {exc}")
            time.sleep(1.5 * (attempt + 1))
        raise last  # type: ignore[misc]

    def add_bytes(self, data: bytes, name: str, content_type: str = "application/octet-stream") -> str:
        res = self._post(
            "/pinning/pinFileToIPFS",
            files={"file": (name, data, content_type)},
            data={"pinataMetadata": json.dumps({"name": name}), "pinataOptions": json.dumps({"cidVersion": 1})},
        )
        cid = res["IpfsHash"]
        self._cache_put(cid, data)
        return cid

    def add_json(self, obj: Any, name: str) -> str:
        res = self._post(
            "/pinning/pinJSONToIPFS",
            json={"pinataContent": obj, "pinataMetadata": {"name": name}, "pinataOptions": {"cidVersion": 1}},
        )
        cid = res["IpfsHash"]
        self._cache_put(cid, _json_bytes(obj))  # chỉ để đọc lại nhanh; CID vẫn do Pinata tính
        return cid

    def unpin(self, cid: str) -> None:
        r = self.session.delete(f"{PINATA_API}/pinning/unpin/{strip_ipfs_uri(cid)}", timeout=self.timeout)
        if r.status_code not in (200, 404):
            raise IPFSError(f"Unpin thất bại {r.status_code}: {r.text[:200]}")

    # ------------------------------------------------------------------ retrieve
    def _cache_path(self, cid: str) -> Path | None:
        if not self.cache:
            return None
        return self.cache / hashlib.sha256(cid.encode()).hexdigest()

    def _cache_put(self, cid: str, data: bytes) -> None:
        p = self._cache_path(cid)
        if p:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)

    def get_bytes(self, cid: str, use_cache: bool = True) -> bytes:
        cid = strip_ipfs_uri(cid)
        p = self._cache_path(cid)
        if use_cache and p and p.exists():
            return p.read_bytes()
        errors = []
        for gw in self.gateways:
            for attempt in range(self.retries):
                try:
                    # Không gửi JWT tới gateway công cộng
                    r = requests.get(gateway_url(cid, gw), timeout=self.timeout)
                    if r.status_code == 200:
                        self._cache_put(cid, r.content)
                        return r.content
                    errors.append(f"{gw}: {r.status_code}")
                    if r.status_code not in (429, 500, 502, 503, 504):
                        break
                except requests.RequestException as exc:
                    errors.append(f"{gw}: {exc.__class__.__name__}")
                time.sleep(1.5 * (attempt + 1))
        raise IPFSError(f"Không tải được {cid} từ gateway nào: {errors}")

    def get_json(self, cid: str) -> Any:
        return json.loads(self.get_bytes(cid).decode("utf-8"))


class MemoryIPFS:
    """IPFS giả lập: CID = 'mem' + sha256 nội dung (giữ tính chất content-addressed)."""

    def __init__(self):
        self.blobs: dict[str, bytes] = {}
        self.names: dict[str, str] = {}

    def _put(self, data: bytes, name: str) -> str:
        cid = "mem" + hashlib.sha256(data).hexdigest()[:43]
        self.blobs[cid] = data
        self.names[cid] = name
        return cid

    def add_bytes(self, data: bytes, name: str, content_type: str = "application/octet-stream") -> str:
        return self._put(data, name)

    def add_json(self, obj: Any, name: str) -> str:
        return self._put(_json_bytes(obj), name)

    def get_bytes(self, cid: str) -> bytes:
        cid = strip_ipfs_uri(cid)
        if cid not in self.blobs:
            raise IPFSError(f"Không tìm thấy {cid}")
        return self.blobs[cid]

    def get_json(self, cid: str) -> Any:
        return json.loads(self.get_bytes(cid).decode("utf-8"))
