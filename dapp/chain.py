"""
Lớp kết nối chain bằng Web3.py.

- Đọc địa chỉ contract + ABI từ deployments/<network>.json và deployments/abi/.
- Ký giao dịch bằng private key của từng vai trò (lấy từ .env).
- LUÔN giả lập giao dịch (eth_call) trước khi gửi: nếu contract sẽ revert thì báo lỗi rõ ràng
  mà không tốn gas và không tạo "giao dịch lỗi" khi demo (rubric: ≤ 1 lỗi giao dịch).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Any

from eth_account import Account
from web3 import Web3
from web3.exceptions import ContractLogicError

ROOT = Path(__file__).resolve().parent.parent
DEPLOY_DIR = ROOT / "deployments"

ROLE_ENV_KEYS = {
    "admin": "PRIVATE_KEY_ADMIN",
    "importer": "PRIVATE_KEY_IMPORTER",
    "issuing_bank": "PRIVATE_KEY_ISSUING_BANK",
    "exporter": "PRIVATE_KEY_EXPORTER",
    "advising_bank": "PRIVATE_KEY_ADVISING_BANK",
}

# Tên vai trò trong contract (bytes32 = keccak256(tên))
ROLE_IDS = {
    "importer": Web3.keccak(text="IMPORTER_ROLE"),
    "issuing_bank": Web3.keccak(text="ISSUING_BANK_ROLE"),
    "exporter": Web3.keccak(text="EXPORTER_ROLE"),
    "advising_bank": Web3.keccak(text="ADVISING_BANK_ROLE"),
}


class LCState(IntEnum):
    Created = 0
    Issued = 1
    Shipped = 2
    Paid = 3
    Closed = 4
    Rejected = 5
    Cancelled = 6


@dataclass
class LetterOfCredit:
    id: int
    importer: str
    issuing_bank: str
    exporter: str
    advising_bank: str
    amount: int
    deadline: int
    state: LCState
    encrypted_terms: str
    doc_cids: list[str]
    doc_hashes: list[str]
    invoice_amount: int
    submitted_at: int
    bl_nft_id: int
    discrepancy_count: int
    reject_reason: str
    discrepancy_note: str

    @classmethod
    def from_tuple(cls, t) -> "LetterOfCredit":
        return cls(
            id=t[0], importer=t[1], issuing_bank=t[2], exporter=t[3], advising_bank=t[4],
            amount=t[5], deadline=t[6], state=LCState(t[7]), encrypted_terms=t[8],
            doc_cids=list(t[9]), doc_hashes=["0x" + bytes(h).hex() for h in t[10]],
            invoice_amount=t[11], submitted_at=t[12], bl_nft_id=t[13], discrepancy_count=t[14],
            reject_reason=t[15], discrepancy_note=t[16],
        )

    def party_of(self, address: str) -> str | None:
        """Vai trò của `address` trong L/C này (None nếu không phải một bên)."""
        a = address.lower()
        for name, addr in (
            ("importer", self.importer),
            ("issuing_bank", self.issuing_bank),
            ("exporter", self.exporter),
            ("advising_bank", self.advising_bank),
        ):
            if addr.lower() == a:
                return name
        return None


class TxError(Exception):
    """Giao dịch bị contract từ chối (phát hiện khi giả lập, chưa gửi lên chain)."""


def _decode_revert(exc: Exception, contracts) -> str:
    msg = getattr(exc, "message", None) or str(exc)
    data = getattr(exc, "data", None)
    if isinstance(data, str) and data.startswith("0x") and len(data) >= 10:
        for c in contracts:
            for item in c.abi:
                if item.get("type") != "error":
                    continue
                sig = f"{item['name']}({','.join(i['type'] for i in item['inputs'])})"
                if Web3.keccak(text=sig)[:4].hex() == data[2:10].lower():
                    return item["name"]
    return msg.replace("execution reverted: ", "")


class Chain:
    def __init__(self, network: str | None = None, rpc_url: str | None = None):
        self.network = network or os.environ.get("NETWORK", "sepolia")
        dep_file = DEPLOY_DIR / f"{self.network}.json"
        if not dep_file.exists():
            raise FileNotFoundError(f"Chưa có {dep_file}. Chạy script deploy trước.")
        self.deployment = json.loads(dep_file.read_text(encoding="utf-8"))

        if rpc_url is None:
            rpc_url = os.environ.get("SEPOLIA_RPC_URL") if self.network == "sepolia" else "http://127.0.0.1:8545"
        self.w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 60}))
        self.chain_id = self.deployment["chainId"]

        def load(name):
            abi = json.loads((DEPLOY_DIR / "abi" / f"{name}.json").read_text(encoding="utf-8"))
            return self.w3.eth.contract(address=self.deployment["contracts"][name], abi=abi)

        self.lc = load("TradeFinanceLC")
        self.token = load("StableToken")
        self.nft = load("BillOfLadingNFT")
        gp = os.environ.get("SEPOLIA_GAS_PRICE_GWEI") if self.network == "sepolia" else None
        self.gas_price = Web3.to_wei(gp, "gwei") if gp else None
        # Block của giao dịch gần nhất app gửi: mọi lần đọc sau đó phải nhìn thấy ít nhất block này
        # (RPC cân bằng tải có thể trả dữ liệu từ node chậm hơn vài block).
        self.min_block = 0

    def _read(self, fn, retries: int = 8):
        """Đọc contract tại block >= min_block; thử lại nếu node chưa có block đó."""
        import time as _t

        if not self.min_block:
            return fn.call()
        last = None
        for _ in range(retries):
            try:
                head = self.w3.eth.block_number
                return fn.call(block_identifier=max(head, self.min_block))
            except ContractLogicError:
                raise
            except Exception as exc:  # node chưa có block min_block
                last = exc
                _t.sleep(1.5)
        raise last

    # ------------------------------------------------------------------ accounts
    def account(self, role: str):
        key = os.environ.get(ROLE_ENV_KEYS[role], "").strip()
        if not key:
            raise KeyError(f"Thiếu {ROLE_ENV_KEYS[role]} trong .env")
        return Account.from_key(key)

    def address(self, role: str) -> str:
        return self.deployment["accounts"].get(
            {"issuing_bank": "issuingBank", "advising_bank": "advisingBank"}.get(role, role)
        ) or self.account(role).address

    # ------------------------------------------------------------------ reads
    def get_lc(self, lc_id: int) -> LetterOfCredit:
        return LetterOfCredit.from_tuple(self._read(self.lc.functions.getLC(lc_id)))

    def has_role(self, role: str, address: str) -> bool:
        return self._read(self.lc.functions.hasRole(ROLE_IDS[role], Web3.to_checksum_address(address)))

    def lc_count(self) -> int:
        return self._read(self.lc.functions.getLCCount())

    def lcs_of(self, address: str) -> list[int]:
        return list(self._read(self.lc.functions.getLCsByParty(Web3.to_checksum_address(address))))

    def token_balance(self, address: str) -> int:
        return self._read(self.token.functions.balanceOf(Web3.to_checksum_address(address)))

    def nft_owner(self, token_id: int) -> str:
        return self._read(self.nft.functions.ownerOf(token_id))

    def eth_balance(self, address: str) -> int:
        return self.w3.eth.get_balance(Web3.to_checksum_address(address))

    def allowance(self, owner: str) -> int:
        return self._read(self.token.functions.allowance(Web3.to_checksum_address(owner), self.lc.address))

    def ebls_of(self, address: str) -> list[int]:
        """Các eBL NFT `address` đang giữ (duyệt các L/C mà address là Importer)."""
        out = []
        for lc_id in self.lcs_of(address):
            lc = self.get_lc(lc_id)
            if lc.bl_nft_id and lc.state in (LCState.Paid, LCState.Closed):
                try:
                    if self.nft_owner(lc.bl_nft_id).lower() == address.lower():
                        out.append(lc.bl_nft_id)
                except ContractLogicError:
                    pass
        return out

    # ------------------------------------------------------------------ lịch sử event
    def lc_events(self, lc_id: int) -> list[dict]:
        """
        Lịch sử event của một L/C (lcId là topic đầu tiên của mọi event).
        Sepolia: dùng Etherscan API (RPC gói Free giới hạn khoảng block của eth_getLogs).
        Local: dùng eth_getLogs trực tiếp.
        """
        topic1 = "0x" + int(lc_id).to_bytes(32, "big").hex()
        raw = self._logs_etherscan(topic1) if self.network == "sepolia" else self._logs_rpc(topic1)
        by_topic = {}
        for item in self.lc.abi:
            if item.get("type") == "event":
                sig = f"{item['name']}({','.join(i['type'] for i in item['inputs'])})"
                by_topic[Web3.keccak(text=sig).hex().removeprefix("0x")] = item["name"]
        events = []
        for log in raw:
            name = by_topic.get(bytes(log["topics"][0]).hex())
            if not name:
                continue
            decoded = getattr(self.lc.events, name)().process_log(log)
            events.append({
                "event": name,
                "args": dict(decoded["args"]),
                "block": log["blockNumber"],
                "tx": "0x" + bytes(log["transactionHash"]).hex().removeprefix("0x"),
                "time": log.get("timeStamp"),
            })
        return sorted(events, key=lambda e: (e["block"]))

    def _logs_rpc(self, topic1: str) -> list:
        return self.w3.eth.get_logs({
            "address": self.lc.address,
            "fromBlock": self.deployment.get("startBlock", 0),
            "toBlock": "latest",
            "topics": [None, topic1],
        })

    def _logs_etherscan(self, topic1: str) -> list:
        import requests
        from hexbytes import HexBytes

        r = requests.get("https://api.etherscan.io/v2/api", params={
            "chainid": self.chain_id, "module": "logs", "action": "getLogs",
            "address": self.lc.address, "fromBlock": self.deployment.get("startBlock", 0),
            "toBlock": "latest", "topic1": topic1, "apikey": os.environ.get("ETHERSCAN_API_KEY", ""),
        }, timeout=30)
        body = r.json()
        if body.get("status") != "1":
            if "No records" in str(body.get("message")):
                return []
            raise RuntimeError(f"Etherscan getLogs lỗi: {body.get('message')} {str(body.get('result'))[:120]}")
        out = []
        for l in body["result"]:
            out.append({
                "address": Web3.to_checksum_address(l["address"]),
                "topics": [HexBytes(t) for t in l["topics"] if t],
                "data": HexBytes(l["data"]),
                "blockNumber": int(l["blockNumber"], 16),
                "transactionHash": HexBytes(l["transactionHash"]),
                "transactionIndex": int(l["transactionIndex"] or "0x0", 16),
                "blockHash": HexBytes(l.get("blockHash") or "0x" + "00" * 32),
                "logIndex": int(l["logIndex"] or "0x0", 16),
                "timeStamp": int(l["timeStamp"], 16),
            })
        return out

    # ------------------------------------------------------------------ writes
    def simulate(self, role: str, fn) -> Any:
        """Giả lập (eth_call) bằng ví `role`. Ném TxError nếu contract sẽ revert."""
        try:
            frm = {"from": self.account(role).address}
            if self.min_block:
                head = self.w3.eth.block_number
                return fn.call(frm, block_identifier=max(head, self.min_block))
            return fn.call(frm)
        except ContractLogicError as exc:
            raise TxError(_decode_revert(exc, (self.lc, self.token, self.nft))) from exc

    def send(self, role: str, fn, wait: bool = True) -> dict:
        """Giả lập rồi mới ký và gửi giao dịch. Trả về {'hash', 'receipt', 'result'}."""
        acct = self.account(role)
        result = self.simulate(role, fn)
        tx_params = {
            "from": acct.address,
            "nonce": self.w3.eth.get_transaction_count(acct.address, "pending"),
            "chainId": self.chain_id,
        }
        if self.gas_price:
            tx_params["gasPrice"] = self.gas_price
        tx = fn.build_transaction(tx_params)
        tx["gas"] = int(tx["gas"] * 1.2)
        signed = acct.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        out = {"hash": "0x" + bytes(tx_hash).hex().removeprefix("0x"), "result": result, "receipt": None}
        if wait:
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
            if receipt.status != 1:
                raise TxError(f"Giao dịch {out['hash']} thất bại trên chain")
            self.min_block = max(self.min_block, receipt.blockNumber)
            out["receipt"] = receipt
        return out

    def explorer_tx(self, tx_hash: str) -> str:
        return f"https://sepolia.etherscan.io/tx/{tx_hash}" if self.network == "sepolia" else tx_hash
