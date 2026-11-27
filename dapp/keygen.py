"""
Sinh cặp khóa RSA-2048 cho 4 bên của L/C.

    python -m dapp.keygen            # tạo khóa còn thiếu trong thư mục keys/
    python -m dapp.keygen --force    # tạo lại toàn bộ (dữ liệu mã hóa cũ sẽ không mở được nữa)

Đặt KEY_PASSPHRASE trong .env để mã hóa file private key.
"""

import argparse

from dotenv import load_dotenv

from .crypto import KeyStore, fingerprint

PARTIES = ("importer", "issuing_bank", "exporter", "advising_bank")


def main() -> None:
    import sys

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # console Windows mặc định cp1252
    load_dotenv()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dir", default="keys")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    store = KeyStore(args.dir)
    for party in PARTIES:
        if store.exists(party) and not args.force:
            print(f"  = {party:14} đã có  (fp {fingerprint(store.public_key(party))})")
            continue
        pub = store.generate(party, overwrite=args.force)
        print(f"  + {party:14} đã tạo (fp {fingerprint(pub)})")
    print(f"Khóa nằm trong {store.dir.resolve()}  (private key đã được .gitignore)")


if __name__ == "__main__":
    main()
