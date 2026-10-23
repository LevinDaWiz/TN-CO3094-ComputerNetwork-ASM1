"""Sinh file ``accounts.json`` chứa các tài khoản demo (chỉ lưu hash mật khẩu).

Tài khoản mặc định: ``user01..user20`` với ``user_id`` ``u01..u20`` và mật khẩu
demo ``pass01..pass20`` (ghi trong 0_HowToRunCode.md để nhóm test; KHÔNG dùng cho hệ thống
thật). Mỗi tài khoản có salt ngẫu nhiên riêng, nên chạy lại script sẽ ra hash
khác nhưng mật khẩu vẫn như cũ.

Ví dụ::

    python tools/make_accounts.py                 # tạo accounts.json (không ghi đè)
    python tools/make_accounts.py --force         # sinh lại, ghi đè file cũ
    python tools/make_accounts.py --count 30 --out /tmp/accounts.json
"""

import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from sessions import (ACCOUNTS_FILE_VERSION, DEFAULT_ITERATIONS, AccountStore,  # noqa: E402
                      hash_password)


def demo_credentials(count: int):
    """Danh sách ``(user_id, username, password)`` của tài khoản demo."""
    return [(f"u{i:02d}", f"user{i:02d}", f"pass{i:02d}") for i in range(1, count + 1)]


def build_accounts(count: int = 20, iterations: int = DEFAULT_ITERATIONS) -> dict:
    """Tạo nội dung JSON (dict) cho ``count`` tài khoản demo."""
    return {
        "version": ACCOUNTS_FILE_VERSION,
        "accounts": [
            {"user_id": uid, "username": name,
             "password_hash": hash_password(pw, iterations=iterations)}
            for uid, name, pw in demo_credentials(count)
        ],
    }


def write_accounts(path: str, data: dict) -> None:
    """Ghi file qua tệp tạm rồi đổi tên, tránh để lại file ghi dở."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, path)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Sinh accounts.json cho tài khoản demo")
    p.add_argument("--out", default=os.path.join(ROOT, "accounts.json"))
    p.add_argument("--count", type=int, default=20, help="số tài khoản (1..99)")
    p.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS,
                   help="số vòng PBKDF2 (mặc định %(default)s)")
    p.add_argument("--force", action="store_true", help="ghi đè nếu file đã có")
    args = p.parse_args(argv)

    if not 1 <= args.count <= 99:
        p.error("--count phải trong 1..99")
    if os.path.exists(args.out) and not args.force:
        print(f"{args.out} đã tồn tại; thêm --force để sinh lại.")
        return 1

    data = build_accounts(args.count, args.iterations)
    write_accounts(args.out, data)
    AccountStore.from_file(args.out)   # tự kiểm tra file vừa ghi nạp được
    print(f"Đã ghi {args.count} tài khoản vào {args.out} "
          f"(user01..user{args.count:02d}, PBKDF2 {args.iterations} vòng).")
    return 0


def _utf8_console():
    """Windows: console/pipe mặc định cp1252, in tiếng Việt sẽ lỗi -> ép UTF-8."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


if __name__ == "__main__":
    _utf8_console()
    sys.exit(main())
