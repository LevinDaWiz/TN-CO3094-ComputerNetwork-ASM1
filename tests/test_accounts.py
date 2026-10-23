"""Kiểm thử Việc 2: tài khoản demo và hash mật khẩu (``sessions.py``).

Chạy từ thư mục gốc repo::

    python -m unittest discover -s . -v
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

import make_accounts  # noqa: E402
import sessions  # noqa: E402
from protocol import AppError  # noqa: E402
from sessions import (Account, AccountStore, hash_password,  # noqa: E402
                      parse_password_hash, verify_password)

FAST = 1_000   # số vòng PBKDF2 nhỏ cho test tổng hợp


def run_tool(*args):
    """Chạy make_accounts.main, gom output vào bộ nhớ (không phụ thuộc bảng mã console)."""
    with contextlib.redirect_stdout(io.StringIO()):
        return make_accounts.main(list(args))


def fast_store(n=3):
    return AccountStore(Account(f"u{i:02d}", f"user{i:02d}",
                                hash_password(f"pass{i:02d}", iterations=FAST))
                        for i in range(1, n + 1))


class PasswordHashTests(unittest.TestCase):
    def test_format_and_roundtrip(self):
        h = hash_password("pass01", iterations=FAST)
        self.assertTrue(h.startswith("pbkdf2_sha256$1000$"))
        iterations, salt, digest = parse_password_hash(h)
        self.assertEqual((iterations, len(salt), len(digest)), (FAST, 16, 32))
        self.assertTrue(verify_password("pass01", h))
        self.assertFalse(verify_password("pass02", h))
        self.assertFalse(verify_password("", h))

    def test_salt_is_random_per_hash(self):
        a = hash_password("pass01", iterations=FAST)
        b = hash_password("pass01", iterations=FAST)
        self.assertNotEqual(a, b)
        self.assertNotEqual(parse_password_hash(a)[1], parse_password_hash(b)[1])

    def test_unicode_password(self):
        h = hash_password("mật khẩu ✓", iterations=FAST)
        self.assertTrue(verify_password("mật khẩu ✓", h))
        self.assertFalse(verify_password("mat khau", h))

    def test_tampered_or_malformed_hash(self):
        h = hash_password("pass01", iterations=FAST)
        scheme, it, salt, digest = h.split("$")
        flipped = ("A" if digest[0] != "A" else "B") + digest[1:]
        for bad in (f"{scheme}${it}${salt}${flipped}",
                    f"md5${it}${salt}${digest}",
                    f"{scheme}$10${salt}${digest}",
                    f"{scheme}${it}$!!!${digest}",
                    "pbkdf2_sha256$abc", "", None):
            self.assertFalse(verify_password("pass01", bad), bad)

    def test_rejects_too_few_iterations(self):
        with self.assertRaises(ValueError):
            hash_password("x", iterations=10)


class AccountStoreTests(unittest.TestCase):
    def setUp(self):
        self.store = fast_store()

    def test_verify_ok(self):
        acc = self.store.verify("user02", "pass02")
        self.assertEqual((acc.user_id, acc.username), ("u02", "user02"))

    def test_wrong_password_and_unknown_user_same_error(self):
        errors = []
        for username, password in (("user01", "sai"), ("nobody", "pass01"),
                                   ("user01", ""), ("USER01", "pass01"), ("", "")):
            with self.assertRaises(AppError) as cm:
                self.store.verify(username, password)
            errors.append((cm.exception.code, cm.exception.message))
        # Mọi trường hợp cùng mã và cùng thông báo, không lộ tài khoản tồn tại.
        self.assertEqual(len(set(errors)), 1)
        self.assertEqual(errors[0][0], "INVALID_CREDENTIALS")

    def test_non_string_or_huge_input(self):
        for username, password in ((None, "x"), ("user01", None), ("user01", "x" * 2000)):
            with self.assertRaises(AppError):
                self.store.verify(username, password)

    def test_lookup_helpers(self):
        self.assertEqual(self.store.get_by_user_id("u03").username, "user03")
        self.assertEqual(self.store.get_by_username("user03").user_id, "u03")
        self.assertIsNone(self.store.get_by_user_id("u99"))
        self.assertEqual(len(self.store), 3)

    def test_repr_hides_hash(self):
        acc = self.store.get_by_user_id("u01")
        self.assertNotIn("pbkdf2", repr(acc))

    def test_invalid_accounts_rejected(self):
        h = hash_password("x", iterations=FAST)
        cases = [
            [Account("u01", "a", h), Account("u02", "a", h)],         # trùng username
            [Account("u01", "a", h), Account("u01", "b", h)],         # trùng user_id
            [Account("ú01", "a", h)],                                 # user_id không ASCII
            [Account("u" * 33, "a", h)],                              # user_id > 32 ký tự
            [Account("u 1", "a", h)],                                 # có khoảng trắng
            [Account("u01", "", h)],                                  # username rỗng
            [Account("u01", " a", h)],                                # khoảng trắng đầu
            [Account("u01", "a" * 65, h)],                            # username > 64 byte
            [Account("u01", "a", "plaintext")],                       # hash sai định dạng
        ]
        for accounts in cases:
            with self.assertRaises(ValueError, msg=repr(accounts)):
                AccountStore(accounts)

    def test_concurrent_verify(self):
        results, lock = [], threading.Lock()

        def worker(i):
            n = i % 3 + 1
            acc = self.store.verify(f"user{n:02d}", f"pass{n:02d}")
            with lock:
                results.append(acc.user_id)
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(30)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(set(results)), ["u01", "u02", "u03"])
        self.assertEqual(len(results), 30)


class AccountsFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "accounts.json")

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, data):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(data if isinstance(data, str) else json.dumps(data))

    def test_make_accounts_tool(self):
        self.assertEqual(run_tool("--out", self.path, "--count", "5", "--iterations", str(FAST)), 0)
        store = AccountStore.from_file(self.path)
        self.assertEqual(len(store), 5)
        self.assertEqual(store.verify("user05", "pass05").user_id, "u05")
        # Không ghi đè khi thiếu --force.
        self.assertEqual(run_tool("--out", self.path, "--iterations", str(FAST)), 1)
        self.assertEqual(len(AccountStore.from_file(self.path)), 5)

    def test_bad_files(self):
        h = hash_password("x", iterations=FAST)
        for content in ("{not json",
                        {"version": 2, "accounts": [{"user_id": "u01", "username": "a",
                                                     "password_hash": h}]},
                        {"version": 1, "accounts": []},
                        {"version": 1, "accounts": ["u01"]},
                        {"version": 1, "accounts": [{"user_id": "u01", "username": "a"}]}):
            self.write(content)
            with self.assertRaises(ValueError, msg=repr(content)):
                AccountStore.from_file(self.path)

    def test_load_accounts_sets_default_store(self):
        run_tool("--out", self.path, "--count", "2", "--iterations", str(FAST))
        old = sessions._store
        try:
            store = sessions.load_accounts(self.path)
            self.assertIs(sessions.get_account_store(), store)
        finally:
            sessions._store = old


class RealAccountsFileTests(unittest.TestCase):
    """Kiểm tra file ``accounts.json`` thật trong repo (dùng khi demo)."""

    @classmethod
    def setUpClass(cls):
        cls.store = AccountStore.from_file(sessions.ACCOUNTS_FILE)
        with open(sessions.ACCOUNTS_FILE, encoding="utf-8") as f:
            cls.raw = f.read()
            cls.rows = json.loads(cls.raw)["accounts"]

    def test_twenty_demo_accounts(self):
        self.assertEqual(len(self.store), 20)
        self.assertEqual([r["user_id"] for r in self.rows],
                         [f"u{i:02d}" for i in range(1, 21)])
        self.assertEqual([r["username"] for r in self.rows],
                         [f"user{i:02d}" for i in range(1, 21)])

    def test_no_plaintext_and_unique_salts(self):
        for i in range(1, 21):
            self.assertNotIn(f'"pass{i:02d}"', self.raw)
        salts = {parse_password_hash(r["password_hash"])[1] for r in self.rows}
        self.assertEqual(len(salts), 20)
        for r in self.rows:
            self.assertGreaterEqual(parse_password_hash(r["password_hash"])[0],
                                    sessions.DEFAULT_ITERATIONS)

    def test_demo_passwords_documented(self):
        # Kiểm tra vài tài khoản (mỗi lần ~0,1 s vì 600k vòng).
        for i in (1, 10, 20):
            self.assertEqual(self.store.verify(f"user{i:02d}", f"pass{i:02d}").user_id,
                             f"u{i:02d}")
        with self.assertRaises(AppError):
            self.store.verify("user01", "pass02")

    def test_unknown_user_takes_similar_time(self):
        # Username không tồn tại vẫn chạy PBKDF2 với hash giả (chống dò tài khoản).
        def timed(username, password):
            t = time.perf_counter()
            with self.assertRaises(AppError):
                self.store.verify(username, password)
            return time.perf_counter() - t
        wrong_pw = min(timed("user01", "sai") for _ in range(3))
        unknown = min(timed("khongco", "sai") for _ in range(3))
        self.assertGreater(unknown, wrong_pw * 0.5)


if __name__ == "__main__":
    unittest.main()
