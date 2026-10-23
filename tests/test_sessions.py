"""Kiểm thử Việc 3: registry phiên, authenticate, hết hạn phiên chưa bind.

Chạy từ thư mục gốc repo::

    python -m unittest discover -s . -v
"""

import base64
import inspect
import os
import socket
import sys
import threading
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import sessions  # noqa: E402
from framing import encode_frame, recv_frame  # noqa: E402
from protocol import AppError  # noqa: E402
from server import CollabServer  # noqa: E402
from sessions import Account, AccountStore, SessionManager, hash_password  # noqa: E402

FAST = 1_000


def fast_store(n=20):
    """userNN / passNN, PBKDF2 ít vòng cho test nhanh."""
    return AccountStore(Account(f"u{i:02d}", f"user{i:02d}",
                                hash_password(f"pass{i:02d}", iterations=FAST))
                        for i in range(1, n + 1))


STORE = fast_store()


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class SessionManagerTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.mgr = SessionManager(STORE, clock=self.clock)
        self.removed = []
        self.mgr.on_session_removed(lambda s, reason: self.removed.append((s.user_id, reason)))

    # ----- authenticate ----------------------------------------------------

    def test_authenticate_ok(self):
        s = self.mgr.authenticate("user01", "pass01")
        self.assertEqual((s.user_id, s.username), ("u01", "user01"))
        self.assertIsInstance(s.session_id, int)
        self.assertTrue(0 < s.session_id < 2 ** 64)
        self.assertEqual((len(s.c2s_key), len(s.s2c_key)), (32, 32))
        self.assertEqual((len(s.c2s_nonce_prefix), len(s.s2c_nonce_prefix)), (4, 4))
        self.assertNotEqual(s.c2s_key, s.s2c_key)
        self.assertIsNone(s.udp_addr)
        self.assertFalse(s.bound)
        self.assertEqual((s.created_at, s.last_seen), (1000.0, 1000.0))

    def test_wrong_password_creates_no_session(self):
        with self.assertRaises(AppError) as cm:
            self.mgr.authenticate("user01", "sai")
        self.assertEqual(cm.exception.code, "INVALID_CREDENTIALS")
        self.assertEqual(len(self.mgr), 0)

    def test_already_logged_in(self):
        self.mgr.authenticate("user01", "pass01")
        with self.assertRaises(AppError) as cm:
            self.mgr.authenticate("user01", "pass01")
        self.assertEqual(cm.exception.code, "ALREADY_LOGGED_IN")
        self.assertEqual(len(self.mgr), 1)

    def test_relogin_after_remove_gets_new_id_and_keys(self):
        a = self.mgr.authenticate("user01", "pass01")
        self.mgr.remove_session(a.session_id)
        b = self.mgr.authenticate("user01", "pass01")
        self.assertNotEqual(a.session_id, b.session_id)
        for f in ("c2s_key", "s2c_key", "c2s_nonce_prefix", "s2c_nonce_prefix"):
            self.assertNotEqual(getattr(a, f), getattr(b, f), f)
        self.assertIsNone(self.mgr.get_session(a.session_id))

    def test_session_id_skips_zero_and_duplicates(self):
        first = self.mgr.authenticate("user01", "pass01")
        values = iter([0, first.session_id, 0, 42])
        with mock.patch.object(sessions.secrets, "randbits", side_effect=lambda n: next(values)):
            second = self.mgr.authenticate("user02", "pass02")
        self.assertEqual(second.session_id, 42)

    def test_repr_hides_keys(self):
        s = self.mgr.authenticate("user01", "pass01")
        text = repr(s)
        for f in ("c2s_key", "s2c_key", "c2s_nonce_prefix", "s2c_nonce_prefix"):
            self.assertNotIn(f, text)
        self.assertNotIn(repr(s.c2s_key), text)

    def test_returned_session_is_a_copy(self):
        s = self.mgr.authenticate("user01", "pass01")
        s.bound = True
        s.udp_addr = ("1.2.3.4", 5)
        self.assertFalse(self.mgr.get_session(s.session_id).bound)
        self.assertEqual(self.mgr.list_online_users(), [])

    # ----- bind_udp / list_online_users --------------------------------------

    def test_bind_and_online_list(self):
        a = self.mgr.authenticate("user02", "pass02")
        b = self.mgr.authenticate("user01", "pass01")
        self.assertEqual(self.mgr.list_online_users(), [])   # chưa bind: chưa online
        self.clock.advance(3)
        self.mgr.bind_udp(a.session_id, ("127.0.0.1", 50001))
        got = self.mgr.get_session(a.session_id)
        self.assertTrue(got.bound)
        self.assertEqual(got.udp_addr, ("127.0.0.1", 50001))
        self.assertEqual(got.last_seen, 1003.0)
        self.mgr.bind_udp(b.session_id, ("127.0.0.1", 50002))
        self.assertEqual(self.mgr.list_online_users(),
                         [{"user_id": "u01", "username": "user01"},
                          {"user_id": "u02", "username": "user02"}])

    def test_rebind_same_address_ok_other_address_rejected(self):
        s = self.mgr.authenticate("user01", "pass01")
        self.mgr.bind_udp(s.session_id, ("10.0.0.5", 4000))
        self.mgr.bind_udp(s.session_id, ("10.0.0.5", 4000))   # UDP_BIND truyền lại
        with self.assertRaises(AppError) as cm:
            self.mgr.bind_udp(s.session_id, ("10.0.0.6", 4000))
        self.assertEqual(cm.exception.code, "INVALID_SESSION")
        self.assertEqual(self.mgr.get_session(s.session_id).udp_addr, ("10.0.0.5", 4000))

    def test_bind_unknown_session(self):
        with self.assertRaises(AppError) as cm:
            self.mgr.bind_udp(12345, ("127.0.0.1", 5000))
        self.assertEqual(cm.exception.code, "INVALID_SESSION")

    def test_bind_bad_address(self):
        s = self.mgr.authenticate("user01", "pass01")
        for addr in (None, "127.0.0.1:5000", ("127.0.0.1",), ("127.0.0.1", 0),
                     ("127.0.0.1", 70000), ("", 5000), ("127.0.0.1", "5000"), ("127.0.0.1", True)):
            with self.assertRaises(AppError, msg=repr(addr)) as cm:
                self.mgr.bind_udp(s.session_id, addr)
            self.assertEqual(cm.exception.code, "INVALID_PACKET")
        self.assertFalse(self.mgr.get_session(s.session_id).bound)

    def test_ipv6_address_accepted(self):
        s = self.mgr.authenticate("user01", "pass01")
        self.mgr.bind_udp(s.session_id, ("::1", 5000, 0, 0))
        self.assertTrue(self.mgr.get_session(s.session_id).bound)

    # ----- remove / lookup ------------------------------------------------

    def test_remove_session_idempotent_and_callback(self):
        s = self.mgr.authenticate("user01", "pass01")
        self.mgr.remove_session(s.session_id)
        self.mgr.remove_session(s.session_id)
        self.mgr.remove_session(999)
        self.assertEqual(self.removed, [("u01", "REMOVED")])
        self.assertIsNone(self.mgr.get_session_by_user("u01"))

    def test_get_session_by_user(self):
        s = self.mgr.authenticate("user03", "pass03")
        self.assertEqual(self.mgr.get_session_by_user("u03").session_id, s.session_id)
        self.assertIsNone(self.mgr.get_session_by_user("u04"))

    def test_touch_updates_last_seen(self):
        s = self.mgr.authenticate("user01", "pass01")
        self.clock.advance(7)
        self.mgr.touch(s.session_id)
        self.assertEqual(self.mgr.get_session(s.session_id).last_seen, 1007.0)
        self.mgr.touch(424242)   # phiên không tồn tại: bỏ qua

    # ----- hết hạn ----------------------------------------------------------

    def test_unbound_expires_at_15_seconds(self):
        a = self.mgr.authenticate("user01", "pass01")
        b = self.mgr.authenticate("user02", "pass02")
        self.mgr.bind_udp(b.session_id, ("127.0.0.1", 5000))
        self.clock.advance(14.9)
        self.assertEqual(self.mgr.expire_unbound(), [])
        self.clock.advance(0.1)
        removed = self.mgr.expire_unbound()
        self.assertEqual([s.session_id for s in removed], [a.session_id])
        self.assertEqual(self.removed, [("u01", "UNBOUND_TIMEOUT")])
        self.assertIsNone(self.mgr.get_session(a.session_id))
        # Phiên đã bind không bị thread này xóa dù đã lâu.
        self.clock.advance(1000)
        self.assertEqual(self.mgr.expire_unbound(), [])
        self.assertIsNotNone(self.mgr.get_session(b.session_id))
        # Hết hạn xong thì đăng nhập lại được.
        self.mgr.authenticate("user01", "pass01")

    def test_callback_runs_outside_lock_and_errors_are_contained(self):
        calls = []

        def callback(session, reason):
            # Lock không reentrant: nếu callback chạy trong lock sẽ deadlock ở đây.
            calls.append(self.mgr.list_online_users())
            raise RuntimeError("callback lỗi")
        self.mgr.on_session_removed(callback)
        s = self.mgr.authenticate("user01", "pass01")
        t = threading.Thread(target=self.mgr.remove_session, args=(s.session_id,))
        with self.assertLogs("sessions", level="ERROR"):   # lỗi callback chỉ được ghi log
            t.start()
            t.join(3)
        self.assertFalse(t.is_alive(), "callback bị gọi khi đang giữ lock")
        self.assertEqual(calls, [[]])

    # ----- đồng thời --------------------------------------------------------

    def test_20_concurrent_logins_unique_ids(self):
        results = [None] * 20
        barrier = threading.Barrier(20)

        def worker(i):
            barrier.wait()
            results[i] = self.mgr.authenticate(f"user{i + 1:02d}", f"pass{i + 1:02d}")
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        self.assertEqual(len({r.session_id for r in results}), 20)
        self.assertEqual(len(self.mgr), 20)

    def test_same_user_concurrent_only_one_wins(self):
        outcomes = []
        lock = threading.Lock()
        barrier = threading.Barrier(10)

        def worker():
            barrier.wait()
            try:
                self.mgr.authenticate("user05", "pass05")
                r = "OK"
            except AppError as exc:
                r = exc.code
            with lock:
                outcomes.append(r)
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        self.assertEqual(outcomes.count("OK"), 1)
        self.assertEqual(outcomes.count("ALREADY_LOGGED_IN"), 9)


class SweeperThreadTests(unittest.TestCase):
    def test_sweeper_removes_unbound_session(self):
        mgr = SessionManager(STORE, unbound_timeout=0.3, sweep_interval=0.05)
        mgr.start()
        mgr.start()   # gọi lại không tạo thread thứ hai
        try:
            a = mgr.authenticate("user01", "pass01")
            b = mgr.authenticate("user02", "pass02")
            mgr.bind_udp(b.session_id, ("127.0.0.1", 6000))
            deadline = time.monotonic() + 3
            while mgr.get_session(a.session_id) is not None and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertIsNone(mgr.get_session(a.session_id))
            self.assertIsNotNone(mgr.get_session(b.session_id))
            mgr.authenticate("user01", "pass01")
        finally:
            mgr.stop()
        self.assertFalse(mgr._thread.is_alive())

    def test_invalid_config(self):
        with self.assertRaises(ValueError):
            SessionManager(STORE, unbound_timeout=0)


class ModuleApiTests(unittest.TestCase):
    """Hàm cấp module đúng tên/chữ ký trong 1a_api.md mục 5."""

    def setUp(self):
        self._old_manager = sessions._manager
        sessions._manager = SessionManager(STORE)

    def tearDown(self):
        sessions._manager = self._old_manager

    def test_signatures(self):
        expected = {"authenticate": ["username", "password"],
                    "bind_udp": ["session_id", "address"],
                    "list_online_users": [],
                    "remove_session": ["session_id"],
                    "get_session": ["session_id"],
                    "get_session_by_user": ["user_id"]}
        for name, params in expected.items():
            self.assertEqual(list(inspect.signature(getattr(sessions, name)).parameters),
                             params, name)

    def test_module_functions_flow(self):
        s = sessions.authenticate("user07", "pass07")
        self.assertIsInstance(s, sessions.Session)
        sessions.bind_udp(s.session_id, ("127.0.0.1", 7000))
        self.assertEqual(sessions.list_online_users(), [{"user_id": "u07", "username": "user07"}])
        self.assertEqual(sessions.get_session_by_user("u07").session_id, s.session_id)
        sessions.remove_session(s.session_id)
        self.assertEqual(sessions.list_online_users(), [])
        self.assertIsNone(sessions.get_session(s.session_id))


class ServerWithRealSessionsTests(unittest.TestCase):
    """TCP login end-to-end với SessionManager thật (không TLS cho nhanh)."""

    def setUp(self):
        self.mgr = SessionManager(STORE, unbound_timeout=0.5, sweep_interval=0.05)
        self.mgr.start()
        self.server = CollabServer(self.mgr, host="127.0.0.1", tcp_port=0, login_timeout=2)
        self.server.start()

    def tearDown(self):
        self.server.stop()
        self.mgr.stop()

    def login(self, username, password):
        with socket.create_connection(("127.0.0.1", self.server.tcp_port), timeout=5) as s:
            s.sendall(encode_frame({"type": "LOGIN", "username": username, "password": password}))
            return recv_frame(s)

    def test_login_ok_matches_registry(self):
        reply = self.login("user01", "pass01")
        self.assertEqual(reply["type"], "LOGIN_OK")
        s = self.mgr.get_session(reply["session_id"])
        self.assertEqual(s.user_id, "u01")
        self.assertEqual(base64.b64decode(reply["c2s_key"]), s.c2s_key)
        self.assertEqual(base64.b64decode(reply["s2c_key"]), s.s2c_key)
        self.assertEqual(base64.b64decode(reply["c2s_nonce_prefix"]), s.c2s_nonce_prefix)
        self.assertEqual(base64.b64decode(reply["s2c_nonce_prefix"]), s.s2c_nonce_prefix)

    def test_wrong_password_and_duplicate(self):
        self.assertEqual(self.login("user01", "sai")["code"], "INVALID_CREDENTIALS")
        self.assertEqual(self.login("user01", "pass01")["type"], "LOGIN_OK")
        self.assertEqual(self.login("user01", "pass01")["code"], "ALREADY_LOGGED_IN")

    def test_relogin_after_unbound_expiry(self):
        first = self.login("user02", "pass02")
        self.assertEqual(self.login("user02", "pass02")["code"], "ALREADY_LOGGED_IN")
        time.sleep(0.8)   # > unbound_timeout 0,5 s
        second = self.login("user02", "pass02")
        self.assertEqual(second["type"], "LOGIN_OK")
        self.assertNotEqual(first["session_id"], second["session_id"])

    def test_20_concurrent_clients(self):
        results = [None] * 20
        barrier = threading.Barrier(20)

        def worker(i):
            barrier.wait()
            results[i] = self.login(f"user{i + 1:02d}", f"pass{i + 1:02d}")
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(15)
        self.assertTrue(all(r and r["type"] == "LOGIN_OK" for r in results), results)
        self.assertEqual(len({r["session_id"] for r in results}), 20)
        self.assertEqual(len(self.mgr), 20)


if __name__ == "__main__":
    unittest.main()
