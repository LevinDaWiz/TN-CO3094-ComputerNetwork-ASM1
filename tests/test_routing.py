"""Kiểm thử USER_LIST phân trang và định tuyến chat (``server.py``).

Chạy từ thư mục gốc repo::

    python -m unittest tests.test_routing -v
"""

import os
import sys
import threading
import unittest
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from protocol import MAX_PLAINTEXT, AppError, decode_json  # noqa: E402
from server import ChatRouter, build_user_list_parts  # noqa: E402
from sessions import Account, AccountStore, SessionManager, hash_password  # noqa: E402

STORE = AccountStore(Account(f"u{i:02d}", f"user{i:02d}",
                             hash_password(f"pass{i:02d}", iterations=1_000))
                     for i in range(1, 21))
SENT_AT = "2026-10-10T16:00:00Z"


def new_id():
    return str(uuid.uuid4())


def decode_all(parts):
    return [decode_json(p) for p in parts]


class UserListTests(unittest.TestCase):
    def test_empty_list_is_one_part(self):
        parts = decode_all(build_user_list_parts(5, []))
        self.assertEqual(parts, [{"revision": 5, "part_index": 0, "part_count": 1, "users": []}])

    def test_small_list_fits_one_part(self):
        users = [{"user_id": f"u{i:02d}", "username": f"user{i:02d}"} for i in range(1, 21)]
        parts = decode_all(build_user_list_parts(1, users))
        self.assertEqual(len(parts), 1)
        self.assertEqual(parts[0]["users"], users)

    def test_split_respects_byte_limit_and_order(self):
        # Username tiếng Việt dài để buộc chia nhiều phần (đo theo byte UTF-8).
        users = [{"user_id": f"u{i:03d}", "username": "Nguyễn Văn Thành Đạt " + "ư" * 15}
                 for i in range(120)]
        raw = build_user_list_parts(7, users)
        self.assertGreater(len(raw), 1)
        for p in raw:
            self.assertLessEqual(len(p), MAX_PLAINTEXT)
        parts = decode_all(raw)
        self.assertEqual([p["part_index"] for p in parts], list(range(len(parts))))
        self.assertTrue(all(p["part_count"] == len(parts) and p["revision"] == 7 for p in parts))
        merged = [u for p in parts for u in p["users"]]
        self.assertEqual(merged, users)          # đủ, không lặp, đúng thứ tự
        self.assertTrue(all(p["users"] for p in parts))

    def test_tight_limit(self):
        users = [{"user_id": f"u{i:02d}", "username": f"user{i:02d}"} for i in range(1, 11)]
        raw = build_user_list_parts(1, users, max_bytes=120)
        self.assertTrue(all(len(p) <= 120 for p in raw))
        self.assertEqual([u for p in decode_all(raw) for u in p["users"]], users)

    def test_single_user_too_big(self):
        with self.assertRaises(AppError) as cm:
            build_user_list_parts(1, [{"user_id": "u01", "username": "x" * 200}], max_bytes=100)
        self.assertEqual(cm.exception.code, "PAYLOAD_TOO_LARGE")


class OnlineRevisionTests(unittest.TestCase):
    def setUp(self):
        self.mgr = SessionManager(STORE)

    def test_revision_changes_only_when_online_list_changes(self):
        rev0, users = self.mgr.online_snapshot()
        self.assertEqual(users, [])
        a = self.mgr.authenticate("user01", "pass01")
        b = self.mgr.authenticate("user02", "pass02")
        self.assertEqual(self.mgr.online_snapshot()[0], rev0)          # chưa bind: không đổi
        self.mgr.bind_udp(a.session_id, ("127.0.0.1", 5001))
        rev1, users = self.mgr.online_snapshot()
        self.assertEqual((rev1, users), (rev0 + 1, [{"user_id": "u01", "username": "user01"}]))
        self.mgr.bind_udp(a.session_id, ("127.0.0.1", 5001))           # bind lại: không đổi
        self.assertEqual(self.mgr.online_snapshot()[0], rev1)
        self.mgr.remove_session(b.session_id)                          # xóa phiên chưa bind
        self.assertEqual(self.mgr.online_snapshot()[0], rev1)
        self.mgr.remove_session(a.session_id)                          # người online rời đi
        self.assertEqual(self.mgr.online_snapshot(), (rev1 + 1, []))

    def test_list_bound_sessions(self):
        a = self.mgr.authenticate("user02", "pass02")
        b = self.mgr.authenticate("user01", "pass01")
        self.mgr.authenticate("user03", "pass03")                       # chưa bind
        self.mgr.bind_udp(a.session_id, ("127.0.0.1", 5002))
        self.mgr.bind_udp(b.session_id, ("127.0.0.1", 5001))
        bound = self.mgr.list_bound_sessions()
        self.assertEqual([s.user_id for s in bound], ["u01", "u02"])
        bound[0].bound = False                                         # bản sao
        self.assertEqual(len(self.mgr.list_bound_sessions()), 2)


class ChatRouterTests(unittest.TestCase):
    def setUp(self):
        self.mgr = SessionManager(STORE)
        self.router = ChatRouter(self.mgr, clock=lambda: SENT_AT)
        self.s = {}
        for i in (1, 2, 3):
            sess = self.mgr.authenticate(f"user{i:02d}", f"pass{i:02d}")
            self.mgr.bind_udp(sess.session_id, ("127.0.0.1", 6000 + i))
            self.s[f"u{i:02d}"] = self.mgr.get_session(sess.session_id)

    def route(self, sender, payload):
        return self.router.route(self.s[sender], payload)

    def only_status(self, result):
        self.assertEqual(result.deliveries, [])
        self.assertEqual(len(result.statuses), 1)
        return decode_json(result.statuses[0])

    # ----- chat riêng ------------------------------------------------------

    def test_private_chat(self):
        mid = new_id()
        r = self.route("u01", {"message_id": mid, "to": "u02", "text": "Chào bạn!"})
        self.assertEqual(r.statuses, [])
        self.assertIsNone(r.error)
        self.assertEqual(len(r.deliveries), 1)
        d = r.deliveries[0]
        self.assertEqual((d.user_id, d.session_id), ("u02", self.s["u02"].session_id))
        self.assertEqual(decode_json(d.payload), {"message_id": mid, "from": "u01", "to": "u02",
                                                  "text": "Chào bạn!", "sent_at": SENT_AT})

    def test_from_is_taken_from_session_not_client(self):
        r = self.route("u01", {"message_id": new_id(), "to": "u02", "text": "hi", "from": "u03"})
        self.assertEqual(decode_json(r.deliveries[0].payload)["from"], "u01")

    def test_private_to_offline_or_unknown_user(self):
        u4 = self.mgr.authenticate("user04", "pass04")   # đăng nhập nhưng chưa bind
        for to in ("u04", "u99"):
            mid = new_id()
            st = self.only_status(self.route("u01", {"message_id": mid, "to": to, "text": "x"}))
            self.assertEqual(st, {"message_id": mid, "recipient_id": to,
                                  "status": "failed", "error_code": "USER_OFFLINE"})
        self.assertFalse(self.mgr.get_session(u4.session_id).bound)

    def test_private_to_self_allowed(self):
        mid = new_id()
        r = self.route("u01", {"message_id": mid, "to": "u01", "text": "ghi chú"})
        self.assertEqual(r.statuses, [])
        self.assertEqual([(d.user_id, d.session_id) for d in r.deliveries],
                         [("u01", self.s["u01"].session_id)])
        self.assertEqual(decode_json(r.deliveries[0].payload),
                         {"message_id": mid, "from": "u01", "to": "u01",
                          "text": "ghi chú", "sent_at": SENT_AT})

    def test_global_does_not_echo_to_sender(self):
        r = self.route("u01", {"message_id": new_id(), "to": None, "text": "x"})
        self.assertNotIn("u01", [d.user_id for d in r.deliveries])

    # ----- chat chung -------------------------------------------------------

    def test_global_chat_goes_to_everyone_else(self):
        mid = new_id()
        r = self.route("u02", {"message_id": mid, "to": None, "text": "Xin chào cả nhóm"})
        self.assertEqual(sorted(d.user_id for d in r.deliveries), ["u01", "u03"])
        body = decode_json(r.deliveries[0].payload)
        self.assertEqual(body, {"message_id": mid, "from": "u02", "to": None,
                                "text": "Xin chào cả nhóm", "sent_at": SENT_AT})
        self.assertEqual(r.statuses, [])

    def test_global_with_missing_to_field(self):
        r = self.route("u01", {"message_id": new_id(), "text": "x"})   # thiếu "to" = null
        self.assertEqual(len(r.deliveries), 2)

    def test_global_no_recipients(self):
        for uid in ("u02", "u03"):
            self.mgr.remove_session(self.s[uid].session_id)
        mid = new_id()
        st = self.only_status(self.route("u01", {"message_id": mid, "to": None, "text": "x"}))
        self.assertEqual(st, {"message_id": mid, "recipient_id": None,
                              "status": "failed", "error_code": "NO_RECIPIENTS"})

    # ----- kiểm tra đầu vào ---------------------------------------------------

    def test_invalid_message_id_gives_error(self):
        for payload in ({"message_id": "abc", "to": "u02", "text": "x"},
                        {"to": "u02", "text": "x"},
                        {"message_id": 123, "to": "u02", "text": "x"},
                        "không phải dict"):
            r = self.router.route(self.s["u01"], payload)
            self.assertEqual((r.deliveries, r.statuses), ([], []))
            err = decode_json(r.error)
            self.assertEqual((err["code"], err["reference_id"]), ("INVALID_PACKET", None))

    def test_invalid_text(self):
        for text in ("", None, 123, ["x"]):
            st = self.only_status(self.route("u01", {"message_id": new_id(), "to": "u02",
                                                     "text": text}))
            self.assertEqual((st["status"], st["error_code"]), ("failed", "INVALID_PACKET"))

    def test_text_limit_800_utf8_bytes(self):
        ok = self.route("u01", {"message_id": new_id(), "to": "u02", "text": "a" * 800})
        self.assertEqual(len(ok.deliveries), 1)
        # 267 x "ệ" = 801 byte UTF-8 (dù chỉ 267 ký tự).
        st = self.only_status(self.route("u01", {"message_id": new_id(), "to": "u02",
                                                 "text": "ệ" * 267}))
        self.assertEqual(st["error_code"], "PAYLOAD_TOO_LARGE")

    def test_json_escaping_overflow(self):
        # 800 dấu ngoặc kép hợp lệ về số byte text, nhưng JSON escape thành 1600 byte.
        st = self.only_status(self.route("u01", {"message_id": new_id(), "to": "u02",
                                                 "text": '"' * 800}))
        self.assertEqual(st["error_code"], "PAYLOAD_TOO_LARGE")

    def test_invalid_to(self):
        for to in ("", "u" * 33, "người", "u 1", 5):
            st = self.only_status(self.route("u01", {"message_id": new_id(), "to": to,
                                                     "text": "x"}))
            self.assertEqual((st["recipient_id"], st["error_code"]), (None, "INVALID_PACKET"))

    # ----- chống trùng ---------------------------------------------------------

    def test_duplicate_message_id_per_sender(self):
        mid = new_id()
        payload = {"message_id": mid, "to": "u02", "text": "x"}
        self.assertEqual(len(self.route("u01", payload).deliveries), 1)
        dup = self.route("u01", payload)
        self.assertTrue(dup.duplicate)
        self.assertEqual((dup.deliveries, dup.statuses, dup.error), ([], [], None))
        # Cùng message_id nhưng người gửi khác là tin khác.
        self.assertEqual(len(self.route("u03", payload).deliveries), 1)

    def test_failed_message_is_also_deduped(self):
        payload = {"message_id": new_id(), "to": "u99", "text": "x"}
        self.assertEqual(len(self.route("u01", payload).statuses), 1)
        self.assertTrue(self.route("u01", payload).duplicate)

    def test_forget_session_and_bounded_memory(self):
        router = ChatRouter(self.mgr, clock=lambda: SENT_AT, dedupe_limit=3)
        sender = self.s["u01"]
        ids = [new_id() for _ in range(4)]
        for mid in ids:
            router.route(sender, {"message_id": mid, "to": "u02", "text": "x"})
        # Giới hạn 3: id đầu tiên đã bị quên, id cuối vẫn nhớ.
        self.assertFalse(router.route(sender, {"message_id": ids[0], "to": "u02",
                                               "text": "x"}).duplicate)
        self.assertTrue(router.route(sender, {"message_id": ids[3], "to": "u02",
                                              "text": "x"}).duplicate)
        router.forget_session(sender.session_id)
        self.assertFalse(router.route(sender, {"message_id": ids[3], "to": "u02",
                                               "text": "x"}).duplicate)

    def test_concurrent_same_message_id_delivered_once(self):
        payload = {"message_id": new_id(), "to": None, "text": "x"}
        results, lock = [], threading.Lock()
        barrier = threading.Barrier(10)

        def worker():
            barrier.wait()
            r = self.route("u01", payload)
            with lock:
                results.append(r)
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(5)
        self.assertEqual(sum(not r.duplicate for r in results), 1)

    def test_default_clock_format(self):
        r = ChatRouter(self.mgr).route(self.s["u01"], {"message_id": new_id(), "to": "u02",
                                                       "text": "x"})
        self.assertRegex(decode_json(r.deliveries[0].payload)["sent_at"],
                         r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


if __name__ == "__main__":
    unittest.main()
