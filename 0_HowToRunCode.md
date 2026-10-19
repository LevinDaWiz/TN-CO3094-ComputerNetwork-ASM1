# Tải các thư viện còn thiếu trên

python -m pip install -r 01_requirements.txt

# Nếu chạy toàn bộ test

python -m unittest discover -s . -v

# Nếu chạy test giả như là: 

# Chỉ test đóng gói/giải mã
python -m unittest test_protocol_transport.CodecTests -v

# Chỉ test truyền UDP tin cậy
python -m unittest test_protocol_transport.TransportTests -v

# Chỉ test mất ACK
python -m unittest test_protocol_transport.TransportTests.test_lost_ack -v

# ===== Server và tài khoản (Người 2: server.py, sessions.py) =====

# Tình trạng server (16/10):
#   Đã chạy: đăng nhập TCP/TLS 9000; phiên + tài khoản demo; UDP 9001: UDP_BIND/UDP_BIND_OK,
#            USER_LIST khi có người vào/ra, chat riêng/chung + CHAT_STATUS (accepted/delivered/failed),
#            chuyển tiếp tệp A -> server -> B (luồng riêng, không chặn chat),
#            heartbeat (15 s mất kết nối thì xóa khỏi online), LOGOUT.
#   Báo lỗi tệp: người nhận offline/mất kết nối -> người gửi nhận FILE_RESULT failed/USER_OFFLINE;
#                người gửi mất kết nối -> người nhận nhận ERROR USER_OFFLINE.
#   Client thật (client.py) chưa có -> xem luồng đầy đủ bằng các test end-to-end ở cuối mục này.

# Tài khoản demo (không có đăng ký): user01..user20 / mật khẩu pass01..pass20
# user_id tương ứng u01..u20. Mật khẩu chỉ để demo.
# accounts.json chỉ lưu hash PBKDF2-HMAC-SHA256 (600000 vòng, salt riêng từng tài khoản).
# Sinh lại accounts.json (salt mới, mật khẩu giữ nguyên):
python tools/make_accounts.py --force

# Sinh chứng chỉ TLS (lần đầu, trên máy chạy server; tự dò IP LAN, thêm --ip nếu cần)
# Chỉ gửi certs/ca.crt cho máy client; KHÔNG commit thư mục certs/ (có khóa riêng).
python tools/gen_cert.py
python tools/gen_cert.py --ip 192.168.1.10

# Chạy server (TLS bật mặc định; TCP 9000, UDP 9001; log in ra màn hình, Ctrl+C để dừng)
# Windows: lần đầu chạy, Windows Firewall hỏi quyền -> bấm Allow, nếu không máy khác trong LAN không vào được.
python server.py
python server.py --host 0.0.0.0 --tcp-port 9000 --udp-port 9001 --login-timeout 10 --accounts accounts.json
python server.py --help

# Phiên đăng nhập nhưng chưa bind UDP bị xóa sau 15 giây; chỉnh khi test:
python server.py --unbound-timeout 3

# Chỉ để debug: tắt TLS (khóa phiên sẽ đi dạng rõ)
python server.py --no-tls

# Client thử đăng nhập (xác minh chứng chỉ bằng certs/ca.crt)
python tools/login_client.py user01 pass01
python tools/login_client.py user01 pass01 --host 192.168.1.10 --cafile certs/ca.crt
python tools/login_client.py user01 pass01 --no-tls

# Chỉ test server/tài khoản
python -m unittest discover -s tests -v
python -m unittest tests.test_server_login -v
python -m unittest tests.test_accounts -v
python -m unittest tests.test_sessions -v
python -m unittest tests.test_routing -v
python -m unittest tests.test_server_udp -v
python -m unittest tests.test_udp_service -v

# Test end-to-end bằng socket thật: TCP login -> UDP_BIND -> USER_LIST -> chat riêng -> delivered
python -m unittest tests.test_udp_service.EndToEndRealSocketTests -v

# Test chuyển tiếp tệp qua server thật (client là file_transfer.py của Người 4): mất/trùng/đảo gói,
# từ chối, timeout, người nhận/người gửi mất kết nối, bên nhận chậm; có 1 test socket UDP thật
python -m unittest tests.test_file_relay -v
python -m unittest tests.test_file_relay.FileRelayRealSocketTests -v

# Test tải: 20 client đồng thời bằng socket thật (TCP login -> UDP_BIND -> 20 người online ->
# mỗi người nhận đủ 19 tin chung -> chat riêng theo vòng có delivered -> 10 người logout)
python -m unittest tests.test_many_clients -v

# ===== Truyền tệp (Người 4: file_transfer.py) =====

# Test truyền tệp (server giả lập trong tests/, không phải server.py): mất/trùng/đảo gói + UDP thật
python -m unittest tests.test_file_transfer -v

# Demo A -> server -> B qua UDP localhost (in tiến độ, kiểm tra SHA-256, chat song song)
python tools/file_transfer_demo.py
python tools/file_transfer_demo.py --size-mib 100
python tools/file_transfer_demo.py --file duong_dan_toi_tep.pdf

