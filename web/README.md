# Coral Chat — Giao diện CC v1 (Người 5)

Mở app: chạy `python http_bridge.py` rồi vào http://127.0.0.1:8080.
Layout 3 cột kiểu Discord: **bạn bè/online** (trái) — **chat** (giữa) — **trạng thái + tệp** (phải). Không có danh sách server/channel.

## Đăng nhập

Nhập tài khoản demo (`user01`/`pass01` … `user20`/`pass20`), bấm Đăng nhập.
Pill trạng thái trên đầu khung chat và thẻ "Trạng thái kết nối" (cột phải)
hiển thị `connecting` → `connected` (chỉ sau UDP_BIND_OK).
Sai mật khẩu hoặc đã đăng nhập nơi khác báo lỗi ngay trên thẻ đăng nhập.

## Bạn bè và trạng thái online

- Cột trái: nút **Bạn bè** (về kênh chung), ô tìm DM, dòng "**N đang online**"
  và danh sách user (avatar chữ cái đầu + username + user_id).
- Bấm một bạn để chat riêng; bấm **Bạn bè** để về kênh chung `#general`.

## Chat chung / riêng

- Giữa: tiêu đề kênh (`#general` hoặc `@bạn`), vùng tin nhắn, ô nhập kiểu
  Discord (nút `+`, icon gift/ảnh/sticker/emoji trang trí).
- `Enter` để gửi; tối đa 800 byte UTF-8. Gửi xong tới qua polling;
  trạng thái accepted/delivered/failed hiện dòng hệ thống khi lỗi.

## Tải tệp lên (nút +)

1. Chọn một bạn ở cột trái (V1 chỉ gửi tệp riêng).
2. Bấm `+` → **Tải Lên Tệp** → chọn file (tối đa 100 MiB).
3. Bên nhận thấy offer ở cột phải → **Nhận** / **Từ chối**.
4. Thanh tiến độ 0–100% (100% byte chưa đồng nghĩa completed — chỉ
   FILE_RESULT thành công mới xong). Tệp incoming completed hiện **Tải về**.

## Sự kiện và lỗi

- Polling `GET /api/events?after=` mỗi 500 ms, một request tại một thời điểm.
- Đủ 100 event lấy tiếp ngay; 409 EVENT_CURSOR_EXPIRED → báo "có thể mất
  sự kiện", tự tải lại status/users/transfers rồi tiếp tục.
- Lỗi thường gặp: USER_OFFLINE, NO_RECIPIENTS, TRANSFER_TIMEOUT,
  CHECKSUM_MISMATCH, DELIVERY_TIMEOUT.

## Màu sắc, font, icon

- Chủ đạo Living Coral `#FF6F61`, phụ vàng `#FFD166`, nền `#F8F9FA`, chữ `#073B4C`.
- Font Be Vietnam Pro (nội dung) + Quicksand (tiêu đề). Icon Lucide qua CDN:
  icon nền sáng màu `#073B4C`, hover `#FF6F61`; trong nút CTA san hô icon trắng.

## Bảo mật (`security.py`)

- AES-256-GCM qua `cryptography`; raw header 23 byte làm AAD.
- Nonce = prefix 4 byte + counter uint64 có khóa; truyền lại giữ nguyên datagram.
- Khóa do TLS cấp mỗi phiên; không hiện khóa/mật khẩu/nonce trên UI hay log.
