# did-registration — DID Registrar (Java Spring Boot)

Thành phần chính của đồ án. Cung cấp API tạo, cập nhật và vô hiệu hóa DID theo đặc tả DIF DID Registration, ở chế độ Client-managed Secret: lần gọi thứ nhất trả yêu cầu ký (`action: signPayload`), lần gọi thứ hai nhận chữ ký và gửi giao dịch qua module did:cheqd.

- Lưu trạng thái thao tác vào PostgreSQL (bảng `did`, `did_operation`, `did_owner`)
- Giao diện trực quan: `/ui`
- Cổng mặc định: 8085 · Mật khẩu cơ sở dữ liệu đọc từ biến `DB_PASSWORD`
