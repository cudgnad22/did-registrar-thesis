# cheqd-module — Module did:cheqd (Node/TypeScript)

Thành phần duy nhất làm việc trực tiếp với mạng cheqd, dùng cheqd SDK 5.5.1.

- `prepare`: dựng dữ liệu cần ký (protobuf) đúng như SDK và xác định các khóa phải ký
- `submit`: ghép chữ ký của Client và gửi giao dịch bằng tài khoản trả phí
- Cấu hình qua `.env` (xem `.env.example`) · Cổng mặc định: 3000
