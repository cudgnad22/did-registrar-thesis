# tools — Công cụ kiểm thử

`mock-registrar.mjs`: Registrar giả lập có cùng API với ứng dụng, xác minh chữ ký Ed25519 thật nhưng chỉ lưu trong bộ nhớ. Dùng để thử các trường hợp bộ ký từ chối ký mà không cần mạng cheqd (`MODE=evil` chèn khóa lạ, `MODE=wait` giả lập trạng thái chờ).

Kết quả từ Registrar giả lập không phải kết quả trên mạng cheqd.
