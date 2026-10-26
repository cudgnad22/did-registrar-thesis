# did-cli — Bộ ký phía Client (Node/TypeScript)

Giữ khóa bí mật của người dùng; Registrar không bao giờ nhận được khóa này.

- Kho khóa cục bộ `~/.did-cli/wallet.json`, trạng thái khóa PENDING / ACTIVE / REPLACED
- Đối chiếu DID Document và dữ liệu cần ký trước khi ký, hỏi xác nhận `(y/N)`
