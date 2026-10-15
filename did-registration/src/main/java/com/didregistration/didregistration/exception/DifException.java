package com.didregistration.didregistration.exception;

/**
 * Lỗi đầu vào hoặc lỗi hệ thống khi xử lý request DID Registration, trả về dưới dạng
 * didState.state = "failed" với reason tương ứng.
 * Theo HTTPS binding của đặc tả: 400 cho lỗi đầu vào, 500 cho lỗi nội bộ.
 */
public class DifException extends RuntimeException {

    private final int httpStatus;
    private final String reason;
    private final String did;

    public DifException(int httpStatus, String reason, String message) {
        this(httpStatus, reason, message, null);
    }

    public DifException(int httpStatus, String reason, String message, String did) {
        super(message);
        this.httpStatus = httpStatus;
        this.reason = reason;
        this.did = did;
    }

    /** Mã lỗi của module sang reason theo đặc tả: SIGNATURE_INVALID -> signatureInvalid */
    public static String reasonOf(String code) {
        if (code == null) return "error";
        StringBuilder sb = new StringBuilder();
        boolean upper = false;
        for (char c : code.toLowerCase().toCharArray()) {
            if (c == '_') { upper = true; continue; }
            sb.append(upper ? Character.toUpperCase(c) : c);
            upper = false;
        }
        return sb.toString();
    }

    public int getHttpStatus() { return httpStatus; }
    public String getReason() { return reason; }
    public String getDid() { return did; }
}
