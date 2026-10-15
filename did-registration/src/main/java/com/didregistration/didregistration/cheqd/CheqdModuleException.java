package com.didregistration.didregistration.cheqd;

/**
 * Lỗi từ module did:cheqd, xảy ra TRƯỚC khi giao dịch được ghi nhận trên mạng.
 *   400 SIGNATURE_INVALID, SIGNERS_MISMATCH       -> Client có thể ký/gửi lại
 *   404 DID_NOT_FOUND
 *   409 DID_ALREADY_EXISTS, DID_DEACTIVATED
 *   422 INVALID_DID_DOCUMENT, SDK_REJECTED, ...
 *   502 LEDGER_UNAVAILABLE, 503 MODULE_UNAVAILABLE, 504 MODULE_TIMEOUT -> lỗi hạ tầng, có thể thử lại
 */
public class CheqdModuleException extends RuntimeException {

    private final int httpStatus;
    private final String code;

    public CheqdModuleException(int httpStatus, String code, String message) {
        super(message);
        this.httpStatus = httpStatus;
        this.code = code;
    }

    public int getHttpStatus() { return httpStatus; }

    public String getCode() { return code; }

    /** Lỗi do hạ tầng (module hoặc mạng không truy cập được). */
    public boolean isRetryable() {
        return httpStatus == 502 || httpStatus == 503 || httpStatus == 504;
    }
}
