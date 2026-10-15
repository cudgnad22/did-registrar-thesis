package com.didregistration.didregistration.cheqd.dto;

import tools.jackson.databind.JsonNode;

/**
 * Kết quả giao dịch trên mạng cheqd.
 * code: 0 = thành công; 1100 = chữ ký không hợp lệ; 1207 = DID đã bị vô hiệu hóa; ...
 */
public record SubmitResponse(
        boolean success,
        int code,
        String txHash,
        long height,
        String rawLog,
        long elapsedMs,
        JsonNode didDocument,
        JsonNode didDocumentMetadata) {}
