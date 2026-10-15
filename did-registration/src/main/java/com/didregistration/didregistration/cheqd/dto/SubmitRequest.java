package com.didregistration.didregistration.cheqd.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import tools.jackson.databind.JsonNode;
import java.util.List;

/**
 * Request gửi tới POST /internal/cheqd/submit.
 * didDocument và versionId phải GIỐNG HỆT lúc prepare, nếu không chữ ký của Client không còn hợp lệ.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record SubmitRequest(
        String operation,
        String did,
        JsonNode didDocument,
        String versionId,
        List<SignatureItem> signatures) {}