package com.didregistration.didregistration.controller;

import com.didregistration.didregistration.cheqd.CheqdModuleException;
import com.didregistration.didregistration.dto.dif.DifResponse;
import com.didregistration.didregistration.exception.DifException;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Lỗi ở lần gọi đầu (chưa tạo thao tác) được trả về đúng cấu trúc của đặc tả:
 * jobId = null, didState.state = "failed" kèm reason. Mã HTTP: 400 lỗi đầu vào, 500 lỗi nội bộ.
 */
@RestControllerAdvice(assignableTypes = DifRegistrarController.class)
public class DifExceptionHandler {

    @ExceptionHandler(DifException.class)
    public ResponseEntity<DifResponse> handleDif(DifException e) {
        return failed(e.getHttpStatus(), e.getReason(), e.getMessage(), e.getDid());
    }

    /** Lỗi từ module did:cheqd ở bước chuẩn bị (DID không tồn tại, đã vô hiệu hóa, sai đặc tả...) */
    @ExceptionHandler(CheqdModuleException.class)
    public ResponseEntity<DifResponse> handleModule(CheqdModuleException e) {
        int status = e.isRetryable() ? 500 : 400;
        return failed(status, DifException.reasonOf(e.getCode()), e.getMessage(), null);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<DifResponse> handleBadJson(HttpMessageNotReadableException e) {
        return failed(400, "invalidRequest", "Body không phải JSON hợp lệ theo đặc tả", null);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<DifResponse> handleOther(Exception e) {
        org.slf4j.LoggerFactory.getLogger(DifExceptionHandler.class).error("Lỗi không xác định", e);
        return failed(500, "internalError", "Lỗi nội bộ của Registrar", null);
    }

    private ResponseEntity<DifResponse> failed(int status, String reason, String description, String did) {
        Map<String, Object> didState = new LinkedHashMap<>();
        didState.put("state", "failed");
        didState.put("did", did);
        didState.put("reason", reason);
        didState.put("description", description);
        return ResponseEntity.status(status).body(new DifResponse(null, didState, Map.of(), Map.of()));
    }

}
