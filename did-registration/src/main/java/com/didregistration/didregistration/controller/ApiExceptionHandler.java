package com.didregistration.didregistration.controller;

import com.didregistration.didregistration.cheqd.CheqdModuleException;
import com.didregistration.didregistration.dto.api.ApiErrorResponse;
import com.didregistration.didregistration.exception.ResourceNotFoundException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** Chuyển lỗi của API tra cứu thành body {"error":{code,message}}. */
@RestControllerAdvice(assignableTypes = DidRestController.class)
public class ApiExceptionHandler {

    /** Lỗi từ module did:cheqd (ví dụ DID không tồn tại): giữ nguyên mã HTTP và mã lỗi của module. */
    @ExceptionHandler(CheqdModuleException.class)
    public ResponseEntity<ApiErrorResponse> handleModule(CheqdModuleException e) {
        return ResponseEntity.status(e.getHttpStatus()).body(ApiErrorResponse.of(e.getCode(), e.getMessage()));
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiErrorResponse> handleNotFound(ResourceNotFoundException e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ApiErrorResponse.of("NOT_FOUND", e.getMessage()));
    }
}
