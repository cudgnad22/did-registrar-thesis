package com.didregistration.didregistration.dto.api;

/** Định dạng lỗi trả cho Client: {"error": {"code": "...", "message": "..."}} */
public record ApiErrorResponse(ErrorBody error) {

    public record ErrorBody(String code, String message) {}

    public static ApiErrorResponse of(String code, String message) {
        return new ApiErrorResponse(new ErrorBody(code, message));
    }
}