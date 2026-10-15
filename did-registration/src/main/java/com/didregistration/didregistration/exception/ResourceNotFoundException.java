package com.didregistration.didregistration.exception;

/** Không tìm thấy DID hoặc thao tác trong cơ sở dữ liệu của ứng dụng. */
public class ResourceNotFoundException extends RuntimeException {
    public ResourceNotFoundException(String message) {
        super(message);
    }
}