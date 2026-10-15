package com.didregistration.didregistration.dto.api;

/** Thông tin người sở hữu do người dùng nhập trên giao diện. */
public record OwnerInfoRequest(String fullName, String organization, String email) {
}
