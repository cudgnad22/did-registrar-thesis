package com.didregistration.didregistration.cheqd.dto;

import java.util.List;

/**
 * Kết quả prepare: versionId, dữ liệu cần ký (base64) và danh sách khóa phải ký.
 * versionId và DID Document đã gửi phải được lưu lại để dùng đúng như cũ ở bước submit.
 */
public record PrepareResponse(String versionId, String signBytes, List<String> requiredSigners) {}
