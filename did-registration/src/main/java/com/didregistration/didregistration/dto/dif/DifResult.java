package com.didregistration.didregistration.dto.dif;

/** Kết quả xử lý: mã HTTP (theo HTTPS binding của đặc tả) và body. */
public record DifResult(int httpStatus, DifResponse body) {
}
