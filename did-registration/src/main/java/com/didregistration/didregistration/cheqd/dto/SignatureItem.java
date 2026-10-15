package com.didregistration.didregistration.cheqd.dto;

/** Một chữ ký Ed25519 (base64) do Client tạo, gắn với id của Verification Method. */
public record SignatureItem(String verificationMethodId, String signature) {}
