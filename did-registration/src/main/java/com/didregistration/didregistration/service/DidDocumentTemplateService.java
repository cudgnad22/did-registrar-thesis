package com.didregistration.didregistration.service;

import com.didregistration.didregistration.cheqd.CheqdModuleClient;
import com.didregistration.didregistration.cheqd.CheqdModuleException;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Dựng mẫu DID Document từ khóa công khai của Client (điểm cuối hỗ trợ GET /1.0/did-document).
 *
 *  - Tạo DID: sinh DID did:cheqd:testnet:<uuid>, khóa đầu tiên có id #key-1.
 *  - Thay khóa: đọc DID Document hiện hành trên mạng, đặt id khóa mới là #key-(n+1),
 *    DID Document mới chỉ chứa khóa mới (key replacement).
 *
 * Chỉ nhận khóa công khai, không lưu gì và không ghi lên mạng. Client vẫn phải đối chiếu
 * DID Document này trước khi ký, vì đây là dữ liệu do Registrar tạo ra.
 */
@Service
public class DidDocumentTemplateService {

    private static final String DID_CONTEXT = "https://www.w3.org/ns/did/v1";
    private static final Pattern KEY_INDEX = Pattern.compile("#key-(\\d+)$");
    private static final Pattern HEX_32 = Pattern.compile("^[0-9a-fA-F]{64}$");

    private final DidDocumentValidator validator;
    private final CheqdModuleClient cheqdModuleClient;
    private final ObjectMapper objectMapper;

    public DidDocumentTemplateService(DidDocumentValidator validator, CheqdModuleClient cheqdModuleClient,
                                      ObjectMapper objectMapper) {
        this.validator = validator;
        this.cheqdModuleClient = cheqdModuleClient;
        this.objectMapper = objectMapper;
    }

    /** Lỗi đầu vào của điểm cuối hỗ trợ: mã HTTP + mã lỗi + thông báo. */
    public static class TemplateException extends RuntimeException {
        private final int status;
        private final String code;
        public TemplateException(int status, String code, String message) {
            super(message);
            this.status = status;
            this.code = code;
        }
        public int getStatus() { return status; }
        public String getCode() { return code; }
    }

    public Map<String, Object> build(String publicKeyJwk, String publicKeyHex, String did) {
        Map<String, Object> jwk = parsePublicKey(publicKeyJwk, publicKeyHex);

        String operation;
        String targetDid;
        int index;
        List<String> replacedKeys = List.of();
        if (did == null || did.isBlank()) {
            operation = "create";
            targetDid = DidDocumentValidator.DID_PREFIX + UUID.randomUUID();
            index = 1;
        } else {
            operation = "update";
            targetDid = did.trim();
            validator.checkDidFormat(targetDid);
            Map<String, Object> current = readCurrent(targetDid);
            Map<String, Object> doc = asMap(current.get("didDocument"));
            Map<String, Object> meta = asMap(current.get("didDocumentMetadata"));
            if (Boolean.TRUE.equals(meta.get("deactivated"))) {
                throw new TemplateException(409, "DID_DEACTIVATED", targetDid + " đã bị vô hiệu hóa, không thể thay khóa");
            }
            int max = 0;
            for (Object o : asList(doc.get("verificationMethod"))) {
                Map<String, Object> vm = asMap(o);
                Map<String, Object> pk = asMap(vm.get("publicKeyJwk"));
                if (jwk.get("x").equals(pk.get("x"))) {
                    throw new TemplateException(400, "KEY_ALREADY_USED", "Khóa công khai này đã có trong DID Document hiện hành; hãy sinh khóa mới");
                }
                Matcher m = KEY_INDEX.matcher(String.valueOf(vm.get("id")));
                if (m.find()) max = Math.max(max, Integer.parseInt(m.group(1)));
            }
            index = max + 1;
            List<String> auth = new ArrayList<>();
            for (Object a : asList(doc.get("authentication"))) {
                auth.add(a instanceof Map<?, ?> am ? String.valueOf(am.get("id")) : String.valueOf(a));
            }
            replacedKeys = auth;
        }

        String keyId = targetDid + "#key-" + index;
        Map<String, Object> vm = new LinkedHashMap<>();
        vm.put("id", keyId);
        vm.put("type", "JsonWebKey2020");
        vm.put("controller", targetDid);
        vm.put("publicKeyJwk", jwk);

        Map<String, Object> didDocument = new LinkedHashMap<>();
        didDocument.put("@context", List.of(DID_CONTEXT));
        didDocument.put("id", targetDid);
        didDocument.put("controller", List.of(targetDid));
        didDocument.put("verificationMethod", List.of(vm));
        didDocument.put("authentication", List.of(keyId));
        didDocument.put("assertionMethod", List.of(keyId));

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("operation", operation);
        out.put("did", targetDid);
        out.put("keyId", keyId);
        // Với thay khóa: các khóa hiện hành sẽ bị gỡ và cũng phải ký (quy tắc của did:cheqd)
        if (!replacedKeys.isEmpty()) out.put("replacedKeys", replacedKeys);
        out.put("didDocument", didDocument);
        return out;
    }

    private Map<String, Object> readCurrent(String did) {
        try {
            return asMap(objectMapper.convertValue(cheqdModuleClient.resolve(did), Map.class));
        } catch (CheqdModuleException e) {
            throw new TemplateException(e.getHttpStatus(), e.getCode(), e.getMessage());
        }
    }

    /** Nhận đúng một trong hai dạng: JWK (JSON) hoặc 32 byte khóa công khai dạng hex. */
    private Map<String, Object> parsePublicKey(String publicKeyJwk, String publicKeyHex) {
        boolean hasJwk = publicKeyJwk != null && !publicKeyJwk.isBlank();
        boolean hasHex = publicKeyHex != null && !publicKeyHex.isBlank();
        if (hasJwk == hasHex) {
            throw new TemplateException(400, "INVALID_PUBLIC_KEY", "Cần đúng một tham số: publicKeyJwk hoặc publicKeyHex");
        }
        byte[] raw;
        if (hasHex) {
            String hex = publicKeyHex.trim();
            if (!HEX_32.matcher(hex).matches()) {
                throw new TemplateException(400, "INVALID_PUBLIC_KEY", "publicKeyHex phải là 32 byte (64 ký tự hex)");
            }
            raw = HexFormat.of().parseHex(hex);
        } else {
            Map<String, Object> in;
            try {
                in = asMap(objectMapper.readValue(publicKeyJwk, Map.class));
            } catch (RuntimeException e) {
                throw new TemplateException(400, "INVALID_PUBLIC_KEY", "publicKeyJwk không phải JSON hợp lệ");
            }
            if (in.containsKey("d")) {
                throw new TemplateException(400, "PRIVATE_KEY_NOT_ALLOWED",
                        "publicKeyJwk chứa khóa bí mật (trường d). Không gửi khóa bí mật tới Registrar.");
            }
            if (!"OKP".equals(in.get("kty")) || !"Ed25519".equals(in.get("crv")) || !(in.get("x") instanceof String x)) {
                throw new TemplateException(400, "INVALID_PUBLIC_KEY", "Chỉ hỗ trợ khóa Ed25519 dạng JWK (kty OKP, crv Ed25519, x)");
            }
            try {
                raw = Base64.getUrlDecoder().decode(x);
            } catch (IllegalArgumentException e) {
                throw new TemplateException(400, "INVALID_PUBLIC_KEY", "x không phải base64url hợp lệ");
            }
        }
        if (raw.length != 32) {
            throw new TemplateException(400, "INVALID_PUBLIC_KEY", "Khóa công khai Ed25519 phải dài 32 byte");
        }
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "OKP");
        jwk.put("crv", "Ed25519");
        jwk.put("x", Base64.getUrlEncoder().withoutPadding().encodeToString(raw));
        return jwk;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object o) {
        return o instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of();
    }

    private static List<?> asList(Object o) {
        return o instanceof List<?> l ? l : List.of();
    }
}
