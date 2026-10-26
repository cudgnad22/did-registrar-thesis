package com.didregistration.didregistration.service;

import com.didregistration.didregistration.exception.DifException;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Chuẩn hóa và kiểm tra DID Document do CLIENT soạn (theo đặc tả DIF, Client gửi didDocument).
 *
 * Chuẩn hóa: gán id cho DID Document, đổi tham chiếu tương đối "#key-1" thành DID URL đầy đủ,
 *            bổ sung @context và controller mặc định.
 * Kiểm tra : chỉ chấp nhận DID tự kiểm soát (controller là chính DID) và khóa Ed25519 ở một trong hai dạng
 *            JsonWebKey2020 (publicKeyJwk) hoặc Ed25519VerificationKey2020 (publicKeyMultibase);
 *            từ chối nếu Client vô tình gửi kèm private key.
 */
@Component
public class DidDocumentValidator {

    public static final String DID_PREFIX = "did:cheqd:testnet:";
    private static final String DID_CONTEXT = "https://www.w3.org/ns/did/v1";
    private static final Pattern CHEQD_TESTNET_UUID = Pattern.compile(
            "^did:cheqd:testnet:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    private static final List<String> RELATIONSHIPS = List.of(
            "authentication", "assertionMethod", "capabilityInvocation", "capabilityDelegation", "keyAgreement");
    private static final String BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final List<String> PRIVATE_KEY_FIELDS = List.of(
            "privateKeyJwk", "privateKeyMultibase", "privateKeyBase58", "privateKeyHex", "privateKeyPem");
    /** Phần sau dấu # của id service: chữ, số và . _ ~ - */
    private static final Pattern SERVICE_FRAGMENT = Pattern.compile("^[A-Za-z0-9._~-]+$");

    public void checkDidFormat(String did) {
        if (did == null || !CHEQD_TESTNET_UUID.matcher(did).matches()) {
            throw new DifException(400, "invalidDid",
                    "DID phải có dạng did:cheqd:testnet:<uuid>, nhận được: " + did, did);
        }
    }

    /** Chuẩn hóa DID Document của Client thành bản đầy đủ gắn với DID. */
    public Map<String, Object> normalize(Map<String, Object> input, String did) {
        Object inputId = input.get("id");
        if (inputId != null && !did.equals(inputId)) {
            throw new DifException(400, "invalidDidDocument",
                    "didDocument.id (" + inputId + ") không trùng với DID " + did, did);
        }

        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("@context", input.getOrDefault("@context", List.of(DID_CONTEXT)));
        doc.put("id", did);
        doc.put("controller", input.containsKey("controller") ? absoluteList(input.get("controller"), did) : List.of(did));

        List<Map<String, Object>> vms = new ArrayList<>();
        for (Object o : asList(input.get("verificationMethod"), "verificationMethod", did)) {
            Map<String, Object> vm = new LinkedHashMap<>(asMap(o, "verificationMethod[]", did));
            vm.put("id", absolute(asString(vm.get("id"), "verificationMethod[].id", did), did));
            vm.putIfAbsent("controller", did);
            vms.add(vm);
        }
        doc.put("verificationMethod", vms);

        for (String rel : RELATIONSHIPS) {
            if (input.containsKey(rel)) doc.put(rel, absoluteList(input.get(rel), did));
        }
        if (input.containsKey("service")) {
            List<Map<String, Object>> services = new ArrayList<>();
            for (Object o : asList(input.get("service"), "service", did)) {
                Map<String, Object> s = new LinkedHashMap<>(asMap(o, "service[]", did));
                s.put("id", absolute(asString(s.get("id"), "service[].id", did), did));
                services.add(s);
            }
            doc.put("service", services);
        }
        // Giữ nguyên các trường khác (ví dụ alsoKnownAs); đặc tả cheqd sẽ kiểm tra ở module
        input.forEach((k, v) -> doc.putIfAbsent(k, v));
        return doc;
    }

    /** Kiểm tra DID Document đã chuẩn hóa. */
    public void validate(Map<String, Object> doc, String did) {
        List<?> controller = (List<?>) doc.get("controller");
        if (controller.size() != 1 || !did.equals(controller.get(0))) {
            throw new DifException(400, "unsupportedDidDocument",
                    "Chỉ hỗ trợ DID tự kiểm soát: controller phải là [" + did + "]", did);
        }

        Set<String> vmIds = new HashSet<>();
        for (Object o : (List<?>) doc.get("verificationMethod")) {
            Map<String, Object> vm = asMap(o, "verificationMethod[]", did);
            String id = (String) vm.get("id");
            if (!vmIds.add(id)) throw new DifException(400, "invalidDidDocument", "Trùng id Verification Method: " + id, did);
            if (!did.equals(vm.get("controller"))) {
                throw new DifException(400, "unsupportedDidDocument", id + ": controller phải là " + did, did);
            }
            for (String field : PRIVATE_KEY_FIELDS) {
                if (vm.containsKey(field)) {
                    throw new DifException(400, "privateKeyNotAllowed",
                            id + ": có trường " + field + " (khóa bí mật). Không gửi private key tới Registrar.", did);
                }
            }
            Object type = vm.get("type");
            if ("JsonWebKey2020".equals(type)) {
                Map<String, Object> jwk = asMap(vm.get("publicKeyJwk"), id + ".publicKeyJwk", did);
                if (jwk.containsKey("d")) {
                    throw new DifException(400, "privateKeyNotAllowed",
                            id + ": publicKeyJwk chứa private key (trường d). Không gửi private key tới Registrar.", did);
                }
                if (!"OKP".equals(jwk.get("kty")) || !"Ed25519".equals(jwk.get("crv"))) {
                    throw new DifException(400, "unsupportedVerificationMethod", id + ": chỉ hỗ trợ khóa Ed25519 (kty OKP)", did);
                }
                asString(jwk.get("x"), id + ".publicKeyJwk.x", did);
                if (ed25519PublicKey(vm) == null) {
                    throw new DifException(400, "invalidDidDocument", id + ".publicKeyJwk.x phải là base64url của 32 byte", did);
                }
            } else if ("Ed25519VerificationKey2020".equals(type)) {
                asString(vm.get("publicKeyMultibase"), id + ".publicKeyMultibase", did);
                // SDK cheqd không kiểm tra giá trị này; nếu để lọt, mạng chỉ báo lỗi (1205) sau khi Client đã ký
                if (ed25519PublicKey(vm) == null) {
                    throw new DifException(400, "invalidDidDocument",
                            id + ".publicKeyMultibase phải là khóa Ed25519 dạng multibase: \"z\" + base58btc(0xed01 + 32 byte)", did);
                }
            } else {
                throw new DifException(400, "unsupportedVerificationMethod",
                        id + ": chỉ hỗ trợ kiểu JsonWebKey2020 hoặc Ed25519VerificationKey2020", did);
            }
        }
        if (vmIds.isEmpty()) {
            throw new DifException(400, "invalidDidDocument", "DID Document phải có ít nhất một Verification Method", did);
        }

        List<?> auth = (List<?>) doc.get("authentication");
        if (auth == null || auth.isEmpty()) {
            throw new DifException(400, "invalidDidDocument", "DID Document phải có authentication", did);
        }
        for (String rel : RELATIONSHIPS) {
            if (!(doc.get(rel) instanceof List<?> refs)) continue;
            for (Object ref : refs) {
                if (!(ref instanceof String s) || !vmIds.contains(s)) {
                    throw new DifException(400, "invalidDidDocument",
                            rel + " chỉ được tham chiếu tới Verification Method có trong DID Document: " + ref, did);
                }
            }
        }
        validateServices(doc.get("service"), vmIds, did);
    }

    /**
     * Service: id dạng did#tên (không trùng nhau, không trùng id khóa), type bắt buộc,
     * serviceEndpoint là một chuỗi hoặc mảng chuỗi không rỗng.
     */
    private void validateServices(Object value, Set<String> vmIds, String did) {
        Set<String> serviceIds = new HashSet<>();
        String prefix = did + "#";
        for (Object o : asList(value, "service", did)) {
            Map<String, Object> s = asMap(o, "service[]", did);
            String id = asString(s.get("id"), "service[].id", did);
            if (!id.startsWith(prefix) || !SERVICE_FRAGMENT.matcher(id.substring(prefix.length())).matches()) {
                throw new DifException(400, "invalidDidDocument",
                        "id của service phải có dạng " + prefix + "<tên>, nhận được: " + id, did);
            }
            if (!serviceIds.add(id) || vmIds.contains(id)) {
                throw new DifException(400, "invalidDidDocument", "Trùng id service: " + id, did);
            }
            asString(s.get("type"), id + ".type", did);
            Object endpoint = s.get("serviceEndpoint");
            List<Object> endpoints = new ArrayList<>();
            if (endpoint instanceof List<?> list) endpoints.addAll(list);
            else if (endpoint != null) endpoints.add(endpoint);
            if (endpoints.isEmpty()) {
                throw new DifException(400, "invalidDidDocument", id + ".serviceEndpoint là bắt buộc", did);
            }
            for (Object e : endpoints) asString(e, id + ".serviceEndpoint", did);
        }
    }

    // ------------------------------------------------------------------ khóa Ed25519

    /**
     * 32 byte khóa công khai Ed25519 của một Verification Method, hoặc null nếu kiểu/dạng khóa không hỗ trợ.
     *   JsonWebKey2020             : publicKeyJwk.x = base64url(32 byte)
     *   Ed25519VerificationKey2020 : publicKeyMultibase = "z" + base58btc(0xed 0x01 + 32 byte)
     */
    public static byte[] ed25519PublicKey(Map<?, ?> vm) {
        if (vm == null) return null;
        try {
            if ("JsonWebKey2020".equals(vm.get("type")) && vm.get("publicKeyJwk") instanceof Map<?, ?> jwk
                    && jwk.get("x") instanceof String x) {
                byte[] raw = Base64.getUrlDecoder().decode(x);
                return raw.length == 32 ? raw : null;
            }
            if ("Ed25519VerificationKey2020".equals(vm.get("type")) && vm.get("publicKeyMultibase") instanceof String mb
                    && mb.startsWith("z")) {
                byte[] bytes = base58Decode(mb.substring(1));
                if (bytes != null && bytes.length == 34 && (bytes[0] & 0xff) == 0xed && bytes[1] == 0x01) {
                    return Arrays.copyOfRange(bytes, 2, 34);
                }
            }
        } catch (IllegalArgumentException e) {
            return null;
        }
        return null;
    }

    private static byte[] base58Decode(String s) {
        java.math.BigInteger n = java.math.BigInteger.ZERO;
        java.math.BigInteger base = java.math.BigInteger.valueOf(58);
        for (char c : s.toCharArray()) {
            int i = BASE58.indexOf(c);
            if (i < 0) return null;
            n = n.multiply(base).add(java.math.BigInteger.valueOf(i));
        }
        byte[] body = n.signum() == 0 ? new byte[0] : n.toByteArray();
        if (body.length > 1 && body[0] == 0) body = Arrays.copyOfRange(body, 1, body.length); // bỏ byte dấu của BigInteger
        int leadingZeros = 0;
        while (leadingZeros < s.length() && s.charAt(leadingZeros) == '1') leadingZeros++;
        byte[] out = new byte[leadingZeros + body.length];
        System.arraycopy(body, 0, out, leadingZeros, body.length);
        return out;
    }

    // ------------------------------------------------------------------ helper

    private String absolute(String ref, String did) {
        return ref.startsWith("#") ? did + ref : ref;
    }

    private List<Object> absoluteList(Object value, String did) {
        List<Object> out = new ArrayList<>();
        for (Object o : (value instanceof List<?> l ? l : List.of(value))) {
            out.add(o instanceof String s ? absolute(s, did) : o);
        }
        return out;
    }

    private List<?> asList(Object value, String field, String did) {
        if (value == null) return List.of();
        if (value instanceof List<?> l) return l;
        throw new DifException(400, "invalidDidDocument", field + " phải là mảng", did);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> asMap(Object value, String field, String did) {
        if (value instanceof Map<?, ?> m) return (Map<String, Object>) m;
        throw new DifException(400, "invalidDidDocument", field + " phải là object", did);
    }

    private String asString(Object value, String field, String did) {
        if (value instanceof String s && !s.isBlank()) return s;
        throw new DifException(400, "invalidDidDocument", field + " là bắt buộc", did);
    }
}