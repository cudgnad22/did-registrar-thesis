package com.didregistration.didregistration.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Thông tin về khả năng của Registrar, tương tự GET /1.0/methods và GET /1.0/properties
 * trên trang tài liệu của cheqd did-registrar. Giao diện Client đọc các giá trị này để hiển thị.
 */
@RestController
@RequestMapping("/1.0")
public class RegistrarInfoController {

    @GetMapping("/methods")
    public List<String> methods() {
        return List.of("cheqd");
    }

    @GetMapping("/properties")
    public Map<String, Object> properties() {
        Map<String, Object> cheqd = new LinkedHashMap<>();
        cheqd.put("network", List.of("testnet"));
        cheqd.put("didFormat", "did:cheqd:testnet:<uuid>");
        cheqd.put("secretModes", List.of("clientSecretMode"));
        cheqd.put("operations", List.of("create", "update", "deactivate"));
        cheqd.put("didDocumentOperations", List.of("setDidDocument"));
        cheqd.put("verificationMethodTypes", List.of("JsonWebKey2020"));
        cheqd.put("keyTypes", List.of("Ed25519"));
        cheqd.put("signingAlgorithm", "EdDSA");
        return Map.of("cheqd", cheqd);
    }
}
