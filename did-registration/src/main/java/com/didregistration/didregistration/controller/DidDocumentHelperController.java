package com.didregistration.didregistration.controller;

import com.didregistration.didregistration.dto.api.ApiErrorResponse;
import com.didregistration.didregistration.exception.DifException;
import com.didregistration.didregistration.service.DidDocumentTemplateService;
import com.didregistration.didregistration.service.DidDocumentTemplateService.TemplateException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Điểm cuối hỗ trợ, tương tự "Cheqd Helpers" của cheqd did-registrar:
 *   GET /1.0/did-document?publicKeyJwk=...            mẫu DID Document cho DID mới
 *   GET /1.0/did-document?publicKeyJwk=...&did=...    mẫu DID Document để thay khóa
 * Chỉ nhận khóa công khai. Không có điểm cuối sinh khóa: khóa bí mật luôn được sinh ở phía Client.
 */
@RestController
@RequestMapping("/1.0")
public class DidDocumentHelperController {

    private final DidDocumentTemplateService templateService;

    public DidDocumentHelperController(DidDocumentTemplateService templateService) {
        this.templateService = templateService;
    }

    @GetMapping("/did-document")
    public ResponseEntity<?> didDocument(@RequestParam(required = false) String publicKeyJwk,
                                         @RequestParam(required = false) String publicKeyHex,
                                         @RequestParam(required = false) String did) {
        try {
            return ResponseEntity.ok(templateService.build(publicKeyJwk, publicKeyHex, did));
        } catch (TemplateException e) {
            return ResponseEntity.status(e.getStatus()).body(ApiErrorResponse.of(e.getCode(), e.getMessage()));
        } catch (DifException e) {
            return ResponseEntity.status(e.getHttpStatus()).body(ApiErrorResponse.of("INVALID_DID", e.getMessage()));
        }
    }
}
