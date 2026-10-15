package com.didregistration.didregistration.controller;

import com.didregistration.didregistration.dto.api.ApiErrorResponse;
import com.didregistration.didregistration.dto.api.OwnerInfoRequest;
import com.didregistration.didregistration.entity.*;
import com.didregistration.didregistration.repository.DidOperationRepository;
import com.didregistration.didregistration.repository.DidOwnerRepository;
import com.didregistration.didregistration.repository.DidRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.regex.Pattern;

/**
 * API phụ trợ cho giao diện trực quan (không thuộc đặc tả DID Registration):
 *   GET /api/v1/dids                               danh sách DID do ứng dụng quản lý, kèm người sở hữu
 *   PUT /api/v1/did-operations/{jobId}/owner       ghi thông tin người sở hữu sau khi tạo DID thành công
 *
 * Thông tin người sở hữu chỉ được ghi một lần, bằng jobId của chính thao tác tạo DID đã hoàn tất.
 * jobId chỉ bên tạo DID biết, nên đóng vai trò bằng chứng gắn với thao tác đó.
 */
@RestController
@RequestMapping("/api/v1")
public class UiSupportController {

    private static final Pattern EMAIL = Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");
    private static final int MAX_LEN = 200;

    private final DidRepository didRepository;
    private final DidOperationRepository didOperationRepository;
    private final DidOwnerRepository didOwnerRepository;

    public UiSupportController(DidRepository didRepository, DidOperationRepository didOperationRepository,
                               DidOwnerRepository didOwnerRepository) {
        this.didRepository = didRepository;
        this.didOperationRepository = didOperationRepository;
        this.didOwnerRepository = didOwnerRepository;
    }

    @GetMapping("/dids")
    public List<Map<String, Object>> listDids() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (DidEntity d : didRepository.findAll()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("did", d.getDidString());
            row.put("label", d.getLabel());
            row.put("status", d.getStatus());
            row.put("createdAt", d.getCreatedAt());
            row.put("updatedAt", d.getUpdatedAt());
            didOwnerRepository.findById(d.getDidString()).ifPresent(o -> row.put("owner", ownerMap(o)));
            out.add(row);
        }
        out.sort(Comparator.comparing((Map<String, Object> r) -> String.valueOf(r.get("createdAt"))).reversed());
        return out;
    }

    @PutMapping("/did-operations/{jobId}/owner")
    public ResponseEntity<?> saveOwner(@PathVariable String jobId, @RequestBody OwnerInfoRequest req) {
        Optional<DidOperationEntity> found = didOperationRepository.findById(jobId);
        if (found.isEmpty()) return error(404, "NOT_FOUND", "Không tìm thấy thao tác: " + jobId);
        DidOperationEntity op = found.get();
        if (op.getOperationType() != OperationType.CREATE || op.getState() != DidOperationState.COMPLETED) {
            return error(409, "OPERATION_NOT_COMPLETED", "Chỉ ghi được sau khi thao tác tạo DID đã hoàn tất");
        }
        if (didOwnerRepository.existsById(op.getTargetDid())) {
            return error(409, "OWNER_ALREADY_SET", "DID này đã có thông tin người sở hữu");
        }
        String name = clean(req.fullName()), org = clean(req.organization()), email = clean(req.email());
        if (name == null && org == null && email == null) return error(400, "EMPTY_OWNER", "Chưa nhập thông tin người sở hữu");
        for (String s : new String[]{name, org, email}) {
            if (s != null && s.length() > MAX_LEN) return error(400, "TOO_LONG", "Mỗi trường tối đa " + MAX_LEN + " ký tự");
        }
        if (email != null && !EMAIL.matcher(email).matches()) return error(400, "INVALID_EMAIL", "Email không hợp lệ");

        DidOwnerEntity saved = didOwnerRepository.save(new DidOwnerEntity(op.getTargetDid(), jobId, name, org, email));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("did", saved.getDidString());
        body.put("owner", ownerMap(saved));
        return ResponseEntity.ok(body);
    }

    private static Map<String, Object> ownerMap(DidOwnerEntity o) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("fullName", o.getFullName());
        m.put("organization", o.getOrganization());
        m.put("email", o.getEmail());
        m.put("createdAt", o.getCreatedAt());
        return m;
    }

    private static String clean(String s) {
        return s == null || s.isBlank() ? null : s.trim();
    }

    private static ResponseEntity<ApiErrorResponse> error(int status, String code, String message) {
        return ResponseEntity.status(status).body(ApiErrorResponse.of(code, message));
    }
}
