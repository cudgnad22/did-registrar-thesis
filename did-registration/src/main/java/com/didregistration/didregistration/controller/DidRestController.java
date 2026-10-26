package com.didregistration.didregistration.controller;

import com.didregistration.didregistration.cheqd.CheqdModuleClient;
import com.didregistration.didregistration.cheqd.CheqdModuleException;
import com.didregistration.didregistration.dto.api.OperationResultResponse;
import com.didregistration.didregistration.entity.DidOperationEntity;
import com.didregistration.didregistration.exception.ResourceNotFoundException;
import com.didregistration.didregistration.repository.DidOperationRepository;
import com.didregistration.didregistration.repository.DidOwnerRepository;
import com.didregistration.didregistration.repository.DidRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tools.jackson.databind.JsonNode;

import java.util.*;

/**
 * API tra cứu phụ trợ (không thuộc đặc tả DID Registration):
 *   GET /api/v1/did-operations/{jobId}  trạng thái một thao tác
 *   GET /api/v1/dids/{did}              DID Document hiện hành đọc trực tiếp từ mạng cheqd
 *   GET /api/v1/dids/{did}/details      gộp: bản trên mạng + bản ghi của ứng dụng + người sở hữu + lịch sử thao tác
 */
@RestController
@RequestMapping("/api/v1")
public class DidRestController {

    private final DidOperationRepository didOperationRepository;
    private final DidRepository didRepository;
    private final DidOwnerRepository didOwnerRepository;
    private final CheqdModuleClient cheqdModuleClient;

    public DidRestController(DidOperationRepository didOperationRepository, DidRepository didRepository,
                             DidOwnerRepository didOwnerRepository, CheqdModuleClient cheqdModuleClient) {
        this.didOperationRepository = didOperationRepository;
        this.didRepository = didRepository;
        this.didOwnerRepository = didOwnerRepository;
        this.cheqdModuleClient = cheqdModuleClient;
    }

    @GetMapping("/did-operations/{operationId}")
    public ResponseEntity<OperationResultResponse> getOperation(@PathVariable String operationId) {
        DidOperationEntity op = didOperationRepository.findById(operationId)
                .orElseThrow(() -> new ResourceNotFoundException("Không tìm thấy thao tác: " + operationId));
        return ResponseEntity.ok(new OperationResultResponse(
                op.getId(), op.getOperationType(), op.getState(), op.getTargetDid(),
                op.getTxHash(), op.getTxHeight(), op.getLedgerCode(), op.getErrorMessage(),
                op.getCreatedAt(), op.getUpdatedAt()));
    }

    @GetMapping("/dids/{did}")
    public ResponseEntity<JsonNode> resolve(@PathVariable String did) {
        return ResponseEntity.ok(cheqdModuleClient.resolve(did));
    }

    /**
     * Thông tin đầy đủ của một DID cho trang cập nhật / vô hiệu hóa.
     * Mạng cheqd là nguồn sự thật (ledger); bản ghi của ứng dụng chỉ bổ sung nhãn, người sở hữu và lịch sử.
     * Không trả jobId của các thao tác: jobId của thao tác tạo DID là bằng chứng để ghi thông tin người sở hữu.
     */
    @GetMapping("/dids/{did}/details")
    public ResponseEntity<Map<String, Object>> details(@PathVariable String did) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("did", did);

        JsonNode ledger = null;
        try {
            ledger = cheqdModuleClient.resolve(did);
        } catch (CheqdModuleException e) {
            if (e.getHttpStatus() != 404) {
                body.put("ledgerError", Map.of("code", e.getCode(), "message", String.valueOf(e.getMessage())));
            }
        }
        body.put("ledger", ledger);

        var app = didRepository.findByDidString(did);
        body.put("app", app.map(d -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("label", d.getLabel());
            m.put("status", d.getStatus());
            m.put("createdAt", d.getCreatedAt());
            m.put("updatedAt", d.getUpdatedAt());
            return m;
        }).orElse(null));

        body.put("owner", didOwnerRepository.findById(did).map(o -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("fullName", o.getFullName());
            m.put("organization", o.getOrganization());
            m.put("email", o.getEmail());
            m.put("createdAt", o.getCreatedAt());
            return m;
        }).orElse(null));

        List<Map<String, Object>> history = new ArrayList<>();
        for (DidOperationEntity op : didOperationRepository.findByTargetDidOrderByCreatedAtAsc(did)) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("operationType", op.getOperationType());
            m.put("state", op.getState());
            m.put("txHash", op.getTxHash());
            m.put("txHeight", op.getTxHeight());
            m.put("ledgerCode", op.getLedgerCode());
            m.put("createdAt", op.getCreatedAt());
            m.put("updatedAt", op.getUpdatedAt());
            history.add(m);
        }
        body.put("operations", history);

        if (ledger == null && app.isEmpty() && history.isEmpty() && !body.containsKey("ledgerError")) {
            throw new ResourceNotFoundException("Không tìm thấy DID trên mạng cheqd và trong ứng dụng: " + did);
        }
        return ResponseEntity.ok(body);
    }
}
