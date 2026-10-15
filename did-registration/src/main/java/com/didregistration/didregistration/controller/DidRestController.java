package com.didregistration.didregistration.controller;

import com.didregistration.didregistration.cheqd.CheqdModuleClient;
import com.didregistration.didregistration.dto.api.OperationResultResponse;
import com.didregistration.didregistration.entity.DidOperationEntity;
import com.didregistration.didregistration.exception.ResourceNotFoundException;
import com.didregistration.didregistration.repository.DidOperationRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tools.jackson.databind.JsonNode;

/**
 * API tra cứu phụ trợ (không thuộc đặc tả DID Registration):
 *   GET /api/v1/did-operations/{jobId}  trạng thái một thao tác
 *   GET /api/v1/dids/{did}              DID Document hiện hành đọc trực tiếp từ mạng cheqd
 */
@RestController
@RequestMapping("/api/v1")
public class DidRestController {

    private final DidOperationRepository didOperationRepository;
    private final CheqdModuleClient cheqdModuleClient;

    public DidRestController(DidOperationRepository didOperationRepository, CheqdModuleClient cheqdModuleClient) {
        this.didOperationRepository = didOperationRepository;
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
}
