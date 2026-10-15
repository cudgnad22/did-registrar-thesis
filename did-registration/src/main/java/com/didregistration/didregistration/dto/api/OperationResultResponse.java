package com.didregistration.didregistration.dto.api;

import com.didregistration.didregistration.entity.DidOperationState;
import com.didregistration.didregistration.entity.OperationType;

import java.time.LocalDateTime;

/** Trạng thái/kết quả của một thao tác. */
public record OperationResultResponse(
        String operationId,
        OperationType operationType,
        DidOperationState state,
        String did,
        String txHash,
        Long txHeight,
        Integer ledgerCode,
        String errorMessage,
        LocalDateTime createdAt,
        LocalDateTime updatedAt
) {
}