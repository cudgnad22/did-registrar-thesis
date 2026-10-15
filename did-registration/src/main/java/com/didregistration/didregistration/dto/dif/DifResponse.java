package com.didregistration.didregistration.dto.dif;

import java.util.Map;

/**
 * Response theo đặc tả DIF DID Registration: jobId, didState, didRegistrationMetadata, didDocumentMetadata.
 * jobId là null khi didState.state là finished hoặc failed.
 */
public record DifResponse(
        String jobId,
        Map<String, Object> didState,
        Map<String, Object> didRegistrationMetadata,
        Object didDocumentMetadata
) {
}
