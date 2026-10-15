package com.didregistration.didregistration.cheqd.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import tools.jackson.databind.JsonNode;

/**
 * Request gửi tới POST /internal/cheqd/prepare của module did:cheqd.
 * operation: "create" | "update" | "deactivate"; didDocument để null với deactivate.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record PrepareRequest(String operation, String did, JsonNode didDocument) {}