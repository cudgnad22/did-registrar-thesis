package com.didregistration.didregistration.entity;

/**
 * Trạng thái thao tác, ánh xạ sang didState.state của DID Registration:
 *   AWAITING_SIGNATURE -> action (signPayload)
 *   SUBMITTING         -> wait
 *   COMPLETED          -> finished
 *   FAILED             -> failed
 */
public enum DidOperationState {

    AWAITING_SIGNATURE,

    SUBMITTING,

    COMPLETED,

    FAILED
}
