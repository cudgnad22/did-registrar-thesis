package com.didregistration.didregistration.service;

import com.didregistration.didregistration.cheqd.CheqdModuleClient;
import com.didregistration.didregistration.cheqd.CheqdModuleException;
import com.didregistration.didregistration.cheqd.dto.PrepareResponse;
import com.didregistration.didregistration.cheqd.dto.SignatureItem;
import com.didregistration.didregistration.cheqd.dto.SubmitResponse;
import com.didregistration.didregistration.dto.dif.DifRequest;
import com.didregistration.didregistration.dto.dif.DifResponse;
import com.didregistration.didregistration.dto.dif.DifResult;
import com.didregistration.didregistration.entity.*;
import com.didregistration.didregistration.exception.DifException;
import com.didregistration.didregistration.repository.DidOperationRepository;
import com.didregistration.didregistration.repository.DidRepository;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import org.springframework.orm.ObjectOptimisticLockingFailureException;

import java.util.*;

/**
 * DID Registrar cho did:cheqd theo đặc tả DIF DID Registration, Client-managed Secret Mode.
 *
 * Mỗi thao tác gồm hai lần gọi CÙNG một endpoint:
 *   1. Client gửi yêu cầu (create: didDocument; update: did + didDocument; deactivate: did)
 *      -> didState.state = "action", action = "signPayload", kèm signingRequest và jobId
 *   2. Client gửi lại jobId + secret.signingResponse
 *      -> didState.state = "finished" (hoặc "failed")
 *
 * Ứng dụng KHÔNG tiếp nhận và KHÔNG lưu khóa kiểm soát DID.
 */
@Service
public class DidRegistrarService {

    private static final String METHOD = "cheqd";
    private static final String NETWORK = "testnet";
    private static final String ALG = "EdDSA";
    private static final String SET_DID_DOCUMENT = "setDidDocument";

    private final DidRepository didRepository;
    private final DidOperationRepository didOperationRepository;
    private final DidDocumentValidator validator;
    private final CheqdModuleClient cheqdModuleClient;
    private final ObjectMapper objectMapper;

    public DidRegistrarService(DidRepository didRepository,
                               DidOperationRepository didOperationRepository,
                               DidDocumentValidator validator,
                               CheqdModuleClient cheqdModuleClient,
                               ObjectMapper objectMapper) {
        this.didRepository = didRepository;
        this.didOperationRepository = didOperationRepository;
        this.validator = validator;
        this.cheqdModuleClient = cheqdModuleClient;
        this.objectMapper = objectMapper;
    }

    // =====================================================================
    // create()
    // =====================================================================

    public DifResult create(String methodParam, DifRequest req) {
        if (req.jobId() != null) return continueJob(req, OperationType.CREATE);

        String method = methodParam != null ? methodParam : req.method();
        if (!METHOD.equals(method)) {
            throw new DifException(400, "unsupportedMethod", "Chỉ hỗ trợ DID Method cheqd (method=cheqd), nhận được: " + method);
        }
        checkOptions(req.options());
        if (!(req.didDocument() instanceof Map<?, ?>)) {
            throw new DifException(400, "invalidDidDocument",
                    "Client-managed Secret Mode: didDocument (một object) chứa khóa công khai của Client là bắt buộc");
        }
        Map<String, Object> input = castMap(req.didDocument());

        // DID do Client chỉ định (did hoặc didDocument.id), nếu không thì Registrar sinh mới
        String did = req.did() != null ? req.did()
                : input.get("id") instanceof String id ? id
                : DidDocumentValidator.DID_PREFIX + UUID.randomUUID();
        validator.checkDidFormat(did);
        if (didRepository.findByDidString(did).isPresent()) {
            throw new DifException(400, "didAlreadyExists", "DID đã tồn tại: " + did, did);
        }

        Map<String, Object> didDocument = validator.normalize(input, did);
        validator.validate(didDocument, did);

        PrepareResponse prepared = prepare("create", did, didDocument);
        DidOperationEntity op = saveOperation(OperationType.CREATE, did, optionLabel(req.options()), didDocument, prepared);
        return actionResult(op, 200, null, null);
    }

    // =====================================================================
    // update()
    // =====================================================================

    public DifResult update(DifRequest req) {
        if (req.jobId() != null) return continueJob(req, OperationType.UPDATE);

        String did = requireDid(req.did());
        checkOptions(req.options());
        List<String> operations = req.didDocumentOperation() == null ? List.of(SET_DID_DOCUMENT) : req.didDocumentOperation();
        if (!operations.equals(List.of(SET_DID_DOCUMENT))) {
            throw new DifException(400, "unsupportedDidDocumentOperation",
                    "Chỉ hỗ trợ didDocumentOperation [\"setDidDocument\"], nhận được: " + operations, did);
        }

        // Đặc tả: didDocument của update là MẢNG object; chấp nhận thêm một object đơn lẻ
        Object value = req.didDocument();
        if (value instanceof List<?> list && list.size() == 1) value = list.get(0);
        if (!(value instanceof Map<?, ?>)) {
            throw new DifException(400, "invalidDidDocument",
                    "setDidDocument: didDocument phải là mảng gồm đúng một DID Document mới", did);
        }
        ensureUsable(did);

        Map<String, Object> didDocument = validator.normalize(castMap(value), did);
        validator.validate(didDocument, did);

        PrepareResponse prepared = prepare("update", did, didDocument);
        DidOperationEntity op = saveOperation(OperationType.UPDATE, did, null, didDocument, prepared);
        return actionResult(op, 200, null, null);
    }

    // =====================================================================
    // deactivate()
    // =====================================================================

    public DifResult deactivate(DifRequest req) {
        if (req.jobId() != null) return continueJob(req, OperationType.DEACTIVATE);

        String did = requireDid(req.did());
        checkOptions(req.options());
        if (req.didDocument() != null) {
            throw new DifException(400, "invalidRequest", "deactivate: không được gửi didDocument", did);
        }
        ensureUsable(did);

        PrepareResponse prepared = prepare("deactivate", did, null);
        DidOperationEntity op = saveOperation(OperationType.DEACTIVATE, did, null, null, prepared);
        return actionResult(op, 200, null, null);
    }

    // =====================================================================
    // Lần gọi thứ hai: jobId + secret.signingResponse
    // =====================================================================

    private DifResult continueJob(DifRequest req, OperationType expectedType) {
        DidOperationEntity op = didOperationRepository.findById(req.jobId())
                .orElseThrow(() -> new DifException(400, "unknownJobId", "Không tìm thấy jobId: " + req.jobId()));
        if (op.getOperationType() != expectedType) {
            throw new DifException(400, "invalidJobId",
                    "jobId thuộc thao tác " + op.getOperationType() + ", không phải " + expectedType, op.getTargetDid());
        }

        switch (op.getState()) {
            case COMPLETED: return finishedFromRecord(op);
            case FAILED: return failedResult(op, 400, "operationFailed", op.getErrorMessage(), null);
            case SUBMITTING: return waitResult(op);
            default: break; // AWAITING_SIGNATURE
        }

        Object signingResponse = req.secret() == null ? null : req.secret().get("signingResponse");
        if (signingResponse == null) {
            // Client gọi lại với jobId nhưng chưa ký: trả lại yêu cầu ký hiện tại
            return actionResult(op, 200, null, null);
        }
        if (!(signingResponse instanceof Map<?, ?>)) {
            return actionResult(op, 400, "invalidSigningResponse", "secret.signingResponse phải là object");
        }

        // Ghép mỗi signingRequestN với khóa đã được yêu cầu (không tin kid do Client tự khai)
        List<SignatureItem> signatures = new ArrayList<>();
        List<String> signers = op.getRequiredSignerList();
        Map<String, Object> responses = castMap(signingResponse);
        for (int i = 0; i < signers.size(); i++) {
            String requestId = signingRequestId(i);
            if (!(responses.get(requestId) instanceof Map<?, ?> r)) {
                return actionResult(op, 400, "missingSignature", "Thiếu chữ ký cho " + requestId + " (" + signers.get(i) + ")");
            }
            Object kid = r.get("kid");
            Object alg = r.get("alg");
            if (kid != null && !signers.get(i).equals(kid)) {
                return actionResult(op, 400, "kidMismatch", requestId + ": kid phải là " + signers.get(i) + ", nhận được " + kid);
            }
            if (alg != null && !ALG.equals(alg)) {
                return actionResult(op, 400, "unsupportedAlgorithm", requestId + ": alg phải là " + ALG);
            }
            if (!(r.get("signature") instanceof String signature) || signature.isBlank()) {
                return actionResult(op, 400, "missingSignature", requestId + ": thiếu signature");
            }
            signatures.add(new SignatureItem(signers.get(i), signature));
        }

        // Chặn gửi trùng: nếu một yêu cầu khác cùng jobId đã chuyển sang SUBMITTING trước,
        // lần lưu này bị từ chối vì phiên bản bản ghi đã cũ
        op.markSubmitting();
        try {
            op = didOperationRepository.save(op);
        } catch (ObjectOptimisticLockingFailureException e) {
            return waitResult(op);
        }

        SubmitResponse result;
        try {
            // Gửi lại ĐÚNG DID Document và versionId đã dùng ở lần gọi đầu
            result = cheqdModuleClient.submit(
                    op.getOperationType().name().toLowerCase(), op.getTargetDid(),
                    readTree(op.getDidDocumentJson()), op.getVersionId(), signatures);
        } catch (CheqdModuleException e) {
            String message = e.getCode() + ": " + e.getMessage();
            if (e.getHttpStatus() == 400 || e.isRetryable()) {
                // Chữ ký sai / hạ tầng tạm lỗi: chưa có gì được ghi lên mạng, Client có thể gửi lại
                op.backToAwaitingSignature(message);
                didOperationRepository.save(op);
                return actionResult(op, e.isRetryable() ? 500 : 400, DifException.reasonOf(e.getCode()), e.getMessage());
            }
            op.markFailed(null, null, message);
            didOperationRepository.save(op);
            return failedResult(op, 400, DifException.reasonOf(e.getCode()), e.getMessage(), null);
        }

        if (!result.success()) {
            String message = "Ledger code " + result.code() + ": " + result.rawLog();
            op.markFailed(result.code(), result.txHash(), message);
            didOperationRepository.save(op);
            Map<String, Object> meta = new LinkedHashMap<>();
            meta.put("ledgerCode", result.code());
            meta.put("txHash", result.txHash());
            return failedResult(op, 400, "ledgerRejected", result.rawLog(), meta);
        }

        applySuccess(op);
        op.markCompleted(result.txHash(), result.height());
        didOperationRepository.save(op);
        return finishedResult(op, result);
    }

    // =====================================================================
    // Cập nhật cơ sở dữ liệu sau khi mạng xác nhận
    // =====================================================================

    private void applySuccess(DidOperationEntity op) {
        String did = op.getTargetDid();
        switch (op.getOperationType()) {
            case CREATE -> didRepository.save(new DidEntity(did, op.getLabel()));
            case UPDATE -> {
                DidEntity didEntity = findOrCreateDid(did);
                didEntity.touch();
                didRepository.save(didEntity);
            }
            case DEACTIVATE -> {
                DidEntity didEntity = findOrCreateDid(did);
                didEntity.setStatus(DidStatus.DEACTIVATED);
                didRepository.save(didEntity);
            }
        }
    }

    /** DID chưa từng đăng ký qua ứng dụng này (nhưng tồn tại trên mạng) thì tạo bản ghi khi cập nhật. */
    private DidEntity findOrCreateDid(String did) {
        return didRepository.findByDidString(did).orElseGet(() -> didRepository.save(new DidEntity(did, null)));
    }

    // =====================================================================
    // Dựng response theo đặc tả
    // =====================================================================

    private static String signingRequestId(int index) {
        return "signingRequest" + index;
    }

    /** didState.state = "action", action = "signPayload" với Signing Request Set */
    private DifResult actionResult(DidOperationEntity op, int httpStatus, String error, String errorMessage) {
        Map<String, Object> payload = new LinkedHashMap<>(); // dạng JSON "để tham khảo" (informational) theo đặc tả
        if (op.getDidDocumentJson() != null) payload.put("didDocument", readTree(op.getDidDocumentJson()));
        else payload.put("id", op.getTargetDid());
        payload.put("versionId", op.getVersionId());

        Map<String, Object> signingRequest = new LinkedHashMap<>();
        List<String> signers = op.getRequiredSignerList();
        for (int i = 0; i < signers.size(); i++) {
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("payload", payload);
            r.put("serializedPayload", op.getSerializedPayload());
            r.put("kid", signers.get(i));
            r.put("alg", ALG);
            r.put("purpose", "authentication");
            signingRequest.put(signingRequestId(i), r);
        }

        Map<String, Object> didState = new LinkedHashMap<>();
        didState.put("state", "action");
        didState.put("action", "signPayload");
        didState.put("did", op.getTargetDid());
        didState.put("description", "Ký serializedPayload bằng khóa kid của từng signingRequest, "
                + "rồi gửi lại jobId kèm secret.signingResponse");
        didState.put("signingRequest", signingRequest);

        Map<String, Object> meta = registrationMetadata(op);
        if (error != null) {
            meta.put("error", error);
            meta.put("errorMessage", errorMessage);
        }
        return new DifResult(httpStatus, new DifResponse(op.getId(), didState, meta, Map.of()));
    }

    private DifResult waitResult(DidOperationEntity op) {
        Map<String, Object> didState = new LinkedHashMap<>();
        didState.put("state", "wait");
        didState.put("did", op.getTargetDid());
        didState.put("wait", "Giao dịch đang được gửi lên mạng cheqd, hãy gọi lại sau");
        didState.put("waitTime", 3000);
        return new DifResult(200, new DifResponse(op.getId(), didState, registrationMetadata(op), Map.of()));
    }

    private DifResult finishedResult(DidOperationEntity op, SubmitResponse result) {
        Map<String, Object> didState = new LinkedHashMap<>();
        didState.put("state", "finished");
        didState.put("did", op.getTargetDid());
        if (result.didDocument() != null) didState.put("didDocument", result.didDocument());

        Map<String, Object> meta = registrationMetadata(op);
        meta.put("txHash", result.txHash());
        meta.put("height", result.height());
        meta.put("durationMs", result.elapsedMs());

        Object docMeta = result.didDocumentMetadata() != null ? result.didDocumentMetadata() : Map.of();
        // HTTPS binding: create hoàn tất -> 201; update/deactivate -> 200
        int status = op.getOperationType() == OperationType.CREATE ? 201 : 200;
        return new DifResult(status, new DifResponse(null, didState, meta, docMeta));
    }

    /** Client gọi lại jobId của thao tác đã hoàn tất: trả kết quả đã lưu */
    private DifResult finishedFromRecord(DidOperationEntity op) {
        Map<String, Object> didState = new LinkedHashMap<>();
        didState.put("state", "finished");
        didState.put("did", op.getTargetDid());
        Map<String, Object> meta = registrationMetadata(op);
        meta.put("txHash", op.getTxHash());
        meta.put("height", op.getTxHeight());
        return new DifResult(200, new DifResponse(null, didState, meta, Map.of()));
    }

    private DifResult failedResult(DidOperationEntity op, int status, String reason, String description,
                                   Map<String, Object> extraMeta) {
        Map<String, Object> didState = new LinkedHashMap<>();
        didState.put("state", "failed");
        didState.put("did", op.getTargetDid());
        didState.put("reason", reason);
        didState.put("description", description);
        Map<String, Object> meta = registrationMetadata(op);
        if (extraMeta != null) meta.putAll(extraMeta);
        return new DifResult(status, new DifResponse(null, didState, meta, Map.of()));
    }

    private Map<String, Object> registrationMetadata(DidOperationEntity op) {
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("method", METHOD);
        meta.put("network", NETWORK);
        meta.put("operation", op.getOperationType().name().toLowerCase());
        meta.put("operationId", op.getId());
        meta.put("versionId", op.getVersionId());
        return meta;
    }

    // =====================================================================
    // Helper
    // =====================================================================

    private PrepareResponse prepare(String operation, String did, Map<String, Object> didDocument) {
        JsonNode doc = didDocument == null ? null : objectMapper.valueToTree(didDocument);
        return cheqdModuleClient.prepare(operation, did, doc);
    }

    private DidOperationEntity saveOperation(OperationType type, String did, String label,
                                             Map<String, Object> didDocument, PrepareResponse prepared) {
        String json = didDocument == null ? null : objectMapper.writeValueAsString(didDocument);
        return didOperationRepository.save(new DidOperationEntity(
                type, did, label, json, prepared.versionId(), prepared.signBytes(),
                prepared.requiredSigners(), ALG));
    }

    /** Options theo đặc tả: chỉ hỗ trợ clientSecretMode = true và network = testnet */
    private void checkOptions(Map<String, Object> options) {
        if (options == null) return;
        Object mode = options.get("clientSecretMode");
        if (mode != null && !Boolean.TRUE.equals(mode)) {
            throw new DifException(400, "unsupportedSecretMode",
                    "Registrar chỉ hoạt động ở Client-managed Secret Mode (options.clientSecretMode = true)");
        }
        Object network = options.get("network");
        if (network != null && !NETWORK.equals(network)) {
            throw new DifException(400, "unsupportedNetwork", "Chỉ hỗ trợ network = testnet (cheqd localnet)");
        }
    }

    private String optionLabel(Map<String, Object> options) {
        return options != null && options.get("label") instanceof String s ? s : null;
    }

    private String requireDid(String did) {
        if (did == null || did.isBlank()) throw new DifException(400, "invalidRequest", "did là bắt buộc");
        validator.checkDidFormat(did);
        return did;
    }

    /** Chặn thao tác trên DID đã vô hiệu hóa (theo bản ghi) hoặc đang có giao dịch chờ mạng. */
    private void ensureUsable(String did) {
        didRepository.findByDidString(did).ifPresent(d -> {
            if (d.getStatus() == DidStatus.DEACTIVATED) {
                throw new DifException(400, "didDeactivated", "DID đã bị vô hiệu hóa: " + did, did);
            }
        });
        if (didOperationRepository.existsByTargetDidAndState(did, DidOperationState.SUBMITTING)) {
            throw new DifException(400, "operationInProgress", "DID đang có giao dịch chờ mạng xác nhận", did);
        }
    }

    private JsonNode readTree(String json) {
        return json == null ? null : objectMapper.readTree(json);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castMap(Object value) {
        return (Map<String, Object>) value;
    }
}