package com.didregistration.didregistration.entity;

import jakarta.persistence.*;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;

/**
 * Một thao tác Create / Update / Deactivate đang được điều phối.
 * Lưu đủ dữ liệu để bước submit gửi đúng dữ liệu Client đã ký (module không lưu trạng thái).
 */
@Entity
@Table(name = "did_operation")
public class DidOperationEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    /** Khóa lạc quan: hai yêu cầu cùng jobId thì chỉ một yêu cầu được chuyển sang SUBMITTING. */
    @Version
    private Long version;

    @Enumerated(EnumType.STRING)
    @Column(name = "operation_type", nullable = false)
    private OperationType operationType;

    @Enumerated(EnumType.STRING)
    @Column(name = "state", nullable = false)
    private DidOperationState state;

    /* DID mà thao tác đang xử lý. */
    @Column(name = "target_did", nullable = false)
    private String targetDid;

    /* Nhãn quản lý do Client truyền vào (chỉ dùng với Create). */
    @Column(name = "label")
    private String label;

    /* DID Document đã gửi ở bước prepare, lưu NGUYÊN VĂN để gửi lại đúng như cũ ở bước submit. */
    @Column(name = "did_document_json", columnDefinition = "TEXT")
    private String didDocumentJson;

    /* versionId do module sinh ở bước prepare; phải dùng lại ở bước submit. */
    @Column(name = "version_id")
    private String versionId;

    /* Dữ liệu cần ký (base64) trả cho Client. Không phải private key. */
    @Column(name = "serialized_payload", nullable = false, columnDefinition = "TEXT")
    private String serializedPayload;

    /* Danh sách id Verification Method phải ký, phân tách bằng dấu phẩy. */
    @Column(name = "required_signers", columnDefinition = "TEXT")
    private String requiredSigners;

    @Column(name = "signing_algorithm", nullable = false)
    private String signingAlgorithm;

    /* Kết quả giao dịch trên mạng cheqd. */
    @Column(name = "tx_hash")
    private String txHash;

    @Column(name = "tx_height")
    private Long txHeight;

    /* Mã phản hồi của mạng: 0 thành công, 1100 chữ ký sai, 1207 DID đã vô hiệu hóa... */
    @Column(name = "ledger_code")
    private Integer ledgerCode;

    @Column(name = "error_message", columnDefinition = "TEXT")
    private String errorMessage;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    protected DidOperationEntity() {
        // required by JPA
    }

    public DidOperationEntity(
            OperationType operationType,
            String targetDid,
            String label,
            String didDocumentJson,
            String versionId,
            String serializedPayload,
            List<String> requiredSigners,
            String signingAlgorithm
    ) {
        this.operationType = operationType;
        this.targetDid = targetDid;
        this.label = label;
        this.didDocumentJson = didDocumentJson;
        this.versionId = versionId;
        this.serializedPayload = serializedPayload;
        this.requiredSigners = String.join(",", requiredSigners);
        this.signingAlgorithm = signingAlgorithm;
        this.state = DidOperationState.AWAITING_SIGNATURE;
        this.createdAt = LocalDateTime.now();
        this.updatedAt = this.createdAt;
    }

    /** Đã nhận chữ ký, đang gửi tới mạng: chặn gửi trùng. */
    public void markSubmitting() {
        this.state = DidOperationState.SUBMITTING;
        this.updatedAt = LocalDateTime.now();
    }

    /** Lỗi có thể khắc phục (chữ ký sai, module/mạng tạm thời lỗi): cho phép Client gửi lại. */
    public void backToAwaitingSignature(String errorMessage) {
        this.state = DidOperationState.AWAITING_SIGNATURE;
        this.errorMessage = errorMessage;
        this.updatedAt = LocalDateTime.now();
    }

    public void markCompleted(String txHash, long txHeight) {
        this.state = DidOperationState.COMPLETED;
        this.txHash = txHash;
        this.txHeight = txHeight;
        this.ledgerCode = 0;
        this.errorMessage = null;
        this.updatedAt = LocalDateTime.now();
    }

    public void markFailed(Integer ledgerCode, String txHash, String errorMessage) {
        this.state = DidOperationState.FAILED;
        this.ledgerCode = ledgerCode;
        this.txHash = txHash;
        this.errorMessage = errorMessage;
        this.updatedAt = LocalDateTime.now();
    }

    public List<String> getRequiredSignerList() {
        return requiredSigners == null || requiredSigners.isBlank()
                ? List.of()
                : Arrays.asList(requiredSigners.split(","));
    }

    public String getId() { return id; }
    public OperationType getOperationType() { return operationType; }
    public DidOperationState getState() { return state; }
    public String getTargetDid() { return targetDid; }
    public String getLabel() { return label; }
    public String getDidDocumentJson() { return didDocumentJson; }
    public String getVersionId() { return versionId; }
    public String getSerializedPayload() { return serializedPayload; }
    public String getSigningAlgorithm() { return signingAlgorithm; }
    public String getTxHash() { return txHash; }
    public Long getTxHeight() { return txHeight; }
    public Integer getLedgerCode() { return ledgerCode; }
    public String getErrorMessage() { return errorMessage; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getUpdatedAt() { return updatedAt; }
}
