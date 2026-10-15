package com.didregistration.didregistration.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Thông tin người sở hữu DID, chỉ lưu tại ứng dụng để quản lý.
 * Không đưa vào DID Document vì DID Document là công khai và mạng cheqd giữ lại mọi phiên bản.
 */
@Entity
@Table(name = "did_owner")
public class DidOwnerEntity {

    @Id
    @Column(name = "did_string", nullable = false)
    private String didString;

    /** jobId của thao tác tạo DID đã dùng để ghi thông tin này. */
    @Column(name = "operation_id", nullable = false)
    private String operationId;

    @Column(name = "full_name", length = 200)
    private String fullName;

    @Column(name = "organization", length = 200)
    private String organization;

    @Column(name = "email", length = 200)
    private String email;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    protected DidOwnerEntity() {
        // required by JPA
    }

    public DidOwnerEntity(String didString, String operationId, String fullName, String organization, String email) {
        this.didString = didString;
        this.operationId = operationId;
        this.fullName = fullName;
        this.organization = organization;
        this.email = email;
        this.createdAt = LocalDateTime.now();
    }

    public String getDidString() { return didString; }
    public String getOperationId() { return operationId; }
    public String getFullName() { return fullName; }
    public String getOrganization() { return organization; }
    public String getEmail() { return email; }
    public LocalDateTime getCreatedAt() { return createdAt; }
}
