package com.didregistration.didregistration.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/** DID do ứng dụng quản lý. Trạng thái chính xác cuối cùng luôn là trạng thái trên mạng cheqd. */
@Entity
@Table(name = "did")
public class DidEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(name = "did_string", nullable = false, unique = true)
    private String didString;              // vd: did:cheqd:testnet:<uuid>

    @Column(name = "label")
    private String label;                  // nhãn tuỳ chọn người dùng đặt

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private DidStatus status;              // ACTIVE, DEACTIVATED

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    protected DidEntity() {
        // required by JPA
    }

    public DidEntity(String didString, String label) {
        this.didString = didString;
        this.label = label;
        this.status = DidStatus.ACTIVE;
        this.createdAt = LocalDateTime.now();
    }

    /** Ghi nhận DID vừa được cập nhật trên mạng (ví dụ sau khi thay khóa). */
    public void touch() {
        this.updatedAt = LocalDateTime.now();
    }

    public String getId() { return id; }
    public String getDidString() { return didString; }
    public String getLabel() { return label; }
    public DidStatus getStatus() { return status; }
    public void setStatus(DidStatus status) {
        this.status = status;
        this.updatedAt = LocalDateTime.now();
    }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getUpdatedAt() { return updatedAt; }
}