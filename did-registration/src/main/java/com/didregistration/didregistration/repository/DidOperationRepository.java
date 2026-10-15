package com.didregistration.didregistration.repository;

import com.didregistration.didregistration.entity.DidOperationEntity;
import com.didregistration.didregistration.entity.DidOperationState;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DidOperationRepository extends JpaRepository<DidOperationEntity, String> {

    /** Dùng để chặn khởi tạo thao tác mới khi DID đang có thao tác gửi lên mạng. */
    boolean existsByTargetDidAndState(String targetDid, DidOperationState state);
}
