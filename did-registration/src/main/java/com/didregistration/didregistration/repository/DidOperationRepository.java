package com.didregistration.didregistration.repository;

import com.didregistration.didregistration.entity.DidOperationEntity;
import com.didregistration.didregistration.entity.DidOperationState;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface DidOperationRepository extends JpaRepository<DidOperationEntity, String> {

    /** Dùng để chặn khởi tạo thao tác mới khi DID đang có thao tác gửi lên mạng. */
    boolean existsByTargetDidAndState(String targetDid, DidOperationState state);

    /** Lịch sử thao tác của một DID, theo thời gian. */
    List<DidOperationEntity> findByTargetDidOrderByCreatedAtAsc(String targetDid);
}
