package com.didregistration.didregistration.repository;

import com.didregistration.didregistration.entity.DidEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface DidRepository extends JpaRepository<DidEntity, String> {

    Optional<DidEntity> findByDidString(String didString);
}