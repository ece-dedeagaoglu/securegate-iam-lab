package com.aycil.securegate.repository;

import com.aycil.securegate.model.AuditLog;
import com.aycil.securegate.model.PolicyDecision;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
    List<AuditLog> findTop50ByOrderByTimestampDesc();
    List<AuditLog> findTop50ByDecisionOrderByTimestampDesc(PolicyDecision decision);
}
