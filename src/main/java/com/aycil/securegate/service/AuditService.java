package com.aycil.securegate.service;

import com.aycil.securegate.model.AuditLog;
import com.aycil.securegate.model.PolicyDecision;
import com.aycil.securegate.model.PrincipalType;
import com.aycil.securegate.repository.AuditLogRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AuditService {

    private final AuditLogRepository auditLogRepository;

    public AuditService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    public void record(
            String actor,
            PrincipalType principalType,
            String action,
            String resource,
            int riskScore,
            PolicyDecision decision,
            String reason
    ) {
        AuditLog log = new AuditLog();
        log.setActor(actor);
        log.setPrincipalType(principalType);
        log.setAction(action);
        log.setResource(resource);
        log.setRiskScore(riskScore);
        log.setDecision(decision);
        log.setReason(reason);
        auditLogRepository.save(log);
    }

    public List<AuditLog> recentLogs(String decisionFilter) {
        if (decisionFilter != null && !decisionFilter.isBlank()) {
            try {
                PolicyDecision parsed = PolicyDecision.valueOf(decisionFilter.trim().toUpperCase());
                return auditLogRepository.findTop50ByDecisionOrderByTimestampDesc(parsed);
            } catch (IllegalArgumentException ignored) {
                return List.of();
            }
        }
        return auditLogRepository.findTop50ByOrderByTimestampDesc();
    }
}
