package com.aycil.securegate.controller;

import com.aycil.securegate.model.PrincipalType;
import com.aycil.securegate.model.UserAccount;
import com.aycil.securegate.policy.AccessRequestContext;
import com.aycil.securegate.policy.PolicyEvaluationResult;
import com.aycil.securegate.policy.RiskScoringService;
import com.aycil.securegate.policy.ZeroTrustPolicyEngine;
import com.aycil.securegate.repository.UserAccountRepository;
import com.aycil.securegate.service.AuditService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/api/resources")
public class PolicyGateController {

    private final UserAccountRepository userAccountRepository;
    private final ZeroTrustPolicyEngine policyEngine;
    private final RiskScoringService riskScoringService;
    private final AuditService auditService;

    public PolicyGateController(
            UserAccountRepository userAccountRepository,
            ZeroTrustPolicyEngine policyEngine,
            RiskScoringService riskScoringService,
            AuditService auditService
    ) {
        this.userAccountRepository = userAccountRepository;
        this.policyEngine = policyEngine;
        this.riskScoringService = riskScoringService;
        this.auditService = auditService;
    }

    @GetMapping("/telemetry")
    public ResponseEntity<Map<String, Object>> readTelemetry(
            Authentication authentication,
            @RequestHeader(name = "X-Risk-Score", defaultValue = "15") int riskScore
    ) {
        return evaluateAndRespond(
                authentication,
                "READ_TELEMETRY",
                "/api/resources/telemetry",
                "read:telemetry",
                false,
                riskScore,
                Map.of("status", "ok", "stream", "security-events-v1", "anomalyCount", 2)
        );
    }

    @GetMapping("/knowledge-base")
    public ResponseEntity<Map<String, Object>> queryKnowledgeBase(
            Authentication authentication,
            @RequestParam(defaultValue = "zero-trust-baseline") String topic,
            @RequestHeader(name = "X-Risk-Score", defaultValue = "20") int riskScore
    ) {
        return evaluateAndRespond(
                authentication,
                "QUERY_KNOWLEDGE_BASE",
                "/api/resources/knowledge-base?topic=" + topic,
                "query:knowledge_base",
                false,
                riskScore,
                Map.of("topic", topic, "summary", "Policy-approved reference document")
        );
    }

    @GetMapping("/sensitive-db")
    public ResponseEntity<Map<String, Object>> readSensitiveDb(
            Authentication authentication,
            @RequestHeader(name = "X-Risk-Score", defaultValue = "25") int riskScore
    ) {
        return evaluateAndRespond(
                authentication,
                "ACCESS_SENSITIVE_DB",
                "/api/resources/sensitive-db",
                "access:sensitive_db",
                true,
                riskScore,
                Map.of("classification", "RESTRICTED", "records", 148, "note", "Human-only audited access")
        );
    }

    private ResponseEntity<Map<String, Object>> evaluateAndRespond(
            Authentication authentication,
            String action,
            String resource,
            String requiredScope,
            boolean sensitiveResource,
            int riskScore,
            Map<String, Object> payload
    ) {
        String actorName = authentication != null ? authentication.getName() : "anonymous";
        UserAccount account = userAccountRepository.findByUsername(actorName).orElse(null);

        PrincipalType principalType = account != null ? account.getPrincipalType() : PrincipalType.HUMAN;
        Set<String> scopes = account != null ? account.getScopes() : Set.of();

        RiskScoringService.RiskAssessment assessment = riskScoringService.assess(
                actorName, principalType, sensitiveResource, riskScore
        );

        AccessRequestContext ctx = new AccessRequestContext(
                actorName,
                principalType,
                scopes,
                requiredScope,
                resource,
                sensitiveResource,
                assessment.effectiveRiskScore()
        );

        PolicyEvaluationResult result = policyEngine.evaluate(ctx);
        String auditReason = result.reason() + " [" + assessment.summary() + "]";

        auditService.record(
                actorName,
                principalType,
                action,
                resource,
                result.riskScore(),
                result.decision(),
                auditReason
        );

        if (!result.isAllowed()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                    "decision", result.decision(),
                    "riskScore", result.riskScore(),
                    "riskAssessment", assessment.summary(),
                    "reason", result.reason()
            ));
        }

        return ResponseEntity.ok(Map.of(
                "decision", result.decision(),
                "riskScore", result.riskScore(),
                "riskAssessment", assessment.summary(),
                "reason", result.reason(),
                "data", payload
        ));
    }
}
