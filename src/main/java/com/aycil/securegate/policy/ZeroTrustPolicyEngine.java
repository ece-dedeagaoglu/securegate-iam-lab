package com.aycil.securegate.policy;

import com.aycil.securegate.model.PolicyDecision;
import com.aycil.securegate.model.PrincipalType;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class ZeroTrustPolicyEngine {

    private final int aiAgentRiskThreshold;
    private final int humanRiskThreshold;

    public ZeroTrustPolicyEngine(
            @Value("${security.policy.ai-agent-risk-threshold:50}") int aiAgentRiskThreshold,
            @Value("${security.policy.human-risk-threshold:80}") int humanRiskThreshold
    ) {
        this.aiAgentRiskThreshold = aiAgentRiskThreshold;
        this.humanRiskThreshold = humanRiskThreshold;
    }

    public PolicyEvaluationResult evaluate(AccessRequestContext ctx) {
        int normalizedRisk = Math.max(0, Math.min(100, ctx.riskScore()));

        if (ctx.requiredScope() != null && !ctx.requiredScope().isBlank()
                && !ctx.scopes().contains(ctx.requiredScope())) {
            return new PolicyEvaluationResult(
                    PolicyDecision.DENY,
                    normalizedRisk,
                    "Missing required scope: " + ctx.requiredScope()
            );
        }

        if (ctx.principalType() == PrincipalType.AI_AGENT) {
            if (ctx.sensitiveResource()) {
                return new PolicyEvaluationResult(
                        PolicyDecision.DENY,
                        normalizedRisk,
                        "AI_AGENT principals are restricted from autonomous access to sensitive resources"
                );
            }
            if (normalizedRisk >= aiAgentRiskThreshold) {
                return new PolicyEvaluationResult(
                        PolicyDecision.DENY,
                        normalizedRisk,
                        "AI_AGENT risk score (" + normalizedRisk + ") exceeds threshold (" + aiAgentRiskThreshold + ")"
                );
            }
        } else {
            if (normalizedRisk >= humanRiskThreshold) {
                return new PolicyEvaluationResult(
                        PolicyDecision.DENY,
                        normalizedRisk,
                        "Request risk score (" + normalizedRisk + ") exceeds human threshold (" + humanRiskThreshold + ")"
                );
            }
        }

        return new PolicyEvaluationResult(
                PolicyDecision.ALLOW,
                normalizedRisk,
                "Policy checks passed under least-privilege and risk rules"
        );
    }
}
