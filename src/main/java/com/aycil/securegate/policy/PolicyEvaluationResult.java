package com.aycil.securegate.policy;

import com.aycil.securegate.model.PolicyDecision;

public record PolicyEvaluationResult(
        PolicyDecision decision,
        int riskScore,
        String reason
) {
    public boolean isAllowed() {
        return decision == PolicyDecision.ALLOW;
    }
}
