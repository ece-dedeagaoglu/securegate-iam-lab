package com.aycil.securegate.policy;

import com.aycil.securegate.model.PrincipalType;

import java.util.Set;

public record AccessRequestContext(
        String actor,
        PrincipalType principalType,
        Set<String> scopes,
        String requiredScope,
        String resource,
        boolean sensitiveResource,
        int riskScore
) {}
