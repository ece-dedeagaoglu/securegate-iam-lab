# SecureGate IAM Lab

Zero-Trust Identity and Access Management (IAM) and AI policy gate prototype built with Spring Boot.

## Architecture Overview

- **Identity & Token Layer (`AuthService`, `JwtService`, `JwtAuthenticationFilter`, `SecurityConfig`):** Separates `HUMAN` and `AI_AGENT` principals, enforces least-privilege scopes (`read:telemetry`, `query:knowledge_base`, `access:sensitive_db`, `audit:read`), and tracks failed login attempts.
- **Contextual Risk & Policy Engine (`RiskScoringService`, `ZeroTrustPolicyEngine`):** Combines request risk scores (`X-Risk-Score`), short-window request burst activity, and sensitive-resource / `AI_AGENT` context before making `ALLOW` or `DENY` decisions.
- **Audit Logging (`AuditService`, `AuditController`, `AuditLog`):** Records policy decisions, effective risk scores, and evaluation summaries for inspection.

## Running Tests

./mvnw test
