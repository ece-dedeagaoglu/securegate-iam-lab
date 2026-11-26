package com.aycil.securegate.model;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "audit_logs")
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String actor;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private PrincipalType principalType;

    @Column(nullable = false)
    private String action;

    @Column(nullable = false)
    private String resource;

    @Column(nullable = false)
    private int riskScore;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private PolicyDecision decision;

    @Column(nullable = false, length = 512)
    private String reason;

    @Column(nullable = false)
    private Instant timestamp = Instant.now();

    public Long getId() { return id; }
    public String getActor() { return actor; }
    public void setActor(String actor) { this.actor = actor; }
    public PrincipalType getPrincipalType() { return principalType; }
    public void setPrincipalType(PrincipalType principalType) { this.principalType = principalType; }
    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }
    public String getResource() { return resource; }
    public void setResource(String resource) { this.resource = resource; }
    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }
    public PolicyDecision getDecision() { return decision; }
    public void setDecision(PolicyDecision decision) { this.decision = decision; }
    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }
    public Instant getTimestamp() { return timestamp; }
}
