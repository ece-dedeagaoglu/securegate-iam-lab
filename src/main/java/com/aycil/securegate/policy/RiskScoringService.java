package com.aycil.securegate.policy;

import com.aycil.securegate.model.PrincipalType;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RiskScoringService {

    private static final long WINDOW_SECONDS = 60;
    private static final int BURST_THRESHOLD = 8;

    private final Map<String, Deque<Instant>> requestHistory = new ConcurrentHashMap<>();

    public record RiskAssessment(int effectiveRiskScore, int recentRequestCount, String summary) {}

    public RiskAssessment assess(String actorName, PrincipalType principalType, boolean sensitiveResource, int headerRiskScore) {
        int baseRisk = Math.max(0, Math.min(100, headerRiskScore));
        int delta = 0;

        String key = (actorName == null || actorName.isBlank() ? "anonymous" : actorName) + ":" + principalType;
        Instant now = Instant.now();
        Deque<Instant> timestamps = requestHistory.computeIfAbsent(key, k -> new ArrayDeque<>());

        int recentCount;
        synchronized (timestamps) {
            while (!timestamps.isEmpty() && now.getEpochSecond() - timestamps.peekFirst().getEpochSecond() > WINDOW_SECONDS) {
                timestamps.pollFirst();
            }
            timestamps.addLast(now);
            recentCount = timestamps.size();
        }

        if (recentCount > BURST_THRESHOLD) {
            delta += 15;
        }
        if (principalType == PrincipalType.AI_AGENT && sensitiveResource) {
            delta += 20;
        }

        int effective = Math.max(0, Math.min(100, baseRisk + delta));
        String summary = "base=" + baseRisk + ", delta=" + delta + ", recent60s=" + recentCount;
        return new RiskAssessment(effective, recentCount, summary);
    }
}
