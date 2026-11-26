package com.aycil.securegate.config;

import com.aycil.securegate.model.PrincipalType;
import com.aycil.securegate.model.Role;
import com.aycil.securegate.repository.UserAccountRepository;
import com.aycil.securegate.service.AuthService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Set;

@Configuration
public class DataInitializer {

    @Bean
    CommandLineRunner seedIdentities(UserAccountRepository repo, AuthService authService) {
        return args -> {
            if (!repo.existsByUsername("sec-admin")) {
                authService.register(
                        "sec-admin",
                        "AdminPass#2026",
                        PrincipalType.HUMAN,
                        Set.of(Role.ADMIN, Role.SECURITY_ANALYST),
                        Set.of("read:telemetry", "query:knowledge_base", "access:sensitive_db", "audit:read")
                );
            }
            if (!repo.existsByUsername("triage-ai-agent")) {
                authService.register(
                        "triage-ai-agent",
                        "AgentSecret#2026",
                        PrincipalType.AI_AGENT,
                        Set.of(Role.AI_AGENT),
                        Set.of("read:telemetry", "query:knowledge_base")
                );
            }
            if (!repo.existsByUsername("analyst-alice")) {
                authService.register(
                        "analyst-alice",
                        "AnalystPass#2026",
                        PrincipalType.HUMAN,
                        Set.of(Role.SECURITY_ANALYST),
                        Set.of("read:telemetry", "query:knowledge_base", "audit:read")
                );
            }
        };
    }
}
