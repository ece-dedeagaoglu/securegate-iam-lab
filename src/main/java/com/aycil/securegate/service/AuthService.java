package com.aycil.securegate.service;

import com.aycil.securegate.model.PolicyDecision;
import com.aycil.securegate.model.PrincipalType;
import com.aycil.securegate.model.Role;
import com.aycil.securegate.model.UserAccount;
import com.aycil.securegate.repository.UserAccountRepository;
import com.aycil.securegate.security.JwtService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class AuthService {

    private final UserAccountRepository userAccountRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuditService auditService;
    private final int maxFailedAttempts;

    public AuthService(
            UserAccountRepository userAccountRepository,
            PasswordEncoder passwordEncoder,
            JwtService jwtService,
            AuditService auditService,
            @Value("${security.policy.max-failed-attempts:3}") int maxFailedAttempts
    ) {
        this.userAccountRepository = userAccountRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.auditService = auditService;
        this.maxFailedAttempts = maxFailedAttempts;
    }

    public UserAccount register(
            String username,
            String rawPassword,
            PrincipalType principalType,
            Set<Role> roles,
            Set<String> scopes
    ) {
        if (userAccountRepository.existsByUsername(username)) {
            throw new IllegalArgumentException("Username already exists: " + username);
        }

        UserAccount account = new UserAccount();
        account.setUsername(username);
        account.setPasswordHash(passwordEncoder.encode(rawPassword));
        account.setPrincipalType(principalType != null ? principalType : PrincipalType.HUMAN);

        Set<Role> assignedRoles = (roles == null || roles.isEmpty())
                ? new HashSet<>(Set.of(Role.USER))
                : new HashSet<>(roles);
        account.setRoles(assignedRoles);

        Set<String> assignedScopes = (scopes == null || scopes.isEmpty())
                ? new HashSet<>(Set.of("read:telemetry"))
                : new HashSet<>(scopes);
        account.setScopes(assignedScopes);

        UserAccount saved = userAccountRepository.save(account);
        auditService.record(
                saved.getUsername(),
                saved.getPrincipalType(),
                "REGISTER",
                "/api/auth/register",
                10,
                PolicyDecision.ALLOW,
                "Account provisioned with roles=" + saved.getRoles() + " and scopes=" + saved.getScopes()
        );
        return saved;
    }

    public String login(String username, String rawPassword) {
        UserAccount user = userAccountRepository.findByUsername(username)
                .orElseThrow(() -> {
                    auditService.record(
                            username,
                            PrincipalType.HUMAN,
                            "LOGIN",
                            "/api/auth/login",
                            60,
                            PolicyDecision.DENY,
                            "Unknown principal attempted login"
                    );
                    return new SecurityException("Invalid credentials");
                });

        if (user.isAccountLocked()) {
            auditService.record(
                    user.getUsername(),
                    user.getPrincipalType(),
                    "LOGIN",
                    "/api/auth/login",
                    85,
                    PolicyDecision.DENY,
                    "Account is locked due to repeated failed authentication attempts"
            );
            throw new IllegalStateException("Account is locked");
        }

        if (!passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
            int nextAttempts = user.getFailedAttempts() + 1;
            user.setFailedAttempts(nextAttempts);
            boolean lockedNow = nextAttempts >= maxFailedAttempts;
            if (lockedNow) {
                user.setAccountLocked(true);
            }
            userAccountRepository.save(user);

            auditService.record(
                    user.getUsername(),
                    user.getPrincipalType(),
                    "LOGIN",
                    "/api/auth/login",
                    lockedNow ? 90 : 55,
                    PolicyDecision.DENY,
                    lockedNow
                            ? "Invalid password; account locked after " + nextAttempts + " failed attempts"
                            : "Invalid password; failed attempt " + nextAttempts + "/" + maxFailedAttempts
            );
            throw new SecurityException("Invalid credentials");
        }

        user.setFailedAttempts(0);
        userAccountRepository.save(user);

        String token = jwtService.generateToken(user);
        auditService.record(
                user.getUsername(),
                user.getPrincipalType(),
                "LOGIN",
                "/api/auth/login",
                10,
                PolicyDecision.ALLOW,
                "Authenticated and issued scoped JWT"
        );
        return token;
    }
}
