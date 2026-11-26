package com.aycil.securegate.controller;

import com.aycil.securegate.model.PrincipalType;
import com.aycil.securegate.model.Role;
import com.aycil.securegate.model.UserAccount;
import com.aycil.securegate.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    public record RegisterRequest(
            String username,
            String password,
            PrincipalType principalType,
            Set<Role> roles,
            Set<String> scopes
    ) {}

    public record LoginRequest(String username, String password) {}

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@RequestBody RegisterRequest req) {
        UserAccount created = authService.register(
                req.username(),
                req.password(),
                req.principalType() != null ? req.principalType() : PrincipalType.HUMAN,
                req.roles(),
                req.scopes()
        );
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                "username", created.getUsername(),
                "principalType", created.getPrincipalType(),
                "roles", created.getRoles(),
                "scopes", created.getScopes()
        ));
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody LoginRequest req) {
        String token = authService.login(req.username(), req.password());
        return ResponseEntity.ok(Map.of(
                "accessToken", token,
                "tokenType", "Bearer",
                "username", req.username()
        ));
    }
}
