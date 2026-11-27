package com.aycil.securegate.controller;

import java.security.Principal;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class AccessDemoController {

    @GetMapping("/customer/profile")
    public Map<String, String> customerProfile(Principal principal) {
        return response(principal, "CUSTOMER_RESOURCE");
    }

    @GetMapping("/analyst/events")
    public Map<String, String> analystEvents(Principal principal) {
        return response(principal, "ANALYST_RESOURCE");
    }

    @GetMapping("/admin/users")
    public Map<String, String> adminUsers(Principal principal) {
        return response(principal, "ADMIN_RESOURCE");
    }

    private Map<String, String> response(Principal principal, String resource) {
        return Map.of(
                "authenticatedUser", principal.getName(),
                "resource", resource,
                "decision", "ALLOW"
        );
    }
}
