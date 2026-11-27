package com.aycil.securegate.controller;

import java.time.Instant;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/public")
public class StatusController {

    @GetMapping("/status")
    public Map<String, String> getStatus() {
        return Map.of(
                "application", "SecureGate IAM Lab",
                "status", "UP",
                "timestamp", Instant.now().toString()
        );
    }
}
