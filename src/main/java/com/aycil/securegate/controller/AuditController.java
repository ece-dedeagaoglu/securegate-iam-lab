package com.aycil.securegate.controller;

import com.aycil.securegate.model.AuditLog;
import com.aycil.securegate.service.AuditService;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/audit")
public class AuditController {

    private final AuditService auditService;

    public AuditController(AuditService auditService) {
        this.auditService = auditService;
    }

    @GetMapping("/logs")
    public List<AuditLog> getLogs(@RequestParam(required = false) String decision) {
        return auditService.recentLogs(decision);
    }
}
