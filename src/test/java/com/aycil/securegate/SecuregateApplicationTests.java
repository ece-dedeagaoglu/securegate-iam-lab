package com.aycil.securegate;

import com.aycil.securegate.repository.AuditLogRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class SecuregateApplicationTests {

    @Autowired
    private MockMvc mockMvc;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    private AuditLogRepository auditLogRepository;

    @BeforeEach
    void cleanAuditLogs() {
        auditLogRepository.deleteAll();
    }

    private String loginAndGetToken(String username, String password) throws Exception {
        String body = "{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}";
        MvcResult res = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode json = objectMapper.readTree(res.getResponse().getContentAsString());
        return json.get("accessToken").asText();
    }

    @Test
    void aiAgentCanReadTelemetryWhenRiskIsLow() throws Exception {
        String agentToken = loginAndGetToken("triage-ai-agent", "AgentSecret#2026");

        mockMvc.perform(get("/api/resources/telemetry")
                        .header("Authorization", "Bearer " + agentToken)
                        .header("X-Risk-Score", "20"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("ALLOW"));

        assertThat(auditLogRepository.count()).isEqualTo(2);
    }

    @Test
    void aiAgentIsBlockedFromSensitiveDbEvenWithLowRisk() throws Exception {
        String agentToken = loginAndGetToken("triage-ai-agent", "AgentSecret#2026");

        mockMvc.perform(get("/api/resources/sensitive-db")
                        .header("Authorization", "Bearer " + agentToken)
                        .header("X-Risk-Score", "10"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.decision").value("DENY"));
    }

    @Test
    void aiAgentIsBlockedWhenEffectiveRiskExceedsThreshold() throws Exception {
        String agentToken = loginAndGetToken("triage-ai-agent", "AgentSecret#2026");

        mockMvc.perform(get("/api/resources/telemetry")
                        .header("Authorization", "Bearer " + agentToken)
                        .header("X-Risk-Score", "65"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.decision").value("DENY"));
    }

    @Test
    void secAdminCanAccessSensitiveDbWithinThreshold() throws Exception {
        String adminToken = loginAndGetToken("sec-admin", "AdminPass#2026");

        mockMvc.perform(get("/api/resources/sensitive-db")
                        .header("Authorization", "Bearer " + adminToken)
                        .header("X-Risk-Score", "25"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("ALLOW"));
    }

    @Test
    void analystWithoutSensitiveScopeIsDenied() throws Exception {
        String analystToken = loginAndGetToken("analyst-alice", "AnalystPass#2026");

        mockMvc.perform(get("/api/resources/sensitive-db")
                        .header("Authorization", "Bearer " + analystToken)
                        .header("X-Risk-Score", "20"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.decision").value("DENY"));
    }
}
