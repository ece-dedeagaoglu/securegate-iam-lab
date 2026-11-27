package com.aycil.securegate;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class AuthorizationIntegrationTests {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void publicStatusIsAvailableWithoutAuthentication() throws Exception {
        mockMvc.perform(get("/api/public/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }

    @Test
    void protectedEndpointRejectsAnonymousUser() throws Exception {
        mockMvc.perform(get("/api/customer/profile"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void customerCanAccessCustomerResource() throws Exception {
        mockMvc.perform(get("/api/customer/profile")
                        .with(httpBasic("customer", "Customer!234")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authenticatedUser").value("customer"));
    }

    @Test
    void customerCannotAccessAnalystResource() throws Exception {
        mockMvc.perform(get("/api/analyst/events")
                        .with(httpBasic("customer", "Customer!234")))
                .andExpect(status().isForbidden());
    }

    @Test
    void analystCanAccessAnalystResource() throws Exception {
        mockMvc.perform(get("/api/analyst/events")
                        .with(httpBasic("analyst", "Analyst!234")))
                .andExpect(status().isOk());
    }

    @Test
    void analystCannotAccessAdminResource() throws Exception {
        mockMvc.perform(get("/api/admin/users")
                        .with(httpBasic("analyst", "Analyst!234")))
                .andExpect(status().isForbidden());
    }

    @Test
    void adminCanAccessAdminAndAnalystResources() throws Exception {
        mockMvc.perform(get("/api/admin/users")
                        .with(httpBasic("admin", "Admin!234")))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/analyst/events")
                        .with(httpBasic("admin", "Admin!234")))
                .andExpect(status().isOk());
    }
}
