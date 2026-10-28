package com.smartgn.iam.auth.infrastructure.security;

import static org.mockito.Mockito.mock;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup;

import com.smartgn.iam.auth.application.port.out.TokenProvider;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

@SpringJUnitConfig(SecurityCorsTest.TestConfiguration.class)
@WebAppConfiguration
@TestPropertySource(
        properties = {
            "smartgn.security.allowed-origins=https://frontend.example",
            "smartgn.internal.token=isolated-test-internal-service-token-123456"
        })
class SecurityCorsTest {
    @Autowired private WebApplicationContext context;
    private MockMvc mvc;

    @BeforeEach
    void setup() {
        mvc = webAppContextSetup(context).apply(springSecurity()).build();
    }

    @Test
    void permitsBearerPreflightFromTheConfiguredFrontend() throws Exception {
        mvc.perform(
                        options("/api/v1/profile")
                                .header("Origin", "https://frontend.example")
                                .header("Access-Control-Request-Method", "PUT")
                                .header(
                                        "Access-Control-Request-Headers",
                                        "authorization,content-type"))
                .andExpect(status().isOk())
                .andExpect(
                        header().string("Access-Control-Allow-Origin", "https://frontend.example"));
    }

    @Test
    void rejectsUntrustedFrontendOrigins() throws Exception {
        mvc.perform(
                        options("/api/v1/profile")
                                .header("Origin", "https://untrusted.example")
                                .header("Access-Control-Request-Method", "PUT"))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
    }

    @Test
    void corsDoesNotGrantUnauthenticatedAccessToPrivateEndpoints() throws Exception {
        mvc.perform(get("/api/v1/profile").header("Origin", "https://frontend.example"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void healthRemainsPublicForDocker() throws Exception {
        mvc.perform(get("/actuator/health")).andExpect(status().isOk());
    }

    @Configuration
    @EnableWebMvc
    @Import(SecurityConfig.class)
    static class TestConfiguration {
        @Bean
        TokenProvider tokenProvider() {
            return mock(TokenProvider.class);
        }

        @Bean
        ProbeController controller() {
            return new ProbeController();
        }
    }

    @RestController
    static class ProbeController {
        @GetMapping("/actuator/health")
        String health() {
            return "UP";
        }

        @GetMapping("/api/v1/profile")
        String profile() {
            return "private";
        }
    }
}
