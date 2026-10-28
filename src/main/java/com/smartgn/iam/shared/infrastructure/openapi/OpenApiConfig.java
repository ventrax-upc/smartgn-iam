package com.smartgn.iam.shared.infrastructure.openapi;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    private static final String BEARER = "bearerAuth";

    @Bean
    OpenAPI iamOpenAPI() {
        return new OpenAPI()
                .info(
                        new Info()
                                .title("SmartGN - IAM Service")
                                .description(
                                        "Verified-purchase account provisioning, password"
                                                + " activation and recovery, current JWT sessions,"
                                                + " profiles and meter-specific delegations. Global"
                                                + " roles: USER and SUPERADMIN. Billing owns"
                                                + " subscriptions.")
                                .version("v1"))
                .addSecurityItem(new SecurityRequirement().addList(BEARER))
                .components(
                        new Components()
                                .addSecuritySchemes(
                                        "serviceAuth",
                                        new SecurityScheme()
                                                .type(SecurityScheme.Type.HTTP)
                                                .scheme("bearer")
                                                .description(
                                                        "Private service credential, independent of"
                                                            + " user JWTs. Never expose internal"
                                                            + " paths through a public gateway."))
                                .addSecuritySchemes(
                                        BEARER,
                                        new SecurityScheme()
                                                .type(SecurityScheme.Type.HTTP)
                                                .scheme("bearer")
                                                .bearerFormat("JWT")));
    }
}
