package uk.gov.hmcts.reform.idam.oidc.demo1.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.AuthorizationCodeGrantBuilder;
import springfox.documentation.builders.OAuthBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.AuthorizationScope;
import springfox.documentation.service.GrantType;
import springfox.documentation.service.SecurityReference;
import springfox.documentation.service.SecurityScheme;
import springfox.documentation.service.Tag;
import springfox.documentation.service.TokenEndpoint;
import springfox.documentation.service.TokenRequestEndpoint;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spi.service.contexts.SecurityContext;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger.web.SecurityConfiguration;
import springfox.documentation.swagger.web.SecurityConfigurationBuilder;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.util.Arrays;

import static java.util.Collections.singletonList;

@Configuration
@EnableSwagger2
public class SwaggerConfig {

    private static final String description =
            "A Demo backend using OIDC RBAC Access";

    /** The tags used for categorizing rest calls on the Swagger site. */
    public static final String EXAMPLE_ENDPOINTS = "Example Endpoints";

    @Value("${spring.security.oauth2.client.provider.oidc.issuer-uri}")
    public String oidc_issuer_uri;

    @Value("${spring.security.oauth2.client.registration.oidc.client-id}")
    public String client_id;

    @Value("${spring.security.oauth2.client.registration.oidc.client-secret}")
    public String client_secret;

    public SwaggerConfig() { }

    @Bean
    public Docket api() {
        return new Docket(DocumentationType.SWAGGER_2)
                .groupName("Reform IdAM API Service")
                .ignoredParameterTypes(OidcUser.class)
                .apiInfo(apiInfo())
                .tags(new Tag(EXAMPLE_ENDPOINTS, ""))
                .select()
                .apis(RequestHandlerSelectors.basePackage("uk.gov.hmcts.reform.idam.oidc.demo1.web"))
                .paths(PathSelectors.ant("/**"))
                .build()
                .securitySchemes(singletonList(securityScheme()))
                .securityContexts(singletonList(securityContext()));
    }

    @Bean
    public SecurityConfiguration security() {
        return SecurityConfigurationBuilder.builder()
                .clientId(client_id)
                .clientSecret(client_secret)
                .scopeSeparator(" ")
                .useBasicAuthenticationWithAccessCodeGrant(true)
                .build();
    }

    private SecurityScheme securityScheme() {
        GrantType grantType = new AuthorizationCodeGrantBuilder()
                .tokenEndpoint(new TokenEndpoint(oidc_issuer_uri + "/token", "Bearer"))
                .tokenRequestEndpoint(new TokenRequestEndpoint(oidc_issuer_uri + "/authorize",
                                                               client_id,
                                                               client_secret))
                .build();

        return new OAuthBuilder().name("spring_oauth")
                .grantTypes(singletonList(grantType))
                .scopes(Arrays.asList(scopes()))
                .build();
    }

    private AuthorizationScope[] scopes() {
        return new AuthorizationScope[]{
                new AuthorizationScope("create-user", "User create operations"),
                new AuthorizationScope("manage-user", "Edit and delete user operations"),
                new AuthorizationScope("search-user", "Search user operations") };
    }

    private SecurityContext securityContext() {
        return SecurityContext.builder()
                .securityReferences(singletonList(new SecurityReference("spring_oauth", scopes())))
                .forPaths(PathSelectors.regex("/api/v1.*"))
                .build();
    }

    private ApiInfo apiInfo() {
        return new ApiInfoBuilder()
                .title("Overview")
                .description(description)
                .license("MIT License")
                .version("1.0")
                .build();
    }

}