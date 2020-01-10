package uk.gov.hmcts.reform.idam.oidc.demo1.client;

import org.springframework.context.annotation.Bean;

import feign.RequestInterceptor;

import uk.gov.hmcts.reform.idam.oidc.demo1.security.oauth2.AuthorizationHeaderUtil;

public class OAuth2InterceptedFeignConfiguration {

    @Bean(name = "oauth2RequestInterceptor")
    public RequestInterceptor getOAuth2RequestInterceptor(AuthorizationHeaderUtil authorizationHeaderUtil) {
        return new TokenRelayRequestInterceptor(authorizationHeaderUtil);
    }
}
