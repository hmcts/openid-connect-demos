package uk.gov.hmcts.reform.idam.oidc.demo1.web;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
@RequestMapping("/api/v1")
public class ExampleController {

    public ExampleController() { }

    @GetMapping("/oidc-principal")
    public Authentication getOidcUserPrincipal(
            @RequestHeader(value = "authorization") String authorization,
            @AuthenticationPrincipal Authentication principal) {
        return principal;
    }

    @GetMapping("/oidc-principal-if-has-authority")
    @PreAuthorize("hasAnyAuthority(#authority)")
    public Authentication getOidcUserPrincipalIfHaveAuthority(
            @RequestHeader(value = "authorization") String authorization,
            @RequestParam String authority,
            @AuthenticationPrincipal Authentication principal) {
        return principal;
    }
}
