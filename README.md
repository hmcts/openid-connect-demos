## IDAM OpenID Connect Demos

This project aims to provide some basic examples of OpenID
Connect implementations for use with the IDAM system.

Demo 1
---

Demo 1 is the most basic version of the implementation that
supports authentication using `access_token` and `id_token`
as `Authentication: Bearer` tokens.

This is for a Backend Api that wants to make use of RBAC and
not just simple oauth2 authentication.

#### Getting Started
To run the demo project you will need to update some values
in `application.yaml`

```yaml
  security:
    oauth2:
      client:
        provider:
          oidc:
            # Set this to based on env so for aat:
            issuer-uri: https://idam-web-public.aat.platform.hmcts.net/o
        registration:
          oidc:
            # your client_id
            client-id: internal
            # your client_secret
            client-secret: internal

oidc:
  # Set this to your approved audiences
  audience-list: ccd-admin
  # This should be ...compute-idam-<env>.internal so for aat:
  issuer: https://forgerock-am.service.core-compute-idam-aat.internal:8443/openam/oauth2/hmcts
```

Access swagger on http://localhost:5080/swagger-ui.html

The two endpoints `/oidc-principal` and 
`/oidc-principal-if-has-authority` show the token validation
at work. `/oidc-principal` just works with the token and
`/oidc-principal-if-has-authority` will check for the passed 
in authority on the authentication. You will want to get
this value from a list somewhere or hardcode it.

The Authorisation header must be passed in as a bearer token
`Bearer eyJ0eXAiOiJK..`

#### Validation
To validate the tokens we are using the NimbusJwtDecoder.

This decoder comes with a signature validator baked in which
will automatically fetch the Jwk KeySet from the issuer.

We add some extra validators for the bits we care about:
 * Audience Validator for a strict audience list that we have
  pre-approved. This audience list is comprised of the names 
  of the client_ids that will be calling your service. So for
  example if client_id `ccd-admin` consumes the REST Api of
  client_id `ccd` then the approved audience list of `ccd` 
  should contain `ccd-admin`.
 * Timestamp Validator to check for expired tokens.
 * Issuer Validator to confirm issuer is IDAM, and at the time
 of writing the issuer is reporting as ForgerockAM instead of 
 hmcts-access so you will need to override this value until
 that has been fixed.
   
See `#SecurityConfiguration.jwtDecoder()`
```java
    NimbusJwtDecoder jwtDecoder = (NimbusJwtDecoder)
            JwtDecoders.fromOidcIssuerLocation(issuerUri);
    new AudienceValidator(Arrays.asList(allowedAudiences));
    new JwtTimestampValidator();
    new JwtIssuerValidator(issuerOverride);
```

#### Authorities Extractor

Once the Jwt has been validated we move onto extracting the
authorities (aka. the Spring Authorisation Roles).

If our token is the `access_token` we call `/userinfo` endpoint
to get the roles. This part can be cached on token to reduce calls 
to IDAM. The Jwt Validators run before this step so its safe to 
cache the return from `getUserInfo()` as only valid tokens will reach
this point.

See `#JwtAuthorityExtractor.extractAuthorities(Jwt jwt)`

```java
    if (jwt.getClaim("tokenName").equals(ACCESS_TOKEN)) {
        authorities = extractAuthorityFromClaims(
                        getUserInfo(jwt.getTokenValue())
                      );
    } else if (jwt.getClaim("tokenName").equals(ID_TOKEN)) {
        authorities = extractAuthorityFromClaims(jwt.getClaims());
    }
```

#### SecurityUtils

This class just contains some utility methods for getting info
from the authentication once the authorisation token has been 
parsed successfully.

Demo 2
---

This is a more involved demo app with support for refreshing
tokens, Authorized Feign Client examples and more.

WIP
