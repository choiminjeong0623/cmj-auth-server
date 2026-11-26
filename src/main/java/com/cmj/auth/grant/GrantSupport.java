package com.cmj.auth.grant;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;

final class GrantSupport {
    private GrantSupport() {}

    /** /oauth2/token 앞단에서 클라이언트 인증(Basic)이 끝났는지 확인 */
    static OAuth2ClientAuthenticationToken authenticatedClient(Authentication grant) {
        Object principal = grant.getPrincipal();
        if (principal instanceof OAuth2ClientAuthenticationToken client && client.isAuthenticated()) {
            return client;
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }
}
