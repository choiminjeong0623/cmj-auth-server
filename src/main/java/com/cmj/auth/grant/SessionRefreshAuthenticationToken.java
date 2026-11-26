package com.cmj.auth.grant;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.Map;

public class SessionRefreshAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    private final String refreshToken;

    public SessionRefreshAuthenticationToken(Authentication clientPrincipal, String refreshToken) {
        super(CmjGrantTypes.SESSION_REFRESH, clientPrincipal, Map.of());
        this.refreshToken = refreshToken;
    }

    public String getRefreshToken() { return refreshToken; }
}
