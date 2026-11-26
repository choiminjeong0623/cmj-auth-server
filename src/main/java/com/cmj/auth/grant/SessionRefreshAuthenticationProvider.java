package com.cmj.auth.grant;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Component;
import com.cmj.auth.client.SecurityServerClient;
import com.cmj.auth.token.RefreshTokenStore;
import com.cmj.auth.token.TokenUser;
import com.cmj.common.security.SessionData;
import com.cmj.common.security.SessionStore;

import java.util.Map;

/**
 * Access Token 재발급. 재발급 때 확인하는 것:
 *  - Refresh Token이 Redis에 있는가 (없으면 최대 수명 지남·이미 사용됨)
 *  - 사용자 세션(session:{userId})이 아직 있는가 → 없으면 미사용 자동 로그아웃된 것 (✅ Q16)
 *  - 세션의 sid가 같은가 → 다르면 다른 곳에서 새로 로그인한 것 (✅ Q5)
 *  - 그사이 퇴직·휴직·정직·잠금되지 않았는가 → 시큐리티 서버에 재확인
 * (요청마다 하는 확인은 업무 서비스의 SessionAuthFilter가 하고, 여기서는 재발급 시점에 한 번 더 막는다)
 */
@Component
public class SessionRefreshAuthenticationProvider implements AuthenticationProvider {

    private final RefreshTokenStore refreshTokens;
    private final SessionStore sessions;
    private final SecurityServerClient securityServer;
    private final OAuth2TokenGenerator<?> tokenGenerator;

    public SessionRefreshAuthenticationProvider(RefreshTokenStore refreshTokens, SessionStore sessions,
                                                SecurityServerClient securityServer,
                                                OAuth2TokenGenerator<?> tokenGenerator) {
        this.refreshTokens = refreshTokens;
        this.sessions = sessions;
        this.securityServer = securityServer;
        this.tokenGenerator = tokenGenerator;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        SessionRefreshAuthenticationToken grant = (SessionRefreshAuthenticationToken) authentication;
        OAuth2ClientAuthenticationToken clientPrincipal = GrantSupport.authenticatedClient(grant);
        RegisteredClient client = clientPrincipal.getRegisteredClient();

        RefreshTokenStore.Entry entry = refreshTokens.consume(grant.getRefreshToken())
            .orElseThrow(() -> invalidGrant("session_expired", "세션이 만료되었습니다. 다시 로그인하세요."));
        if (!entry.clientId().equals(client.getClientId())) {
            throw invalidGrant(OAuth2ErrorCodes.INVALID_GRANT, "다른 클라이언트의 토큰입니다.");
        }

        SessionData session = sessions.find(entry.userId())
            .orElseThrow(() -> invalidGrant("session_expired", "오랫동안 사용하지 않아 로그아웃되었습니다."));
        if (!session.sid().equals(entry.sid())) {
            throw invalidGrant("logged_in_elsewhere", "다른 곳에서 로그인되어 로그아웃되었습니다.");
        }
        SecurityServerClient.UserStatus status = securityServer.currentStatus(entry.userId()); // 막혔으면 여기서 예외

        TokenUser user = new TokenUser(status.userId(), status.userType());
        OAuth2AccessToken accessToken = LoginGrantAuthenticationProvider.buildAccessToken(
            tokenGenerator, client, grant, user, entry.sid());
        OAuth2RefreshToken refreshToken = refreshTokens.issue(
            new RefreshTokenStore.Entry(entry.userId(), entry.sid(), client.getClientId()));

        return new OAuth2AccessTokenAuthenticationToken(client, clientPrincipal, accessToken, refreshToken, Map.of());
    }

    private static OAuth2AuthenticationException invalidGrant(String code, String message) {
        return new OAuth2AuthenticationException(new OAuth2Error(code, message, null));
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return SessionRefreshAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
