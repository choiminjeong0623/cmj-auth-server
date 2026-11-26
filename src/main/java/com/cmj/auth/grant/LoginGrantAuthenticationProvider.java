package com.cmj.auth.grant;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import com.cmj.auth.client.SecurityServerClient;
import com.cmj.auth.token.RefreshTokenStore;
import com.cmj.auth.token.TokenUser;

import java.util.List;
import java.util.Map;

/**
 * 로그인 흐름: gateway → (여기) OAuth 서버 → 시큐리티 서버(로그인 규칙 + 세션 생성) → 토큰 발급
 * ✅ OAuth 서버는 "토큰을 만드는 일", 로그인 규칙(실패 횟수·AD·인사 상태·MFA)은 시큐리티 서버
 *
 * v1과 다른 점: 세션(Redis)은 시큐리티 서버가 로그인 성공 시 만들고 sid를 돌려준다.
 *              여기서는 그 sid를 JWT에 넣기만 한다.
 */
@Component
public class LoginGrantAuthenticationProvider implements AuthenticationProvider {

    private final SecurityServerClient securityServer;
    private final OAuth2TokenGenerator<?> tokenGenerator;
    private final RefreshTokenStore refreshTokenStore;

    public LoginGrantAuthenticationProvider(SecurityServerClient securityServer,
                                            OAuth2TokenGenerator<?> tokenGenerator,
                                            RefreshTokenStore refreshTokenStore) {
        this.securityServer = securityServer;
        this.tokenGenerator = tokenGenerator;
        this.refreshTokenStore = refreshTokenStore;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        LoginGrantAuthenticationToken grant = (LoginGrantAuthenticationToken) authentication;
        OAuth2ClientAuthenticationToken clientPrincipal = GrantSupport.authenticatedClient(grant);
        RegisteredClient client = clientPrincipal.getRegisteredClient();
        if (!client.getAuthorizationGrantTypes().contains(CmjGrantTypes.LOGIN)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        // 1) 로그인 규칙 검사 + 세션 생성은 시큐리티 서버(Feign 호출). 실패하면 LoginFailureException → 401 + 실패 이유
        SecurityServerClient.LoginResult result = securityServer.verify(new SecurityServerClient.VerifyRequest(
            grant.getUsername(), grant.getPassword(), grant.getLoginType(), grant.getMfaCode(), clientIp()));

        // 2) Access Token(JWT): sub·user_type·sid
        TokenUser user = new TokenUser(result.userId(), result.userType());
        OAuth2AccessToken accessToken = buildAccessToken(tokenGenerator, client, grant, user, result.sid());

        // 3) Refresh Token (Redis 저장 — RefreshTokenStore.issue 안의 opsForValue().set)
        OAuth2RefreshToken refreshToken = refreshTokenStore.issue(
            new RefreshTokenStore.Entry(result.userId(), result.sid(), client.getClientId()));

        return new OAuth2AccessTokenAuthenticationToken(client, clientPrincipal, accessToken, refreshToken,
            Map.of("user_type", result.userType()));
    }

    /** 두 grant(로그인·재발급)가 같이 쓰는 Access Token 생성 */
    static OAuth2AccessToken buildAccessToken(OAuth2TokenGenerator<?> generator, RegisteredClient client,
                                              Authentication grant, TokenUser user, String sid) {
        UsernamePasswordAuthenticationToken userPrincipal =
            UsernamePasswordAuthenticationToken.authenticated(user, null, List.of());
        userPrincipal.setDetails(sid); // JwtClaimsCustomizer가 sid 클레임으로 넣음

        DefaultOAuth2TokenContext context = DefaultOAuth2TokenContext.builder()
            .registeredClient(client)
            .principal(userPrincipal)
            .authorizationServerContext(AuthorizationServerContextHolder.getContext())
            .authorizedScopes(client.getScopes())
            .tokenType(OAuth2TokenType.ACCESS_TOKEN)
            .authorizationGrantType(((OAuth2AuthorizationGrantAuthenticationToken) grant).getGrantType())
            .authorizationGrant(grant)
            .build();

        OAuth2Token generated = generator.generate(context);
        if (generated == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                "Access Token 생성 실패", null));
        }
        return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, generated.getTokenValue(),
            generated.getIssuedAt(), generated.getExpiresAt(), context.getAuthorizedScopes());
    }

    /** 로그인 이력에 남길 사용자 IP (gateway가 붙인 X-Forwarded-For) */
    private static String clientIp() {
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attrs) {
            String xff = attrs.getRequest().getHeader("X-Forwarded-For");
            return xff != null ? xff.split(",")[0].trim() : attrs.getRequest().getRemoteAddr();
        }
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return LoginGrantAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
