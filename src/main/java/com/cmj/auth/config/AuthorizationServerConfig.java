package com.cmj.auth.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import com.cmj.auth.grant.LoginGrantAuthenticationConverter;
import com.cmj.auth.grant.LoginGrantAuthenticationProvider;
import com.cmj.auth.grant.CmjGrantTypes;
import com.cmj.auth.grant.SessionRefreshAuthenticationConverter;
import com.cmj.auth.grant.SessionRefreshAuthenticationProvider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
 * Spring Authorization Server 설정.
 *
 * 왜 커스텀 grant인가: Spring Authorization Server는 OAuth 2.1 방향에 맞춰
 * 아이디·비밀번호를 바로 토큰으로 바꾸는 password grant를 지원하지 않는다.
 * 그래서 "아이디·비밀번호 → 시큐리티 서버 검증 → 토큰" 흐름을 커스텀 grant type으로 만든다.
 * (실제 프로젝트가 이 방식이었는지는 미확인 — README 참고)
 *
 * v2: Access Token에는 sub·user_type·sid만 넣는다. 권한(화면 목록)은 JWT가 아니라 Redis 세션에 있다
 *     (✅ 권한 검사는 업무 서비스의 common.security가 세션 목록과 비교).
 */
@Configuration
public class AuthorizationServerConfig {

    /** /oauth2/token, /oauth2/jwks 등 인가 서버 엔드포인트 전용 필터 체인 */
    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerChain(HttpSecurity http,
                                                 LoginGrantAuthenticationProvider loginProvider,
                                                 SessionRefreshAuthenticationProvider refreshProvider) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .tokenEndpoint(token -> token
                .accessTokenRequestConverter(new LoginGrantAuthenticationConverter())
                .accessTokenRequestConverter(new SessionRefreshAuthenticationConverter())
                .authenticationProvider(loginProvider)
                .authenticationProvider(refreshProvider)
                .errorResponseHandler(new LoginErrorResponseHandler())); // 실패 이유 코드 + 남은 횟수 등을 화면까지
        http.exceptionHandling(e -> e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)));
        return http.build();
    }

    /** /api/auth/** (로그아웃 등): 우리 JWT를 가진 사용자만 */
    @Bean
    @Order(2)
    SecurityFilterChain authApiChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/api/auth/**")
            .csrf(c -> c.disable())
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(a -> a.anyRequest().authenticated())
            .oauth2ResourceServer(rs -> rs.jwt(jwt -> {}));
        return http.build();
    }

    /** 토큰을 받을 수 있는 클라이언트. 포털 웹 하나 (gateway가 대신 클라이언트 인증) */
    @Bean
    RegisteredClientRepository registeredClientRepository(AuthProperties props) {
        RegisteredClient portal = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(props.portalClientId())
            .clientSecret(props.portalClientSecret())   // 예: {bcrypt}... (운영은 해시값)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(CmjGrantTypes.LOGIN)
            .authorizationGrantType(CmjGrantTypes.SESSION_REFRESH)
            .scope("portal")
            .tokenSettings(TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)   // JWT
                .accessTokenTimeToLive(props.accessTokenTtl())
                .build())
            .build();
        return new InMemoryRegisteredClientRepository(portal);
    }

    /**
     * 서명 키. 예시에서는 기동할 때 만든다.
     * 운영에서는 키스토어·비밀 저장소에서 읽어야 인증 서버가 여러 대여도 같은 키로 서명하고,
     * 재기동해도 이미 발급된 토큰이 깨지지 않는다.
     */
    @Bean
    JWKSource<SecurityContext> jwkSource() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
            .privateKey((RSAPrivateKey) keyPair.getPrivate())
            .keyID(UUID.randomUUID().toString())
            .build();
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    /** 로그아웃 API에서 토큰을 확인할 때 쓰는 디코더 (같은 키) */
    @Bean
    JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /** Access Token(JWT) 생성기. Nimbus JOSE+JWT로 서명하고, 커스터마이저로 클레임을 더한다 */
    @Bean
    OAuth2TokenGenerator<?> tokenGenerator(JWKSource<SecurityContext> jwkSource,
                                           OAuth2TokenCustomizer<JwtEncodingContext> customizer) {
        JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
        jwtGenerator.setJwtCustomizer(customizer);
        return new DelegatingOAuth2TokenGenerator(jwtGenerator);
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings(AuthProperties props) {
        return AuthorizationServerSettings.builder().issuer(props.issuer()).build();
    }
}
