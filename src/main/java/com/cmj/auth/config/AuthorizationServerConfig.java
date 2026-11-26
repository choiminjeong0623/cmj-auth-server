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
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
 * Spring Authorization Server 설정.
 *
 * 🟩 로그인 요청은 /oauth2/token(커스텀 grant)이 아니라 우리가 만든 로그인 API(LoginController)로 받았음 (2026-11-26)
 *    → 이 서버에서 Spring Authorization Server가 맡는 일은 "서명 키 관리 + 공개키 제공(/oauth2/jwks)"
 *    → JWT 발급은 같은 키를 쓰는 JwtEncoder로 LoginService가 직접 한다 (AccessTokenIssuer)
 *
 * Access Token에는 sub·user_type·sid만 넣는다. 권한(화면 목록)은 JWT가 아니라 Redis 세션에 있다
 * (✅ 권한 검사는 업무 서비스의 common.security가 세션 목록과 비교).
 */
@Configuration
public class AuthorizationServerConfig {

    /** /oauth2/jwks 등 인가 서버 기본 엔드포인트 전용 필터 체인 (gateway가 여기서 공개키를 받아 JWT 서명을 검증) */
    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.exceptionHandling(e -> e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)));
        return http.build();
    }

    /** /api/auth/**: 로그인·재발급은 누구나(아직 토큰이 없음), 로그아웃은 우리 JWT를 가진 사용자만 */
    @Bean
    @Order(2)
    SecurityFilterChain authApiChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/api/auth/**")
            .csrf(c -> c.disable())
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(a -> a
                .requestMatchers("/api/auth/login", "/api/auth/refresh").permitAll()
                .anyRequest().authenticated())
            .oauth2ResourceServer(rs -> rs.jwt(jwt -> {}));
        return http.build();
    }

    /**
     * Spring Authorization Server는 등록된 클라이언트 저장소가 있어야 기동된다.
     * 이 클라이언트는 그 요구를 맞추려고만 둔 것이고, 실제 로그인은 LoginController(/api/auth/login)로 받는다.
     */
    @Bean
    RegisteredClientRepository registeredClientRepository(AuthProperties props) {
        RegisteredClient portal = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(props.portalClientId())
            .clientSecret(props.portalClientSecret())   // 예: {bcrypt}... (운영은 해시값)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .scope("portal")
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

    /** Access Token(JWT) 서명기. Nimbus JOSE+JWT로 jwks와 같은 키로 서명 → AccessTokenIssuer가 사용 */
    @Bean
    JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings(AuthProperties props) {
        return AuthorizationServerSettings.builder().issuer(props.issuer()).build();
    }
}
