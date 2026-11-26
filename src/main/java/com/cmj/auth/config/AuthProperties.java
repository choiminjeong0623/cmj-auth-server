package com.cmj.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "cmj.auth")
public record AuthProperties(
    String issuer,
    String portalClientId,
    String portalClientSecret,
    Duration accessTokenTtl,       // Access Token(JWT) 수명
    Duration refreshMaxLifetime,   // Refresh Token 최대 수명 (미사용 자동 로그아웃은 Redis 세션 TTL이 담당)
    String securityServerUrl,
    String internalApiKey
) {}
