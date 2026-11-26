package com.cmj.auth.token;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.stereotype.Component;
import com.cmj.auth.config.AuthProperties;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

/**
 * Refresh Token을 Redis에 둔다. ✅ 실제 프로젝트도 Refresh Token은 Redis (직접 개발했는지는 미확인)
 *
 *   rt:{refreshToken} → {"userId","sid","clientId"}   TTL = 최대 수명
 *
 * v1과 다른 점: 중복 로그인·미사용 자동 로그아웃은 여기서 판단하지 않는다.
 *   → 사용자 세션(session:{userId}, common-security의 SessionStore)이 담당하고,
 *     업무 서비스가 "요청마다" 확인한다 (✅ Q5·Q16).
 */
@Component
public class RefreshTokenStore {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final StringRedisTemplate redis;
    private final Duration maxLifetime;

    public RefreshTokenStore(StringRedisTemplate redis, AuthProperties props) {
        this.redis = redis;
        this.maxLifetime = props.refreshMaxLifetime();
    }

    public record Entry(String userId, String sid, String clientId) {}

    public OAuth2RefreshToken issue(Entry entry) {
        String value = randomToken();
        Instant now = Instant.now();
        redis.opsForValue().set("rt:" + value, toJson(entry), maxLifetime);   // ← Redis 저장 (setSession과 같은 opsForValue().set)
        return new OAuth2RefreshToken(value, now, now.plus(maxLifetime));
    }

    /** 한 번 쓴 Refresh Token은 지운다 (rotation). 도난된 토큰의 재사용을 줄인다 */
    public Optional<Entry> consume(String refreshToken) {
        return Optional.ofNullable(redis.opsForValue().getAndDelete("rt:" + refreshToken)).map(this::fromJson);
    }

    private static String randomToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String toJson(Entry e) {
        try { return MAPPER.writeValueAsString(e); } catch (JsonProcessingException ex) { throw new IllegalStateException(ex); }
    }

    private Entry fromJson(String json) {
        try { return MAPPER.readValue(json, Entry.class); } catch (JsonProcessingException ex) { throw new IllegalStateException(ex); }
    }
}
