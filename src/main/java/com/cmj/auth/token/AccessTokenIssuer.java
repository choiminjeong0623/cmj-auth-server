package com.cmj.auth.token;

import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.stereotype.Component;
import com.cmj.auth.config.AuthProperties;

import java.time.Duration;
import java.time.Instant;

/**
 * Access Token(JWT) 만들기.
 * 서명은 Spring Authorization Server와 같은 키(JWKSource)를 쓰는 NimbusJwtEncoder가 한다
 * → gateway는 /oauth2/jwks 의 공개키로 검증 (✅ gateway는 서명·만료만 확인)
 *
 *   sub       : 사용자 ID          → 업무 서비스가 Redis에서 session:{sub} 를 찾는 열쇠
 *   sid       : 이번 로그인 세션 ID → Redis 세션의 sid와 다르면 중복 로그인 (✅ Q5)
 *   user_type : 사용자 유형
 * roles는 넣지 않는다. 권한은 Redis 세션의 화면 목록으로 판단 (✅ Q1·Q7)
 * ⚠️ 클레임 이름은 예시 — 면접에서 단정하지 말 것
 */
@Component
public class AccessTokenIssuer {

    private final JwtEncoder encoder;
    private final AuthProperties props;

    public AccessTokenIssuer(JwtEncoder encoder, AuthProperties props) {
        this.encoder = encoder;
        this.props = props;
    }

    public record Issued(String token, long expiresInSeconds) {}

    public Issued issue(String userId, String userType, String sid) {
        Instant now = Instant.now();
        Duration ttl = props.accessTokenTtl();
        JwtClaimsSet claims = JwtClaimsSet.builder()
            .issuer(props.issuer())
            .subject(userId)
            .issuedAt(now)
            .expiresAt(now.plus(ttl))          // gateway·업무 서비스가 exp로 만료 확인 (📘 Q14)
            .claim("user_type", userType)
            .claim("sid", sid)
            .claim("scope", "portal")
            .build();
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).build();
        String token = encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
        return new Issued(token, ttl.toSeconds());
    }
}
