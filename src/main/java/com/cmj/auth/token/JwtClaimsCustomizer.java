package com.cmj.auth.token;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

/**
 * Access Token(JWT)에 들어갈 우리만의 클레임.
 *
 *   sub       : 사용자 ID          → 업무 서비스가 Redis에서 session:{sub} 를 찾는 열쇠
 *   sid       : 이번 로그인 세션 ID → Redis 세션의 sid와 다르면 중복 로그인 (✅ Q5)
 *   user_type : 사용자 유형
 *
 * v1과 다른 점: roles를 넣지 않는다. 권한은 Redis 세션의 화면 목록으로 판단하기 때문 (✅ Q1·Q7).
 * ⚠️ 세션 ID가 실제로 토큰의 어느 값에 들어 있었는지는 미확인 — 면접에서 클레임 이름을 단정하지 말 것.
 */
@Component
public class JwtClaimsCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    @Override
    public void customize(JwtEncodingContext context) {
        if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            return;
        }
        Authentication principal = context.getPrincipal();
        if (principal.getPrincipal() instanceof TokenUser user) {
            context.getClaims()
                .subject(user.userId())
                .claim("user_type", user.userType());
        }
        if (principal.getDetails() instanceof String sid) {
            context.getClaims().claim("sid", sid);
        }
    }
}
