package com.cmj.auth;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.cmj.common.security.SessionStore;

/**
 * 로그아웃: Redis 세션을 지운다.
 * 업무 서비스는 요청마다 세션을 확인하므로(SessionAuthFilter), 세션을 지우는 순간
 * 아직 만료되지 않은 Access Token(JWT)이 있어도 다음 요청부터 401이 된다.
 * → "JWT는 만료 전에 끊을 수 없다"는 문제를 Redis 세션으로 푼 구조 (Q3)
 */
@RestController
@RequestMapping("/api/auth")
public class LogoutController {

    private final SessionStore sessions;

    public LogoutController(SessionStore sessions) {
        this.sessions = sessions;
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@AuthenticationPrincipal Jwt jwt) {
        sessions.deleteIfCurrent(jwt.getSubject(), jwt.getClaimAsString("sid"));
        return ResponseEntity.noContent().build();
    }
}
