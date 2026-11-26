package com.cmj.auth.login;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 로그인 입구.
 * 🟩 화면의 로그인 요청은 /oauth2/token 이 아니라 우리가 만든 로그인 API로 갔음 (2026-11-26, "보였던 것 같다")
 * ⚠️ 실제 주소(/api/auth/login)·요청 모양은 예시
 *
 * 흐름: 화면 → gateway → (여기) 인증 서버 → FeignClient → 시큐리티 서버(로그인 규칙 + 세션 생성) → JWT 발급
 * 서명 키 관리와 공개키 제공(/oauth2/jwks)은 Spring Authorization Server가 맡는다 (AuthorizationServerConfig)
 */
@RestController
@RequestMapping("/api/auth")
public class LoginController {

    private final LoginService loginService;

    public LoginController(LoginService loginService) {
        this.loginService = loginService;
    }

    @PostMapping("/login")
    public TokenResponse login(@Valid @RequestBody LoginRequest request, HttpServletRequest http) {
        return loginService.login(request, clientIp(http));
    }

    /** Access Token 재발급 (⚠️ 재발급도 같은 방식이었는지는 미확인) */
    @PostMapping("/refresh")
    public TokenResponse refresh(@RequestBody Map<String, String> body) {
        return loginService.refresh(body.get("refreshToken"));
    }

    /** 로그인 이력에 남길 사용자 IP (gateway가 붙인 X-Forwarded-For) */
    private static String clientIp(HttpServletRequest http) {
        String xff = http.getHeader("X-Forwarded-For");
        return xff != null ? xff.split(",")[0].trim() : http.getRemoteAddr();
    }
}
