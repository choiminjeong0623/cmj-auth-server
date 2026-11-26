package com.cmj.auth.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * OAuth 서버 → 시큐리티 서버 내부 호출.
 * ✅ 실제 프로젝트는 이 호출에 @FeignClient(OpenFeign)를 사용 (2026-11-26 확인). 인터페이스 내용은 예시.
 *
 * 인터페이스만 적으면 Feign이 HTTP 호출 코드를 만들어 준다.
 * 내부 키 헤더와 실패 응답 변환은 SecurityServerFeignConfig에서 처리.
 */
@FeignClient(name = "security-server", url = "${cmj.auth.security-server-url}",
             configuration = SecurityServerFeignConfig.class)
public interface SecurityServerClient {

    record VerifyRequest(String loginId, String password, String loginType, String mfaCode, String clientIp) {}

    /** 로그인 규칙 검사 + 성공 시 Redis 세션 생성(setSession). 돌려받는 sid를 JWT에 넣는다 */
    record LoginResult(String userId, String userType, String sid) {}

    /** 토큰 재발급 때 "아직 로그인해도 되는 사람인가" 재확인 결과 */
    record UserStatus(String userId, String userType) {}

    @PostMapping("/internal/auth/verify")
    LoginResult verify(@RequestBody VerifyRequest request);

    @GetMapping("/internal/users/{userId}/login-status")
    UserStatus currentStatus(@PathVariable("userId") String userId);
}
