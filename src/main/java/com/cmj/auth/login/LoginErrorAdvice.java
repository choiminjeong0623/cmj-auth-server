package com.cmj.auth.login;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import com.cmj.auth.client.LoginFailureException;

import java.util.Map;

/**
 * 실패 응답 모양을 하나로 맞춘다 → 화면은 error 코드로 문구를 고르고 params로 숫자를 채운다 (✅ Q18)
 *   400 {"error":"invalid_request"}                                   — 아이디·비밀번호 누락 (형식 오류)
 *   401 {"error":"invalid_credentials","params":{"remainingAttempts":2}} — 로그인 규칙에서 막힘
 *   503 {"error":"ad_unavailable"}                                    — AD 연결 장애
 */
@RestControllerAdvice
public class LoginErrorAdvice {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    ResponseEntity<Map<String, Object>> invalid(MethodArgumentNotValidException e) {
        return ResponseEntity.badRequest().body(Map.of("error", "invalid_request"));
    }

    @ExceptionHandler(LoginFailureException.class)
    ResponseEntity<Map<String, Object>> loginFailed(LoginFailureException e) {
        HttpStatus status = "ad_unavailable".equals(e.getCode()) ? HttpStatus.SERVICE_UNAVAILABLE : HttpStatus.UNAUTHORIZED;
        return ResponseEntity.status(status).body(Map.of(
            "error", e.getCode(),
            "error_description", String.valueOf(e.getMessage()),
            "params", e.getParams()));
    }
}
