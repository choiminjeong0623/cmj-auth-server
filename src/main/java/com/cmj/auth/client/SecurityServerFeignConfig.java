package com.cmj.auth.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import feign.RequestInterceptor;
import feign.codec.ErrorDecoder;
import org.springframework.context.annotation.Bean;
import com.cmj.auth.config.AuthProperties;

import java.io.InputStream;
import java.util.Map;

/**
 * Feign 설정 (이 클라이언트에만 적용 — @Configuration을 붙이지 않음)
 *  - 요청마다 내부 키 헤더를 붙임 → 시큐리티 서버가 "OAuth 서버가 부른 것"인지 확인
 *  - 실패 응답(code·message·params)을 LoginFailureException으로 바꿔 화면까지 그대로 전달
 *    → ✅ Q18 "실패 이유에 따라 화면 메시지를 다르게" 의 백엔드 쪽 연결
 * ⚠️ 내부 호출 보호 방식(키 헤더)은 예시. 실제 방식 미확인.
 */
public class SecurityServerFeignConfig {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Bean
    RequestInterceptor internalKeyInterceptor(AuthProperties props) {
        return template -> template.header("X-Internal-Key", props.internalApiKey());
    }

    @Bean
    ErrorDecoder loginErrorDecoder() {
        ErrorDecoder fallback = new ErrorDecoder.Default();
        return (methodKey, response) -> {
            if (response.status() == 401 || response.status() == 403 || response.status() == 503) {
                try (InputStream body = response.body().asInputStream()) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> m = MAPPER.readValue(body, Map.class);
                    @SuppressWarnings("unchecked")
                    Map<String, Object> params = (Map<String, Object>) m.getOrDefault("params", Map.of());
                    return new LoginFailureException((String) m.get("code"), (String) m.get("message"), params);
                } catch (Exception e) {
                    return new LoginFailureException("login_failed", "로그인할 수 없습니다.", Map.of());
                }
            }
            return fallback.decode(methodKey, response);
        };
    }
}
