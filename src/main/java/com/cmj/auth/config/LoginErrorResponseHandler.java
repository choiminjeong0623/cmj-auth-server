package com.cmj.auth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import com.cmj.auth.client.LoginFailureException;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * /oauth2/token 실패 응답 형식.
 * 기본 응답(error, error_description)에 params(남은 시도 횟수, 잠금 해제 시각 등)를 더해서 내려준다.
 * 화면은 error 코드로 어떤 메시지를 보여 줄지 고르고, params로 숫자를 채운다 (✅ Q18 실패 이유별 메시지).
 *
 * 응답 예) 401 {"error":"invalid_credentials","error_description":"...","params":{"remainingAttempts":2}}
 */
public class LoginErrorResponseHandler implements AuthenticationFailureHandler {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        if (exception instanceof OAuth2AuthenticationException e) {
            OAuth2Error error = e.getError();
            body.put("error", error.getErrorCode());
            body.put("error_description", error.getDescription());
        } else {
            body.put("error", "login_failed");
        }
        if (exception instanceof LoginFailureException e && !e.getParams().isEmpty()) {
            body.put("params", e.getParams());
        }
        // 형식 오류(invalid_request)는 400, 그 외 로그인 실패는 401
        int status = "invalid_request".equals(body.get("error")) ? 400 : 401;
        response.setStatus(status);
        response.setContentType("application/json;charset=UTF-8");
        MAPPER.writeValue(response.getWriter(), body);
    }
}
