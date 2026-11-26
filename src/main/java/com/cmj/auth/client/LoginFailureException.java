package com.cmj.auth.client;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

import java.util.Map;

/**
 * 시큐리티 서버가 알려 준 로그인 실패 이유.
 * code 예: invalid_credentials(남은 횟수) / account_locked(해제 시각) / hr_status_blocked /
 *          mfa_required / mfa_invalid(남은 횟수) / mfa_expired / mfa_resend_too_soon(남은 초)
 * params에 남은 횟수·시간을 담아 화면이 다국어 라벨로 메시지를 만들 수 있게 한다.
 */
public class LoginFailureException extends OAuth2AuthenticationException {

    private final Map<String, Object> params;

    public LoginFailureException(String code, String message, Map<String, Object> params) {
        super(new OAuth2Error(code, message, null), message);
        this.params = params == null ? Map.of() : params;
    }

    public Map<String, Object> getParams() {
        return params;
    }
}
