package com.cmj.auth.grant;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

public final class CmjGrantTypes {
    /** 아이디·비밀번호(+MFA 코드) 로그인 */
    public static final AuthorizationGrantType LOGIN =
        new AuthorizationGrantType("urn:cmj:params:oauth:grant-type:login");
    /** Redis 세션 기반 토큰 재발급 */
    public static final AuthorizationGrantType SESSION_REFRESH =
        new AuthorizationGrantType("urn:cmj:params:oauth:grant-type:session-refresh");

    private CmjGrantTypes() {}
}
