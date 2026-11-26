package com.cmj.auth.grant;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.Map;

public class LoginGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    private final String username;
    private final String password;
    private final String loginType;   // ID(기본) 또는 TIN(납세자 고유번호 로그인)
    private final String mfaCode;     // MFA 대상이면 두 번째 요청에 함께 보냄

    public LoginGrantAuthenticationToken(Authentication clientPrincipal, String username, String password,
                                         String loginType, String mfaCode, Map<String, Object> additionalParameters) {
        super(CmjGrantTypes.LOGIN, clientPrincipal, additionalParameters);
        this.username = username;
        this.password = password;
        this.loginType = loginType;
        this.mfaCode = mfaCode;
    }

    public String getUsername() { return username; }
    public String getPassword() { return password; }
    public String getLoginType() { return loginType; }
    public String getMfaCode() { return mfaCode; }

    @Override
    public Object getCredentials() { return password; }
}
