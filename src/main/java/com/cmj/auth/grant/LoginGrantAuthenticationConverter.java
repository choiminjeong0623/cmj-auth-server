package com.cmj.auth.grant;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

import java.util.Map;

/** POST /oauth2/token 요청 파라미터를 LoginGrantAuthenticationToken으로 바꾼다 */
public class LoginGrantAuthenticationConverter implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {
        if (!CmjGrantTypes.LOGIN.getValue().equals(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))) {
            return null; // 다른 grant는 다른 컨버터가 처리
        }
        String username = request.getParameter(OAuth2ParameterNames.USERNAME);
        String password = request.getParameter(OAuth2ParameterNames.PASSWORD);
        if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }
        String loginType = StringUtils.hasText(request.getParameter("login_type")) ? request.getParameter("login_type") : "ID";
        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
        return new LoginGrantAuthenticationToken(clientPrincipal, username, password, loginType,
            request.getParameter("mfa_code"), Map.of());
    }
}
