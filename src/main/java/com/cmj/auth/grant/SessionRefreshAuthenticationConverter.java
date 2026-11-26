package com.cmj.auth.grant;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

public class SessionRefreshAuthenticationConverter implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {
        if (!CmjGrantTypes.SESSION_REFRESH.getValue().equals(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))) {
            return null;
        }
        String refreshToken = request.getParameter(OAuth2ParameterNames.REFRESH_TOKEN);
        if (!StringUtils.hasText(refreshToken)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }
        return new SessionRefreshAuthenticationToken(SecurityContextHolder.getContext().getAuthentication(), refreshToken);
    }
}
