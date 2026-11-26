package com.cmj.auth.login;

/** 로그인·재발급 성공 응답 */
public record TokenResponse(String accessToken, String refreshToken, long expiresIn, String userType) {}
