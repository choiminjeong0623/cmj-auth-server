package com.cmj.auth.login;

import jakarta.validation.constraints.NotBlank;

/**
 * 로그인 요청 본문.
 * 아이디·비밀번호가 비어 있으면 @Valid 검사에서 바로 400 (📘 Q25: 400 = 요청 형식이 틀림)
 */
public record LoginRequest(
    @NotBlank String loginId,
    @NotBlank String password,
    String loginType,   // ID(일반 계정) / AD(직원) / TIN — 없으면 ID
    String mfaCode      // MFA 대상이면 두 번째 요청에 함께 보냄
) {}
