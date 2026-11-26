package com.cmj.auth.login;

import org.springframework.stereotype.Service;
import com.cmj.auth.client.LoginFailureException;
import com.cmj.auth.client.SecurityServerClient;
import com.cmj.auth.token.AccessTokenIssuer;
import com.cmj.auth.token.RefreshTokenStore;
import com.cmj.common.security.SessionData;
import com.cmj.common.security.SessionStore;

import java.util.Map;

/**
 * 인증 서버는 "토큰을 만드는 일"만 하고, 로그인해도 되는 사람인지는 시큐리티 서버가 판단한다 (✅ Q24)
 *
 * 순서가 중요: 검증 → (성공했을 때만) 세션 생성 → 토큰 발급
 *   → 다른 사람이 내 아이디로 비밀번호를 틀리게 넣으면 1)에서 멈추므로 내 세션은 그대로 (📘 Q26)
 */
@Service
public class LoginService {

    private final SecurityServerClient securityServer;
    private final AccessTokenIssuer accessTokens;
    private final RefreshTokenStore refreshTokens;
    private final SessionStore sessions;

    public LoginService(SecurityServerClient securityServer, AccessTokenIssuer accessTokens,
                        RefreshTokenStore refreshTokens, SessionStore sessions) {
        this.securityServer = securityServer;
        this.accessTokens = accessTokens;
        this.refreshTokens = refreshTokens;
        this.sessions = sessions;
    }

    public TokenResponse login(LoginRequest req, String clientIp, String userAgent) {
        String loginType = req.loginType() == null ? "ID" : req.loginType();

        // 1) 로그인 규칙 검사 + 성공 시 세션 생성(setSession)은 시큐리티 서버 — FeignClient 호출
        //    실패하면 ErrorDecoder가 LoginFailureException(이유 코드 + 남은 횟수 등)으로 바꿔 던짐 → 401
        SecurityServerClient.LoginResult result = securityServer.verify(new SecurityServerClient.VerifyRequest(
            req.loginId(), req.password(), loginType, req.mfaCode(), clientIp, userAgent));

        // 2) Access Token(JWT): sub·user_type·sid
        // 3) Refresh Token: Redis (rt:{token})
        return issue(result.userId(), result.userType(), result.sid());
    }

    /**
     * 재발급 때 다시 확인하는 것:
     *  - Refresh Token이 Redis에 있는가 / 사용자 세션이 아직 있는가(미사용 자동 로그아웃, ✅ Q16)
     *  - 세션의 sid가 같은가(다른 곳에서 새로 로그인, ✅ Q5) / 그사이 퇴직·휴직·잠금되지 않았는가
     */
    public TokenResponse refresh(String refreshToken) {
        RefreshTokenStore.Entry entry = refreshTokens.consume(refreshToken)
            .orElseThrow(() -> fail("session_expired", "세션이 만료되었습니다. 다시 로그인하세요."));
        SessionData session = sessions.find(entry.userId())
            .orElseThrow(() -> fail("session_expired", "오랫동안 사용하지 않아 로그아웃되었습니다."));
        if (!session.sid().equals(entry.sid())) {
            throw fail("logged_in_elsewhere", "다른 곳에서 로그인되어 로그아웃되었습니다.");
        }
        SecurityServerClient.UserStatus status = securityServer.currentStatus(entry.userId()); // 막혔으면 여기서 예외
        return issue(status.userId(), status.userType(), entry.sid());
    }

    private TokenResponse issue(String userId, String userType, String sid) {
        AccessTokenIssuer.Issued access = accessTokens.issue(userId, userType, sid);
        String refresh = refreshTokens.issue(new RefreshTokenStore.Entry(userId, sid));
        return new TokenResponse(access.token(), refresh, access.expiresInSeconds(), userType);
    }

    private static LoginFailureException fail(String code, String message) {
        return new LoginFailureException(code, message, Map.of());
    }
}
