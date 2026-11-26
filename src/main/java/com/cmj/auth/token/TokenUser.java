package com.cmj.auth.token;

/** JWT를 만들 때 넣을 최소 정보. 사용자 상세·권한은 Redis 세션에 있으므로 여기엔 없다 */
public record TokenUser(String userId, String userType) {}
