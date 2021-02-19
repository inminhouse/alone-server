package com.inminhouse.alone.api.token;

import java.util.Map;

/**
 * 토큰 발급, 토큰 검사
 * 
 * @author inye
 *
 */
public interface TokenService {

	String permanent(Map<String, String> attributes);

	String expiring(Map<String, String> attributes);

	Map<String, String> untrusted(String token);

	Map<String, String> verify(String token);
}
