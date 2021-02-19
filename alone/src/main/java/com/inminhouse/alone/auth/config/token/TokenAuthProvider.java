package com.inminhouse.alone.auth.config.token;

import static lombok.AccessLevel.PACKAGE;
import static lombok.AccessLevel.PRIVATE;

import java.util.Optional;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import com.inminhouse.alone.auth.domain.service.UserAuthService;

import lombok.AllArgsConstructor;
import lombok.NonNull;
import lombok.experimental.FieldDefaults;

/**
 * token으로 user를 찾는 역할을 담당
 * 
 * @author inye
 *
 */
@Component
@AllArgsConstructor(access = PACKAGE) // 모든 필드 값을 파라미터로 받는 생성자를 만들어줌
@FieldDefaults(level = PRIVATE, makeFinal = true) // 필드의 접근 제한자 설정 가능
public final class TokenAuthProvider extends AbstractUserDetailsAuthenticationProvider {

	@NonNull
	UserAuthService auth;

	@Override
	protected void additionalAuthenticationChecks(final UserDetails userDetails,
			final UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
		// nothing
	}

	@Override
	protected UserDetails retrieveUser(final String username, final UsernamePasswordAuthenticationToken authentication)
			throws AuthenticationException {
		final Object token = authentication.getCredentials();
		return Optional.ofNullable(token)
			.map(String::valueOf)
			.flatMap(auth::findByToken)
			.orElseThrow(() -> new UsernameNotFoundException("cannot find user with this token=" + token));
	}

}
