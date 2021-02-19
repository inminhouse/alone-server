package com.inminhouse.alone.auth.config.token;

import static lombok.AccessLevel.PRIVATE;

import java.io.IOException;
import java.util.Optional;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import lombok.experimental.FieldDefaults;

/**
 * request에서 auth token을 추출하는 역할을 담당 Authorization 헤더에서 토큰을 추출함
 * 
 * @author inye
 *
 */
@FieldDefaults(level = PRIVATE, makeFinal = true)
public final class TokenAuthFilter extends AbstractAuthenticationProcessingFilter {

	private static final String BEARER = "Bearer";

	public TokenAuthFilter(final RequestMatcher requiresAuth) {
		super(requiresAuth);
	}

	@Override
	public Authentication attemptAuthentication(final HttpServletRequest request, final HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {

		final String param = Optional.ofNullable(request.getHeader(HttpHeaders.AUTHORIZATION))
			.orElse(request.getParameter("t"));

		final String token = Optional.ofNullable(param)
			.map(value -> StringUtils.removeStart(value, BEARER))
			.map(String::trim)
			.orElseThrow(() -> new BadCredentialsException("Missing Authentication Token"));

		final Authentication auth = new UsernamePasswordAuthenticationToken(token, token);

		return getAuthenticationManager().authenticate(auth);
	}

	@Override
	protected void successfulAuthentication(final HttpServletRequest request, final HttpServletResponse response,
			final FilterChain chain, final Authentication authResult) throws IOException, ServletException {

		super.successfulAuthentication(request, response, chain, authResult);
		chain.doFilter(request, response);
	}
}
