package com.inminhouse.alone.auth.config;

import static lombok.AccessLevel.PRIVATE;

import java.util.Objects;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.inminhouse.alone.auth.config.token.TokenAuthFilter;
import com.inminhouse.alone.auth.config.token.TokenAuthProvider;

import lombok.experimental.FieldDefaults;

@Configuration
@EnableWebSecurity
//@EnableGlobalMethodSecurity
@FieldDefaults(level = PRIVATE, makeFinal = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private static final RequestMatcher PUBLIC_URLS = new OrRequestMatcher(new AntPathRequestMatcher("/public/**"));

	private static final RequestMatcher PROTECTED_URLS = new NegatedRequestMatcher(PUBLIC_URLS);

	TokenAuthProvider provider;

	public SecurityConfig(final TokenAuthProvider provider) {
		super();
		this.provider = Objects.requireNonNull(provider);
	}

	@Override
	protected void configure(final AuthenticationManagerBuilder auth) {
		auth.authenticationProvider(provider);
	}

	@Override
	protected void configure(final HttpSecurity http) throws Exception {
		http.sessionManagement()
			.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.exceptionHandling()
			// /public/** 으로 시작하는 URL은 SECURITY가 적용되지 않음
			.defaultAuthenticationEntryPointFor(forbiddenEntryPoint(), PROTECTED_URLS)
			.and()
			.authenticationProvider(provider)
			// SECURITY FILTER CHAIN 상반부에 등록됨
			.addFilterBefore(restAuthenticationFilter(), AnonymousAuthenticationFilter.class)
			.authorizeRequests()
			.requestMatchers(PROTECTED_URLS)
			.authenticated()
			.and()
			.csrf()
			.disable()
			// FORM이나 HTTP로 하는 로그인은 사용하지 않겠다
			.formLogin()
			.disable()
			.httpBasic()
			.disable()
			.logout()
			.disable();

	}

	@Bean
	TokenAuthFilter restAuthenticationFilter() throws Exception {
		final TokenAuthFilter filter = new TokenAuthFilter(PROTECTED_URLS);
		filter.setAuthenticationManager(authenticationManager());
		filter.setAuthenticationSuccessHandler(successHandler());
		return filter;
	}

	@Bean
	SimpleUrlAuthenticationSuccessHandler successHandler() {
		final SimpleUrlAuthenticationSuccessHandler successHandler = new SimpleUrlAuthenticationSuccessHandler();
		successHandler.setRedirectStrategy(new NoRedirectStrategy());
		return successHandler;
	}

	/**
	 * 자동 필터 등록 비활성화 boiler-plate code 상용코드
	 * 
	 * @param filter
	 * @return
	 */
	@Bean
	FilterRegistrationBean<TokenAuthFilter> disableAutoRegistration(final TokenAuthFilter filter) {
		final FilterRegistrationBean<TokenAuthFilter> registration = new FilterRegistrationBean<TokenAuthFilter>(
				filter);
		registration.setEnabled(false);
		return registration;
	}

	@Bean
	AuthenticationEntryPoint forbiddenEntryPoint() {
		return new HttpStatusEntryPoint(HttpStatus.FORBIDDEN);
	}

}
