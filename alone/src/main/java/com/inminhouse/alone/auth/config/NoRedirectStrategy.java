package com.inminhouse.alone.auth.config;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.RedirectStrategy;

/**
 * REST API라서 인증 실패할 경우 에러 페이지로 리다이렉트가 아닌 401 응답을 날려야함
 * 
 * @author inye
 *
 */
public class NoRedirectStrategy implements RedirectStrategy {

	@Override
	public void sendRedirect(HttpServletRequest request, HttpServletResponse response, String url) throws IOException {
		// No redirect is required with pure REST

	}

}
