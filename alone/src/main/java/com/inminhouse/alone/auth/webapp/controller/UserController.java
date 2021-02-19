package com.inminhouse.alone.auth.webapp.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.inminhouse.alone.auth.domain.service.UserAuthService;
import com.inminhouse.alone.auth.repository.entity.User;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.NonNull;
import lombok.experimental.FieldDefaults;

@RestController
@RequestMapping("/users")
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@AllArgsConstructor(access = AccessLevel.PACKAGE)
public class UserController {

	@NonNull
	UserAuthService authentication;

	@GetMapping("/current")
	public User getCurrent(@AuthenticationPrincipal User user) {
		return user;
	}
}
