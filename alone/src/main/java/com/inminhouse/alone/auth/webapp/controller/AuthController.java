package com.inminhouse.alone.auth.webapp.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.inminhouse.alone.auth.domain.service.UserAuthService;
import com.inminhouse.alone.auth.domain.store.UserStore;
import com.inminhouse.alone.auth.webapp.form.UserForm;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.NonNull;
import lombok.experimental.FieldDefaults;

@RestController
@RequestMapping("/public/users")
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@AllArgsConstructor(access = AccessLevel.PACKAGE)
public class AuthController {

	@NonNull
	UserAuthService authentication;

	@NonNull
	UserStore store;

	@PostMapping("/login")
	public String login(@RequestBody UserForm userForm) {

		return authentication.login(userForm.getId(), userForm.getPassword())
			.orElseThrow(() -> new RuntimeException("invalid login and/or password"));
	}

}
