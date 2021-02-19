package com.inminhouse.alone.auth.webapp.service;

import java.util.Collections;
import java.util.Objects;
import java.util.Optional;

import org.springframework.stereotype.Service;

import com.inminhouse.alone.api.token.TokenService;
import com.inminhouse.alone.auth.domain.service.UserAuthService;
import com.inminhouse.alone.auth.domain.store.UserStore;
import com.inminhouse.alone.auth.repository.entity.User;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.NonNull;
import lombok.experimental.FieldDefaults;

@Service
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class UserAuthServiceImpl implements UserAuthService {

	@NonNull
	TokenService tokens;

	@NonNull
	UserStore store;

	@Override
	public Optional<String> login(String id, String password) {

		return store.findByUsername(id)
			.filter(user -> Objects.equals(password, user.getPassword()))
			.map(user -> tokens.expiring(Collections.singletonMap("username", id)));
	}

	@Override
	public Optional<User> findByToken(String token) {
		return Optional.of(tokens.verify(token))
			.map(map -> map.get("username"))
			.flatMap(store::findByUsername);
	}

	@Override
	public void logout(User user) {
		// TODO Auto-generated method stub

	}

}
