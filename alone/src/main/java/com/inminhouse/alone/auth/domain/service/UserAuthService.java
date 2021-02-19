
package com.inminhouse.alone.auth.domain.service;

import java.util.Optional;

import com.inminhouse.alone.auth.repository.entity.User;

public interface UserAuthService {

	Optional<String> login(String id, String password);

	Optional<User> findByToken(String token);

	void logout(User user);

}
