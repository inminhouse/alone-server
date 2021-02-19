package com.inminhouse.alone.auth.domain.store;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.inminhouse.alone.auth.repository.entity.User;

public interface UserStore extends JpaRepository<User, Integer> {

	Optional<User> findByUsername(String username);
}
