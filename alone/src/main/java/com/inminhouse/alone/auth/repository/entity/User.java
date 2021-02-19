package com.inminhouse.alone.auth.repository.entity;

import static java.util.Objects.requireNonNull;

import java.util.Collection;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Builder;
import lombok.Value;

/**
 * SpringSecurity에서 User 빈을 사용하기 위해 UserDetails를 상속 받는다.
 * 
 * @author inye
 *
 */
@Entity
@Table(name = "user")
@Value
@Builder
public class User implements UserDetails {

	// 객체를 바이트배열로 변환을해서 파일, 메모리, 데이터베이스에 저장 하는 과정인 직렬화와 그 반대되는 과정인 역직렬화에서 사용
	// 모든 클래스는 uid를 가지고 있음. 이 값이 변경되면 다른 class로 인색하게 됨
	// 객체에 대한 지문(fingerprint)
	// 따로 정의되어 있지않으면 jvm이 설정해주나 os 따라 이 값이 달라질 수 있음(os 따라 jvm이 다르므로)
	private static final long serialVersionUID = 1L;

	@Id
	String username;
	String password;

	public User() {
		username = null;
		password = null;
	}

	@JsonCreator // JSON을 역직렬할 때 property 이름과 엔터티의 프로퍼티 이름이 다른 것을 보완해줌
	public User(@JsonProperty("id") final String username, @JsonProperty("password") final String password) {
		super();
		this.username = requireNonNull(username);
		this.password = requireNonNull(password);
	}

	@JsonIgnore // JSON 직렬화에서 제외시킬 프로퍼티를 지정할 때 사용
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return null;
	}

	@Override
	public String getPassword() {
		return this.password;
	}

	@Override
	public String getUsername() {
		return this.username;
	}

	@JsonIgnore
	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@JsonIgnore
	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@JsonIgnore
	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

	@Override
	public String toString() {
		return new StringBuilder("username=").append(this.username)
			.append(", password=")
			.append(this.password)
			.toString();
	}

}
