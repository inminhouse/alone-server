package com.inminhouse.alone.api.token;

import static java.util.Objects.requireNonNull;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Clock;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.TextCodec;
import io.jsonwebtoken.impl.compression.GzipCompressionCodec;
import lombok.AccessLevel;
import lombok.experimental.FieldDefaults;

@Service
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public final class JWTTokenService implements TokenService, Clock {

	private static final String DOT = ".";

	private static final GzipCompressionCodec COMPRESSION_CODEC = new GzipCompressionCodec();

	String issuer;
	int expirationSec;
	int clockSkewSec;
	String secretKey;

	public JWTTokenService(@Value("${jwt.issuer:inminhouse}") final String issuer,
			@Value("${jwt.expiration-sec:86400}") final int expirationSec,
			@Value("${jwt.clock-skew-sec:300}") final int clockSkewSec,
			@Value("${jwt.secret:secret}") final String secret) {
		super();
		this.issuer = requireNonNull(issuer);
		this.expirationSec = requireNonNull(expirationSec);
		this.clockSkewSec = requireNonNull(clockSkewSec);
		this.secretKey = TextCodec.BASE64.encode(requireNonNull(secret));
	}

	@Override
	public String permanent(final Map<String, String> attributes) {

		return newToken(attributes, 0);
	}

	@Override
	public String expiring(Map<String, String> attributes) {
		return newToken(attributes, expirationSec);
	}

	@Override
	public Map<String, String> untrusted(String token) {
		final JwtParser parser = Jwts.parser()
			.requireIssuer(issuer)
			.setClock(this)
			.setAllowedClockSkewSeconds(clockSkewSec);
		String withoutSignature = StringUtils.substringBeforeLast(token, DOT) + DOT;
		return parseClaims(() -> parser.parseClaimsJwt(withoutSignature)
			.getBody());
	}

	@Override
	public Map<String, String> verify(String token) {
		JwtParser parser = Jwts.parser()
			.requireIssuer(issuer)
			.setClock(this)
			.setAllowedClockSkewSeconds(clockSkewSec)
			.setSigningKey(secretKey);
		return parseClaims(() -> parser.parseClaimsJws(token)
			.getBody());
	}

	private String newToken(final Map<String, String> attributes, final int expireInSec) {
		final LocalDateTime now = LocalDateTime.now();
		final Claims claims = Jwts.claims()
			.setIssuer(issuer)
			.setIssuedAt(Date.from(now.atZone(ZoneId.systemDefault())
				.toInstant()));

		// 만료 기간이 있을 경우
		if (expireInSec > 0) {
			final LocalDateTime expiresAt = now.plusSeconds(expireInSec);
			claims.setExpiration(Date.from(expiresAt.atZone(ZoneId.systemDefault())
				.toInstant()));
		}

		claims.putAll(attributes);

		return Jwts.builder()
			.setClaims(claims)
			.signWith(SignatureAlgorithm.HS256, secretKey)
			.compressWith(COMPRESSION_CODEC)
			.compact();
	}

	private Map<String, String> parseClaims(Supplier<Claims> toClaims) {
		Map<String, String> map = new HashMap<>();
		try {
			Claims claims = toClaims.get();
			// TODO: need to be immutable
			for (Map.Entry<String, Object> e : claims.entrySet()) {
				map.put(e.getKey(), String.valueOf(e.getValue()));
			}
			return map;
		} catch (IllegalArgumentException | JwtException e) {
			return map;
		}
	}

	@Override
	public Date now() {
		LocalDateTime now = LocalDateTime.now();
		return Date.from(now.atZone(ZoneId.systemDefault())
			.toInstant());
	}
}
