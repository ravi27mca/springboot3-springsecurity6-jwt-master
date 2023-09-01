package com.truongbn.security.service.impl;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.truongbn.security.service.JwtService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class JwtServiceImpl implements JwtService {
	@Value("${token.signing.key}")
	private String jwtSigningKey;

	@Override
	public String extractUserName(String token) {
		log.info("JwtServiceImpl:::extractUserName:::start here");
		return extractClaim(token, Claims::getSubject);
	}

	@Override
	public String generateToken(UserDetails userDetails) {
		log.info("JwtServiceImpl:::generateToken:::start here");
		return generateToken(new HashMap<>(), userDetails);
	}

	@Override
	public boolean isTokenValid(String token, UserDetails userDetails) {
		log.info("JwtServiceImpl:::isTokenValid:::start here");
		final String userName = extractUserName(token);
		return (userName.equals(userDetails.getUsername())) && !isTokenExpired(token);
	}

	private <T> T extractClaim(String token, Function<Claims, T> claimsResolvers) {
		log.info("JwtServiceImpl:::extractClaim:::start here");
		final Claims claims = extractAllClaims(token);
		return claimsResolvers.apply(claims);
	}

	private String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
		log.info("JwtServiceImpl:::generateToken:::start here");
		return Jwts.builder().setClaims(extraClaims).setSubject(userDetails.getUsername())
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
				.signWith(getSigningKey(), SignatureAlgorithm.HS256).compact();
	}

	private boolean isTokenExpired(String token) {
		log.info("JwtServiceImpl:::isTokenExpired:::start here");
		return extractExpiration(token).before(new Date());
	}

	private Date extractExpiration(String token) {
		log.info("JwtServiceImpl:::extractExpiration:::start here");
		return extractClaim(token, Claims::getExpiration);
	}

	private Claims extractAllClaims(String token) {
		log.info("JwtServiceImpl:::extractAllClaims:::start here");
		return Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token).getBody();
	}

	private Key getSigningKey() {
		log.info("JwtServiceImpl:::getSigningKey:::start here");
		byte[] keyBytes = Decoders.BASE64.decode(jwtSigningKey);
		return Keys.hmacShaKeyFor(keyBytes);
	}
}
