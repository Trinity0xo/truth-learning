package com.truthlearning.truth.leaning.service;

import com.truthlearning.truth.leaning.domain.response.auth.LoginResponse;
import com.truthlearning.truth.leaning.util.SecurityUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;

@Service
public class JsonWebTokenService {
    private final JwtEncoder jwtEncoder;

    public JsonWebTokenService(JwtEncoder jwtEncoder){
        this.jwtEncoder = jwtEncoder;
    }

    @Value("${jwt.base64-secret}")
    private String jwtKey;

    @Value("${jwt.access-token-valid-time-in-seconds}")
    private long accessTokenExpireTime;

    @Value("${jwt.refresh-token-valid-time-in-seconds}")
    private long refreshTokenExpireTime;

    public String createAccessToken(LoginResponse.UserResponse userResponse){
        Instant now = Instant.now();
        Instant validity = now.plus(this.accessTokenExpireTime, ChronoUnit.SECONDS);

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuedAt(now)
                .expiresAt(validity)
                .subject(userResponse.getEmail())
                .claim("user", userResponse)
                .build();

        JwsHeader jwsHeader = JwsHeader.with(SecurityUtil.JWT_ALGORITHM).build();

        return this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims)).getTokenValue();
    }

    public String createRefreshToken(String email){
        Instant now = Instant.now();
        Instant validity = now.plus(this.refreshTokenExpireTime, ChronoUnit.SECONDS);

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuedAt(now)
                .expiresAt(validity)
                .subject(email)
                .build();

        JwsHeader jwsHeader = JwsHeader.with(SecurityUtil.JWT_ALGORITHM).build();

        return this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims)).getTokenValue();
    }

    public Jwt checkValidRefreshToken(String token){
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withSecretKey(SecurityUtil.getSecretKey(jwtKey)).macAlgorithm(SecurityUtil.JWT_ALGORITHM).build();
        return jwtDecoder.decode(token);
    }
}
