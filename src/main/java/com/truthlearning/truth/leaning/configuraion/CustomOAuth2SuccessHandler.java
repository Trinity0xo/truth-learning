package com.truthlearning.truth.leaning.configuraion;

import com.truthlearning.truth.leaning.domain.User;
import com.truthlearning.truth.leaning.domain.response.auth.LoginResponse;
import com.truthlearning.truth.leaning.service.JsonWebTokenService;
import com.truthlearning.truth.leaning.service.RefreshTokenService;
import com.truthlearning.truth.leaning.service.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;

@Component
public class CustomOAuth2SuccessHandler implements AuthenticationSuccessHandler {
    private final UserService userService;
    private final JsonWebTokenService jsonWebTokenService;
    private final RefreshTokenService refreshTokenService;

    public CustomOAuth2SuccessHandler(UserService userService, JsonWebTokenService jsonWebTokenService, RefreshTokenService refreshTokenService) {
        this.userService = userService;
        this.jsonWebTokenService = jsonWebTokenService;
        this.refreshTokenService = refreshTokenService;
    }

    @Value("${jwt.refresh-token-valid-time-in-seconds}")
    private long refreshTokenExpireTime;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");

        User user = this.userService.handleGetUserByEmail(email);

        LoginResponse.UserResponse userResponse = new LoginResponse.UserResponse();
        userResponse.setFirstName(user.getFirstName());
        userResponse.setLastName(user.getLastName());
        userResponse.setEmail(user.getEmail());

        String accessToken = this.jsonWebTokenService.createAccessToken(userResponse);

        String refreshToken = this.jsonWebTokenService.createRefreshToken(email);

        Jwt jwtInfo = this.jsonWebTokenService.checkValidRefreshToken(refreshToken);

        Instant tokenIat = jwtInfo.getIssuedAt();
        Instant tokenExp = jwtInfo.getExpiresAt();

        this.refreshTokenService.handleAddRefreshTokenToUser(user, refreshToken, tokenIat, tokenExp);

        Cookie refreshTokenCookie = new Cookie("refresh_token", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(true);
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge((int)refreshTokenExpireTime);

        response.addCookie(refreshTokenCookie);

        response.sendRedirect("http://localhost:3000?token=" + accessToken);
    }
}
