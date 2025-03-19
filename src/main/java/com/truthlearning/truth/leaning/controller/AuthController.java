package com.truthlearning.truth.leaning.controller;

import com.truthlearning.truth.leaning.domain.RefreshToken;
import com.truthlearning.truth.leaning.domain.User;
import com.truthlearning.truth.leaning.domain.response.RestApiResponse;
import com.truthlearning.truth.leaning.domain.response.auth.LoginResponse;
import com.truthlearning.truth.leaning.dto.auth.LoginDto;
import com.truthlearning.truth.leaning.dto.auth.RegisterDto;
import com.truthlearning.truth.leaning.service.RefreshTokenService;
import com.truthlearning.truth.leaning.service.JsonWebTokenService;
import com.truthlearning.truth.leaning.service.UserService;
import com.truthlearning.truth.leaning.util.ResponseUtil;
import com.truthlearning.truth.leaning.util.SecurityUtil;
import jakarta.validation.constraints.Null;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final JsonWebTokenService jsonWebTokenService;
    private final RefreshTokenService refreshTokenService;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    public AuthController(UserService userService, PasswordEncoder passwordEncoder, JsonWebTokenService jsonWebTokenService, RefreshTokenService refreshTokenService, AuthenticationManagerBuilder authenticationManagerBuilder) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.jsonWebTokenService = jsonWebTokenService;
        this.refreshTokenService = refreshTokenService;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
    }

    @Value("${jwt.refresh-token-valid-time-in-seconds}")
    private long refreshTokenExpireTime;

    @PostMapping("/register")
    public ResponseEntity<User> register(
            @RequestBody RegisterDto registerDto
            ){
        String hashedPassword = passwordEncoder.encode(registerDto.getPassword());
        registerDto.setPassword(hashedPassword);

        User user = this.userService.handleCreateNewUser(registerDto);

        return ResponseEntity.status(HttpStatus.CREATED).body(user);
    }

    @PostMapping("/login")
    public ResponseEntity<RestApiResponse<LoginResponse>> login(
            @RequestBody LoginDto loginDto
    ) {

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                loginDto.getEmail(), loginDto.getPassword());

        Authentication authentication = authenticationManagerBuilder.getObject()
                .authenticate(authenticationToken);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        User user = this.userService.handleGetUserByEmail(loginDto.getEmail());

        LoginResponse.UserResponse userResponse = new LoginResponse.UserResponse();
        userResponse.setFirstName(user.getFirstName());
        userResponse.setLastName(user.getLastName());
        userResponse.setEmail(user.getEmail());

        String accessToken = this.jsonWebTokenService.createAccessToken(userResponse);

        String refreshToken = this.jsonWebTokenService.createRefreshToken(loginDto.getEmail());

        Jwt jwtInfo = this.jsonWebTokenService.checkValidRefreshToken(refreshToken);

        Instant tokenIat = jwtInfo.getIssuedAt();
        Instant tokenExp = jwtInfo.getExpiresAt();

        this.refreshTokenService.handleAddRefreshTokenToUser(user, refreshToken, tokenIat, tokenExp);

        ResponseCookie responseCookie = ResponseCookie
                .from("refresh_token", refreshToken)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(refreshTokenExpireTime)
                .build();

        LoginResponse loginResponse = new LoginResponse();
        loginResponse.setUser(userResponse);
        loginResponse.setAccess_token(accessToken);

        RestApiResponse<LoginResponse> response
                = ResponseUtil.success(loginResponse, "Login success", HttpStatus.OK.value());

        return ResponseEntity.status(HttpStatus.OK).header(HttpHeaders.SET_COOKIE, responseCookie.toString()).body(response);
    }

    @PostMapping("/refreshToken")
    public ResponseEntity<RestApiResponse<LoginResponse>> refreshToken(
            @CookieValue(name = "refresh_token", defaultValue = "") String refreshToken
    ) {
//        if(refreshToken.isEmpty()){
//            return ResponseEntity.ok().body("refresh token not found");
//        }

        Jwt jwt = this.jsonWebTokenService.checkValidRefreshToken(refreshToken);

        String email = jwt.getSubject();

        User user = this.userService.handleGetUserByEmail(email);
//        if(user == null){
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("user not found");
//        }

        RefreshToken oldRefreshToken = this.refreshTokenService.handleGetRefreshToken(user, refreshToken);
//        if(oldRefreshToken == null){
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("refresh token is invalid");
//        }

        Instant tokenExp = jwt.getExpiresAt();
        Instant tokenIat = jwt.getIssuedAt();

//        if(tokenIat == null || tokenExp == null){
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("refresh token is invalid");
//        }

        boolean validExpire = this.refreshTokenService.handleCheckValidExpireTime(oldRefreshToken, tokenIat, tokenExp);

//        if(!validExpire){
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("refresh token is invalid");
//        }

        LoginResponse.UserResponse userResponse = new LoginResponse.UserResponse();
        userResponse.setFirstName(user.getFirstName());
        userResponse.setLastName(user.getLastName());
        userResponse.setEmail(user.getEmail());

        String accessToken = this.jsonWebTokenService.createAccessToken(userResponse);

        String newRefreshToken = this.jsonWebTokenService.createRefreshToken(userResponse.getEmail());

        Jwt jwtInfo = this.jsonWebTokenService.checkValidRefreshToken(newRefreshToken);

        Instant newTokenIat = jwtInfo.getIssuedAt();
        Instant newTokenExp = jwtInfo.getExpiresAt();

        this.refreshTokenService.handleAddRefreshTokenToUser(user, newRefreshToken, newTokenIat, newTokenExp);

        this.refreshTokenService.handleDeleteOldRefreshToken(oldRefreshToken);

        ResponseCookie responseCookie = ResponseCookie
                .from("refresh_token", newRefreshToken)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(refreshTokenExpireTime)
                .build();

        LoginResponse loginResponse = new LoginResponse();
        loginResponse.setUser(userResponse);
        loginResponse.setAccess_token(accessToken);

        RestApiResponse<LoginResponse> response
                = ResponseUtil.success(loginResponse, "Refresh token success", HttpStatus.OK.value());

        return ResponseEntity.status(HttpStatus.OK).header(HttpHeaders.SET_COOKIE, responseCookie.toString()).body(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<RestApiResponse<Void>> logout(@CookieValue(name = "refresh_token", defaultValue = "") String refreshToken) {
        String email = SecurityUtil.getCurrentUserLogin().isPresent() ? SecurityUtil.getCurrentUserLogin().get() : "";

        if(!refreshToken.isEmpty()){
            User user = this.userService.handleGetUserByEmail(email);
            if(user !=null){
                RefreshToken oldRefreshToken = this.refreshTokenService.handleGetRefreshToken(user, refreshToken);
                if(oldRefreshToken != null){
                    this.refreshTokenService.handleDeleteOldRefreshToken(oldRefreshToken);
                }
            }
        }

        ResponseCookie emptySpringCookie = ResponseCookie
                .from("refresh_token","" )
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(0)
                .build();

        SecurityContextHolder.clearContext();

        RestApiResponse<Void> response
                = ResponseUtil.success(null, "Logout success", HttpStatus.OK.value());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, emptySpringCookie.toString())
                .body(response);
    }
}
