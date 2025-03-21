package com.truthlearning.truth.leaning.controller;

import com.truthlearning.truth.leaning.domain.RefreshToken;
import com.truthlearning.truth.leaning.domain.User;
import com.truthlearning.truth.leaning.domain.VerifyToken;
import com.truthlearning.truth.leaning.domain.response.RestApiResponse;
import com.truthlearning.truth.leaning.domain.response.auth.LoginResponse;
import com.truthlearning.truth.leaning.dto.auth.LoginDto;
import com.truthlearning.truth.leaning.dto.auth.RegisterDto;
import com.truthlearning.truth.leaning.dto.auth.VerifyEmailDto;
import com.truthlearning.truth.leaning.service.*;
import com.truthlearning.truth.leaning.util.ResponseUtil;
import com.truthlearning.truth.leaning.util.SecurityUtil;
import com.truthlearning.truth.leaning.util.error.BadRequestException;
import com.truthlearning.truth.leaning.util.error.ConflictException;
import com.truthlearning.truth.leaning.util.error.NotFoundException;
import com.truthlearning.truth.leaning.util.error.UnAuthorizedException;
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
@RequestMapping("api/v1/auth")
public class AuthController {
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final JsonWebTokenService jsonWebTokenService;
    private final RefreshTokenService refreshTokenService;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final MailService mailService;
    private final VerifyTokenService verifyTokenService;

    public AuthController(UserService userService, PasswordEncoder passwordEncoder, JsonWebTokenService jsonWebTokenService, RefreshTokenService refreshTokenService, AuthenticationManagerBuilder authenticationManagerBuilder, MailService mailService, VerifyTokenService verifyTokenService) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.jsonWebTokenService = jsonWebTokenService;
        this.refreshTokenService = refreshTokenService;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
        this.mailService = mailService;
        this.verifyTokenService = verifyTokenService;
    }

    @Value("${jwt.refresh-token-valid-time-in-seconds}")
    private long refreshTokenExpireTime;

    @Value("${verify.token-valid-time-in-seconds}")
    private long verifyTokenExpireTime;

    @PostMapping("/register")
    public ResponseEntity<RestApiResponse<Void>> register(
            @RequestBody RegisterDto registerDto
            ){

        User user = this.userService.handleGetUserByEmail(registerDto.getEmail());
        if(user !=null){
            throw new ConflictException("Người dùng đã tồn tại");
        }

        String hashedPassword = passwordEncoder.encode(registerDto.getPassword());
        registerDto.setPassword(hashedPassword);

        user = this.userService.handleCreateNewUser(registerDto);

        VerifyToken verifyEmailToken = this.verifyTokenService.handleCreateVerifyToken(user,verifyTokenExpireTime);

        String username = user.getFirstName() + " " + user.getLastName();

        this.mailService.handleSendVerifyEmailLink(username, user.getEmail(), verifyEmailToken.getTokenValue());

        RestApiResponse<Void> response
                = ResponseUtil.success(null, "Đăng ký thành công, vui lòng kiểm tra email để xác thực tài khoản", HttpStatus.CREATED.value());

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/verify-email")
    public ResponseEntity<RestApiResponse<Void>> verifyEmail(
            @RequestBody VerifyEmailDto verifyEmailDto
            ){

        VerifyToken verifyTokenDb = this.verifyTokenService.handleGetVerifyEmailTokenByTokenValue(verifyEmailDto.getVerifyEmailToken());
        if(verifyTokenDb == null){
            throw new BadRequestException("Token không hợp lệ hoặc hết hạn");
        }

        boolean isValidExpire = this.verifyTokenService.handleCheckValidExpireTime(verifyTokenDb);
        if(!isValidExpire){
            throw new BadRequestException("Token không hợp lệ hoặc hết hạn");
        }

        this.userService.handleUpdateVerifyStatus(verifyTokenDb.getUser());

        this.verifyTokenService.handleDeleteVerifyEmailToken(verifyTokenDb);

        RestApiResponse<Void> response = ResponseUtil.success(null, "Xác thực tài khoản thành công", HttpStatus.OK.value());

        return ResponseEntity.status(HttpStatus.OK).body(response);
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
        if(!user.isVerified()){
            VerifyToken oldVerifyToken = this.verifyTokenService.handleGetVerifyEmailTokenByUser(user);
            if(oldVerifyToken !=null){
                this.verifyTokenService.handleDeleteVerifyEmailToken(oldVerifyToken);
            }

            VerifyToken verifyEmailToken = this.verifyTokenService.handleCreateVerifyToken(user,verifyTokenExpireTime);
            String username = user.getFirstName() + " " + user.getLastName();
            this.mailService.handleSendVerifyEmailLink(username, user.getEmail(), verifyEmailToken.getTokenValue());

            throw new UnAuthorizedException("Tài khoản chưa xác thực email, vui lòng kiểm tra email để xác thực");
        }

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
                = ResponseUtil.success(loginResponse, "Đăng nhập thành công", HttpStatus.OK.value());

        return ResponseEntity.status(HttpStatus.OK).header(HttpHeaders.SET_COOKIE, responseCookie.toString()).body(response);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<RestApiResponse<LoginResponse>> refreshToken(
            @CookieValue(name = "refresh_token", defaultValue = "") String refreshToken
    ) {
        Jwt jwt = this.jsonWebTokenService.checkValidRefreshToken(refreshToken);

        String email = jwt.getSubject();

        User user = this.userService.handleGetUserByEmail(email);
        if(user == null){
            throw new NotFoundException("Không tìm thấy người dùng");
        }

        RefreshToken refreshTokenDb = this.refreshTokenService.handleGetRefreshToken(user, refreshToken);
        if(refreshTokenDb == null){
            throw new BadRequestException("Token không hợp lệ hoặc hết hạn");
        }

        Instant tokenExp = jwt.getExpiresAt();
        Instant tokenIat = jwt.getIssuedAt();


        boolean isValidExpire = this.refreshTokenService.handleCheckValidExpireTime(refreshTokenDb, tokenIat, tokenExp);

        if(!isValidExpire){
            throw new BadRequestException("Token không hợp lệ hoặc hết hạn");
        }

        LoginResponse.UserResponse userResponse = new LoginResponse.UserResponse();
        userResponse.setFirstName(user.getFirstName());
        userResponse.setLastName(user.getLastName());
        userResponse.setEmail(user.getEmail());

        String newAccessToken = this.jsonWebTokenService.createAccessToken(userResponse);

        String newRefreshToken = this.jsonWebTokenService.createRefreshToken(userResponse.getEmail());

        Jwt jwtInfo = this.jsonWebTokenService.checkValidRefreshToken(newRefreshToken);

        Instant newTokenIat = jwtInfo.getIssuedAt();
        Instant newTokenExp = jwtInfo.getExpiresAt();

        this.refreshTokenService.handleAddRefreshTokenToUser(user, newRefreshToken, newTokenIat, newTokenExp);

        this.refreshTokenService.handleDeleteOldRefreshToken(refreshTokenDb);

        ResponseCookie responseCookie = ResponseCookie
                .from("refresh_token", newRefreshToken)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(refreshTokenExpireTime)
                .build();

        LoginResponse loginResponse = new LoginResponse();
        loginResponse.setUser(userResponse);
        loginResponse.setAccess_token(newAccessToken);

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
                = ResponseUtil.success(null, "Đăng xuất thành công", HttpStatus.OK.value());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, emptySpringCookie.toString())
                .body(response);
    }
}
