package com.truthlearning.truth.leaning.configuraion;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.truthlearning.truth.leaning.util.SecurityUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.SecretKey;

@Configuration
public class CustomSecurityConfiguration {
    @Value("${jwt.base64-secret}")
    private String jwtKey;

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(
            CustomUserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder);

        return new ProviderManager(authenticationProvider);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity, CustomOAuth2UserService customOAuth2UserService,CustomUserDetailsService customUserDetailsService, CustomOAuth2SuccessHandler customOAuth2SuccessHandler, CustomAuthenticationEntryPoint customAuthenticationEntryPoint) throws Exception {
        httpSecurity
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(
                authorize -> authorize
                        .requestMatchers("api/v1/auth/login", "api/v1/auth/register", "/oauth2/**", "api/v1/auth/refreshToken", "api/v1/auth/verify-email").permitAll()
                        .anyRequest().authenticated())
                .formLogin(AbstractHttpConfigurer::disable)
                .sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(endpoint -> endpoint.userService(customOAuth2UserService))
                        .successHandler(customOAuth2SuccessHandler))
                .oauth2ResourceServer((oauth2) -> oauth2
                        .jwt(Customizer.withDefaults())
                        .authenticationEntryPoint(customAuthenticationEntryPoint));
        return httpSecurity.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        SecretKey secret = SecurityUtil.getSecretKey(jwtKey);
        return  NimbusJwtDecoder.withSecretKey(secret).macAlgorithm(SecurityUtil.JWT_ALGORITHM).build();
    }

    @Bean
    public JwtEncoder jwtEncoder() {
        SecretKey secret = SecurityUtil.getSecretKey(jwtKey);
        return new NimbusJwtEncoder(new ImmutableSecret<>(secret));
    }
}
