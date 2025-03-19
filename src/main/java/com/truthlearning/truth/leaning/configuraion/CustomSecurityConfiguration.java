package com.truthlearning.truth.leaning.configuraion;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.truthlearning.truth.leaning.util.SecurityUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity, CustomOAuth2SuccessHandler customOAuth2SuccessHandler, CustomAuthenticationEntryPoint customAuthenticationEntryPoint) throws Exception {
        httpSecurity
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(
                authorize -> authorize
                        .requestMatchers("/auth/login", "/auth/register", "/oauth2/authorization/google", "/auth/refreshToken").permitAll()
                        .anyRequest().authenticated())
                .formLogin(AbstractHttpConfigurer::disable)
                .sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2Login(oauth2 -> oauth2
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
