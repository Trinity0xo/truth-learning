package com.truthlearning.truth.leaning.configuraion;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.truthlearning.truth.leaning.domain.response.RestApiResponse;
import com.truthlearning.truth.leaning.util.ResponseUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        RestApiResponse<Object> restApiResponse = ResponseUtil.error(
                "Unauthorized: RefreshToken is missing or invalid",
                authException.getMessage(),
                HttpStatus.UNAUTHORIZED.value()
        );

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        ObjectMapper objectMapper = new ObjectMapper();
        String jsonResponse = objectMapper.writeValueAsString(restApiResponse);

        response.getWriter().write(jsonResponse);
    }
}
