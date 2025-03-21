package com.truthlearning.truth.leaning.controller;

import com.truthlearning.truth.leaning.domain.response.RestApiResponse;
import com.truthlearning.truth.leaning.util.ResponseUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {
    @GetMapping("/test")
    public ResponseEntity<RestApiResponse<Void>> test(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();
        RestApiResponse<Void> response = ResponseUtil.success(null, "success", HttpStatus.OK.value());
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }
}
