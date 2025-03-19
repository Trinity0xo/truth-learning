package com.truthlearning.truth.leaning.domain.response.auth;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginResponse {
    private UserResponse user;
    private String access_token;

    @Getter
    @Setter
    public static class UserResponse{
        //    private String avatar;
        private String firstName;
        private String lastName;
        private String email;
    }
}
