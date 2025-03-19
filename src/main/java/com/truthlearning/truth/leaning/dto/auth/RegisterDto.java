package com.truthlearning.truth.leaning.dto.auth;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegisterDto extends LoginDto {
    private String firstName;
    private String lastName;
}
