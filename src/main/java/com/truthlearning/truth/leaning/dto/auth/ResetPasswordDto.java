package com.truthlearning.truth.leaning.dto.auth;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ResetPasswordDto extends VerifyTokenDto {
    private String newPassword;
}
