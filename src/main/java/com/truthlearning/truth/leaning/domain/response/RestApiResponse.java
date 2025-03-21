package com.truthlearning.truth.leaning.domain.response;

import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;

@Getter
@Setter
public class RestApiResponse<T> {
    private boolean success;
    private int statusCode;
    private String message;
    private String error;
    private T data;
}
