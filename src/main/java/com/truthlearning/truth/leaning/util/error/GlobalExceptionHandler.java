package com.truthlearning.truth.leaning.util.error;

import com.truthlearning.truth.leaning.domain.response.RestApiResponse;
import com.truthlearning.truth.leaning.util.ResponseUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import javax.naming.AuthenticationException;

@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(
            value = {RuntimeException.class,}
    )
    public ResponseEntity<RestApiResponse<Object>> handleNoResourceFoundException(Exception exception) {
        RestApiResponse<Object> errorResponse
                = ResponseUtil.error(exception.getMessage(), "Exception occurs...", HttpStatus.INTERNAL_SERVER_ERROR.value());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
    }

    @ExceptionHandler(
            value = {
                    UnAuthorizedException.class
            }
    )
    public ResponseEntity<RestApiResponse<Object>> handleUnAuthorizedException(Exception exception) {
        RestApiResponse<Object> errorResponse
                = ResponseUtil.error(exception.getMessage(), "Unauthorized...", HttpStatus.UNAUTHORIZED.value());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
    }

    @ExceptionHandler(
            value = {
                   ConflictException.class
            }
    )
    public ResponseEntity<RestApiResponse<Object>> handleConflictException(Exception exception) {
        RestApiResponse<Object> errorResponse
                = ResponseUtil.error(exception.getMessage(), "Conflict...", HttpStatus.CONFLICT.value());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(errorResponse);
    }

    @ExceptionHandler(
            value = {
                    BadRequestException.class
            }
    )
    public ResponseEntity<RestApiResponse<Object>> handleBadRequestException(Exception exception) {
        RestApiResponse<Object> errorResponse
                = ResponseUtil.error(exception.getMessage(), "Bad request...", HttpStatus.BAD_REQUEST.value());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
    }
}
