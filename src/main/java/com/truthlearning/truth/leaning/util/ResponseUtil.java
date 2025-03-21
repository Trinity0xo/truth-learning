package com.truthlearning.truth.leaning.util;

import com.truthlearning.truth.leaning.domain.response.RestApiResponse;

public class ResponseUtil {
    public static <T> RestApiResponse<T> success(T data, String message, int httpStatus) {
        RestApiResponse<T> response = new RestApiResponse<>();
        response.setStatusCode(httpStatus);
        response.setSuccess(true);
        response.setMessage(message);
        response.setData(data);
        return response;
    }

    public static <T> RestApiResponse<T> error(String errorMessage, String message, int httpStatus) {
        RestApiResponse<T> response = new RestApiResponse<>();
        response.setStatusCode(httpStatus);
        response.setSuccess(false);
        response.setMessage(message);
        response.setError(errorMessage);
        return response;
    }
}
