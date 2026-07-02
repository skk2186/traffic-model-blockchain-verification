package com.traffic.wecross.crossverification.controller;

import com.traffic.wecross.crossverification.dto.VerificationResult;
import com.traffic.wecross.crossverification.util.ErrorResultFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice(basePackages = "com.traffic.wecross.crossverification.controller")
public class GlobalExceptionHandler {
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<VerificationResult> handleIllegalArgument(IllegalArgumentException e) {
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(ErrorResultFactory.error(null, null, messageOf(e), "PARAMETER_ERROR"));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<VerificationResult> handleMessageNotReadable(HttpMessageNotReadableException e) {
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(ErrorResultFactory.error(null, null, messageOf(e), "REQUEST_BODY_ERROR"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<VerificationResult> handleException(Exception e) {
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ErrorResultFactory.error(null, null, "内部执行异常：" + messageOf(e), "INTERNAL_ERROR"));
    }

    private String messageOf(Exception e) {
        return e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
    }
}
