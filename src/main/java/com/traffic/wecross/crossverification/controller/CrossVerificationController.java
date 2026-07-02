package com.traffic.wecross.crossverification.controller;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@CrossOrigin
@RequestMapping("/api/cross-verification")
public class CrossVerificationController {
    @GetMapping("/health")
    public Map<String, Object> health() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "UP");
        body.put("service", "transportation-cross-verification-service");
        body.put("apiPrefix", "/api/cross-verification");
        return body;
    }
}
