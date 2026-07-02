package com.traffic.wecross.crossverification.controller;

import com.traffic.wecross.crossverification.dto.ThresholdSignatureVerifyRequest;
import com.traffic.wecross.crossverification.dto.VerificationResult;
import com.traffic.wecross.crossverification.service.ThresholdSignatureVerificationService;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@CrossOrigin
@RequestMapping("/api/cross-verification/threshold-signature")
public class ThresholdSignatureVerificationController {
    private final ThresholdSignatureVerificationService thresholdSignatureVerificationService;

    public ThresholdSignatureVerificationController(
            ThresholdSignatureVerificationService thresholdSignatureVerificationService) {
        this.thresholdSignatureVerificationService = thresholdSignatureVerificationService;
    }

    @PostMapping("/verify")
    public VerificationResult verify(@RequestBody ThresholdSignatureVerifyRequest request) {
        return thresholdSignatureVerificationService.verify(request);
    }
}
