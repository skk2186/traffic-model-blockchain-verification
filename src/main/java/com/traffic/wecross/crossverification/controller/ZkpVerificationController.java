package com.traffic.wecross.crossverification.controller;

import com.traffic.wecross.crossverification.dto.VerificationResult;
import com.traffic.wecross.crossverification.dto.ZkpVerifyRequest;
import com.traffic.wecross.crossverification.service.ZkpVerificationService;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@CrossOrigin
@RequestMapping("/api/cross-verification/zkp")
public class ZkpVerificationController {
    private final ZkpVerificationService zkpVerificationService;

    public ZkpVerificationController(ZkpVerificationService zkpVerificationService) {
        this.zkpVerificationService = zkpVerificationService;
    }

    @PostMapping("/verify")
    public VerificationResult verify(@RequestBody ZkpVerifyRequest request) {
        return zkpVerificationService.verify(request);
    }
}
