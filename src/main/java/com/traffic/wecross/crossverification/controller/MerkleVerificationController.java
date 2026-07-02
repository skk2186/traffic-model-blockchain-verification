package com.traffic.wecross.crossverification.controller;

import com.traffic.wecross.crossverification.dto.MerkleVerifyRequest;
import com.traffic.wecross.crossverification.dto.VerificationResult;
import com.traffic.wecross.crossverification.service.MerkleVerificationService;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@CrossOrigin
@RequestMapping("/api/cross-verification/merkle")
public class MerkleVerificationController {
    private final MerkleVerificationService merkleVerificationService;

    public MerkleVerificationController(MerkleVerificationService merkleVerificationService) {
        this.merkleVerificationService = merkleVerificationService;
    }

    @PostMapping("/verify")
    public VerificationResult verify(@RequestBody MerkleVerifyRequest request) {
        return merkleVerificationService.verify(request);
    }
}
