package com.traffic.wecross.crossverification.controller;

import com.traffic.wecross.crossverification.dto.ThresholdSignatureFixtureRequest;
import com.traffic.wecross.crossverification.service.DynamicFrostFixtureService;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@CrossOrigin
@RequestMapping("/api/cross-verification/threshold-signature")
public class ThresholdSignatureFixtureController {
    private final DynamicFrostFixtureService fixtureService;

    public ThresholdSignatureFixtureController(DynamicFrostFixtureService fixtureService) {
        this.fixtureService = fixtureService;
    }

    @PostMapping("/generate-test-fixture")
    public Map<String, Object> generateTestFixture(
            @RequestBody ThresholdSignatureFixtureRequest request) {
        return fixtureService.generate(request);
    }
}
