package com.traffic.wecross.crossverification;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = "com.traffic.wecross")
public class CrossVerificationApplication {
    public static void main(String[] args) {
        SpringApplication.run(CrossVerificationApplication.class, args);
    }
}
