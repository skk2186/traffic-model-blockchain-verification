package com.traffic.wecross.crossverification.util;

import com.traffic.wecross.crossverification.record.VerifyType;

import java.security.SecureRandom;

public final class VerifyIdGenerator {
    private static final SecureRandom RANDOM = new SecureRandom();

    private VerifyIdGenerator() {
    }

    public static String nextId(VerifyType verifyType) {
        long timestamp = System.currentTimeMillis();
        int suffix = 100000 + RANDOM.nextInt(900000);
        return verifyType.name() + "-" + timestamp + "-" + suffix;
    }
}
