package com.traffic.wecross.crossverification.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public final class VerificationHashUtils {
    private VerificationHashUtils() {
    }

    public static String sha256Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest((value == null ? "" : value).getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder(hashed.length * 2);
            for (byte b : hashed) {
                builder.append(String.format("%02x", b));
            }
            return builder.toString();
        } catch (Exception e) {
            throw new IllegalStateException("Unable to calculate verification hash", e);
        }
    }
}
