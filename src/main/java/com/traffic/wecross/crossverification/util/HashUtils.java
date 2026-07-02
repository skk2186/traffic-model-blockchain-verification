package com.traffic.wecross.crossverification.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public final class HashUtils {
    private HashUtils() {
    }

    public static byte[] sha256(byte[] value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(value == null ? new byte[0] : value);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to calculate verification hash", e);
        }
    }

    public static String sha256Hex(String value) {
        return hex(sha256((value == null ? "" : value).getBytes(StandardCharsets.UTF_8)));
    }

    public static String hex(byte[] value) {
        StringBuilder builder = new StringBuilder(value.length * 2);
        for (byte b : value) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }

    public static boolean isSha256Hex(String value) {
        return value != null && value.matches("^[0-9a-fA-F]{64}$");
    }

    public static String merkleRootHex(Iterable<String> leafItems) {
        java.util.List<byte[]> level = new java.util.ArrayList<>();
        for (String leafItem : leafItems) {
            level.add(sha256((leafItem == null ? "" : leafItem).getBytes(StandardCharsets.UTF_8)));
        }
        while (level.size() > 1) {
            java.util.List<byte[]> next = new java.util.ArrayList<>();
            for (int i = 0; i < level.size(); i += 2) {
                byte[] left = level.get(i);
                byte[] right = i + 1 < level.size() ? level.get(i + 1) : left;
                next.add(sha256(concat(left, right)));
            }
            level = next;
        }
        return hex(level.get(0));
    }

    private static byte[] concat(byte[] left, byte[] right) {
        byte[] result = new byte[left.length + right.length];
        System.arraycopy(left, 0, result, 0, left.length);
        System.arraycopy(right, 0, result, left.length, right.length);
        return result;
    }
}
