package com.traffic.wecross.crossverification.util;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class ValidationUtils {
    private ValidationUtils() {
    }

    public static void requireText(String value, String fieldName) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(fieldName + " must not be empty");
        }
    }

    public static void requireNotEmpty(List<?> value, String fieldName) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException(fieldName + " must not be empty");
        }
    }

    public static void requireSha256HexIfPresent(String value, String fieldName) {
        if (value != null && !value.trim().isEmpty() && !HashUtils.isSha256Hex(value.trim())) {
            throw new IllegalArgumentException(fieldName + " must be a 64-character hex string");
        }
    }

    public static void requireIndexInRange(Integer index, int size, String fieldName) {
        if (index != null && (index < 0 || index >= size)) {
            throw new IllegalArgumentException(fieldName + " must be between 0 and " + (size - 1));
        }
    }

    public static void validateThresholdParticipants(
            Integer threshold,
            Integer totalNodes,
            List<Integer> participantIds) {
        if (threshold == null || threshold <= 0) {
            throw new IllegalArgumentException("threshold must be greater than 0");
        }
        if (totalNodes == null || totalNodes <= 0) {
            throw new IllegalArgumentException("totalNodes must be greater than 0");
        }
        if (threshold > totalNodes) {
            throw new IllegalArgumentException("threshold must be less than or equal to totalNodes");
        }
        requireNotEmpty(participantIds, "participantIds");
        if (participantIds.size() < threshold) {
            throw new IllegalArgumentException("participantIds size must be greater than or equal to threshold");
        }
        Set<Integer> seen = new HashSet<>();
        for (Integer participantId : participantIds) {
            if (participantId == null || participantId < 1 || participantId > totalNodes) {
                throw new IllegalArgumentException("participantId must be between 1 and totalNodes");
            }
            if (!seen.add(participantId)) {
                throw new IllegalArgumentException("participantIds must not contain duplicate values");
            }
        }
    }
}
