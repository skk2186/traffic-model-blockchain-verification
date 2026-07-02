package com.traffic.wecross.crossverification.util;

import com.traffic.wecross.crossverification.dto.VerificationResult;

import java.util.Map;

public final class ErrorResultFactory {
    private ErrorResultFactory() {
    }

    public static VerificationResult error(String verifyType, String recordId, String message, String errorCode) {
        VerificationResult result = new VerificationResult();
        result.recordId = recordId;
        result.verifyType = verifyType;
        result.status = "ERROR";
        result.message = message;
        result.detail = detail(errorCode, message);
        result.timestamp = System.currentTimeMillis();
        return result;
    }

    public static Map<String, Object> detail(String errorCode, String errorMessage) {
        Map<String, Object> detail = JsonUtils.detail();
        detail.put("errorCode", errorCode);
        detail.put("errorMessage", errorMessage);
        return detail;
    }
}
