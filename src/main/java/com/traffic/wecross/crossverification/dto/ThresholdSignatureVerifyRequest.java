package com.traffic.wecross.crossverification.dto;

import java.util.List;
import java.util.Map;

public class ThresholdSignatureVerifyRequest extends BaseVerifyRequest {
    public String message;
    public Integer threshold;
    public Integer totalNodes;
    public List<Integer> participantIds;
    public Map<String, Object> signatureBundle;
}
