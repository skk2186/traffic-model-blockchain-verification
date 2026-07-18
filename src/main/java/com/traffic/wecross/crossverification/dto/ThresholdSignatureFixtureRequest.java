package com.traffic.wecross.crossverification.dto;

import java.util.List;

public class ThresholdSignatureFixtureRequest {
    public String businessId;
    public String message;
    public Integer threshold;
    public Integer totalNodes;
    public List<Integer> participantIds;
}
