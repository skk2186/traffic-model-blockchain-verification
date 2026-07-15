package com.traffic.wecross.crossverification.threshold;

import java.security.PublicKey;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public class ThresholdSignaturePolicy {
    private final String policyId;
    private final String scheme;
    private final int threshold;
    private final int totalNodes;
    private final Map<Integer, PublicKey> publicKeys;

    public ThresholdSignaturePolicy(
            String policyId,
            String scheme,
            int threshold,
            int totalNodes,
            Map<Integer, PublicKey> publicKeys) {
        this.policyId = policyId;
        this.scheme = scheme;
        this.threshold = threshold;
        this.totalNodes = totalNodes;
        this.publicKeys = Collections.unmodifiableMap(new LinkedHashMap<>(publicKeys));
    }

    public String getPolicyId() {
        return policyId;
    }

    public String getScheme() {
        return scheme;
    }

    public int getThreshold() {
        return threshold;
    }

    public int getTotalNodes() {
        return totalNodes;
    }

    public Map<Integer, PublicKey> getPublicKeys() {
        return publicKeys;
    }

    public PublicKey getPublicKey(Integer participantId) {
        return publicKeys.get(participantId);
    }
}
