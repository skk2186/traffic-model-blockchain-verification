package com.traffic.wecross.api;

import java.util.List;

public class VerificationRequests {
    public static class BaseRequest {
        public String businessId;
        public List<String> dataBlocks;
        public Integer sampleIndex;
        public List<String> targetChains;
        public Boolean writeOnChain;
    }

    public static class MerkleRequest extends BaseRequest {
    }

    public static class Groth16Request extends BaseRequest {
        public String merkleRoot;
    }

    public static class ThresholdSignatureRequest extends BaseRequest {
        public String merkleRoot;
        public Integer totalNodes;
        public Integer threshold;
        public List<Integer> participantIds;
    }
}
