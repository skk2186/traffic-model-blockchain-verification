package com.traffic.wecross.crossverification.dto;

import java.util.List;

public class MerkleVerifyRequest extends BaseVerifyRequest {
    public String dataSourceName;
    public List<String> leafItems;
    public String expectedRoot;
    public Integer sampleIndex;
}
