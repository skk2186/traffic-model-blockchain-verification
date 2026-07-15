package com.traffic.wecross.crossverification.zkp;

import com.fasterxml.jackson.databind.node.ObjectNode;

public class ZokratesNormalizedProof {
    private final ObjectNode document;
    private final String scheme;
    private final String curve;

    public ZokratesNormalizedProof(ObjectNode document, String scheme, String curve) {
        this.document = document;
        this.scheme = scheme;
        this.curve = curve;
    }

    public ObjectNode getDocument() {
        return document;
    }

    public String getScheme() {
        return scheme;
    }

    public String getCurve() {
        return curve;
    }
}
