package com.traffic.wecross.crossverification.util;

public final class CrossChainSelectionValidator {
    private CrossChainSelectionValidator() {}

    public static void validate(String sourceChain, String verificationChain) {
        if (sourceChain == null && verificationChain == null) {
            return;
        }
        ValidationUtils.requireText(sourceChain, "sourceChain");
        ValidationUtils.requireText(verificationChain, "verificationChain");
        if (!isSupported(sourceChain) || !isSupported(verificationChain)) {
            throw new IllegalArgumentException(
                    "sourceChain and verificationChain must be bcos3, fabric or chainmaker");
        }
        if (sourceChain.equals(verificationChain)) {
            throw new IllegalArgumentException(
                    "sourceChain and verificationChain must be different");
        }
    }

    private static boolean isSupported(String chain) {
        return "bcos3".equals(chain)
                || "fabric".equals(chain)
                || "chainmaker".equals(chain);
    }
}
