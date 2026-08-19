package com.traffic.wecross.crossverification.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CrossChainSelectionValidatorTest {
    @Test
    void acceptsEveryDirectedPairAcrossTheThreeChains() {
        String[] chains = {"bcos3", "fabric", "chainmaker"};
        for (String source : chains) {
            for (String verification : chains) {
                if (!source.equals(verification)) {
                    assertDoesNotThrow(
                            () -> CrossChainSelectionValidator.validate(source, verification));
                }
            }
        }
    }

    @Test
    void rejectsSameChainAndUnsupportedChain() {
        assertThrows(
                IllegalArgumentException.class,
                () -> CrossChainSelectionValidator.validate("chainmaker", "chainmaker"));
        assertThrows(
                IllegalArgumentException.class,
                () -> CrossChainSelectionValidator.validate("unknown", "bcos3"));
    }

    @Test
    void keepsLegacyRequestsWithoutChainSelectionCompatible() {
        assertDoesNotThrow(() -> CrossChainSelectionValidator.validate(null, null));
    }
}
