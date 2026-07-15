package com.traffic.wecross.crossverification.config;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "verification.threshold-signature")
public class ThresholdSignatureVerificationProperties implements InitializingBean {
    public enum Mode {
        REAL,
        MOCK
    }

    private Mode mode = Mode.REAL;
    private boolean allowLegacyMock;

    @Override
    public void afterPropertiesSet() {
        if (mode == null) {
            throw new IllegalArgumentException("verification.threshold-signature.mode must be real or mock");
        }
        if (mode == Mode.REAL && allowLegacyMock) {
            throw new IllegalArgumentException(
                    "verification.threshold-signature.allow-legacy-mock must be false when mode is real");
        }
    }

    public Mode getMode() {
        return mode;
    }

    public void setMode(Mode mode) {
        this.mode = mode;
    }

    public boolean isAllowLegacyMock() {
        return allowLegacyMock;
    }

    public void setAllowLegacyMock(boolean allowLegacyMock) {
        this.allowLegacyMock = allowLegacyMock;
    }
}
