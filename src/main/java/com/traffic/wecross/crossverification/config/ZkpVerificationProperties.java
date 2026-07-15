package com.traffic.wecross.crossverification.config;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "verification.zkp")
public class ZkpVerificationProperties implements InitializingBean {
    public enum Mode {
        REAL,
        MOCK
    }

    private Mode mode = Mode.REAL;
    private boolean allowLegacyMock;
    private String zokratesExecutable = "E:/\u6842\u7535/\u533A\u5757\u94FE/\u591A\u6A21\u6001\u4EA4\u901A\u5927\u6A21\u578B/ZoKrates/target/release/zokrates.exe";
    private String keyRoot = "config/zkp";
    private String tempRoot = "runtime/zkp-temp";
    private long timeoutMillis = 30000L;
    private int maxOutputBytes = 1024 * 1024;

    @Override
    public void afterPropertiesSet() {
        if (mode == null) {
            throw new IllegalArgumentException("verification.zkp.mode must be real or mock");
        }
        requireText(zokratesExecutable, "verification.zkp.zokrates-executable");
        requireText(keyRoot, "verification.zkp.key-root");
        requireText(tempRoot, "verification.zkp.temp-root");
        if (timeoutMillis <= 0) {
            throw new IllegalArgumentException("verification.zkp.timeout-millis must be greater than 0");
        }
        if (maxOutputBytes <= 0) {
            throw new IllegalArgumentException("verification.zkp.max-output-bytes must be greater than 0");
        }
        if (mode == Mode.REAL && allowLegacyMock) {
            throw new IllegalArgumentException(
                    "verification.zkp.allow-legacy-mock must be false when verification.zkp.mode is real");
        }
    }

    private void requireText(String value, String propertyName) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(propertyName + " must not be empty");
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

    public String getZokratesExecutable() {
        return zokratesExecutable;
    }

    public void setZokratesExecutable(String zokratesExecutable) {
        this.zokratesExecutable = zokratesExecutable;
    }

    public String getKeyRoot() {
        return keyRoot;
    }

    public void setKeyRoot(String keyRoot) {
        this.keyRoot = keyRoot;
    }

    public String getTempRoot() {
        return tempRoot;
    }

    public void setTempRoot(String tempRoot) {
        this.tempRoot = tempRoot;
    }

    public long getTimeoutMillis() {
        return timeoutMillis;
    }

    public void setTimeoutMillis(long timeoutMillis) {
        this.timeoutMillis = timeoutMillis;
    }

    public int getMaxOutputBytes() {
        return maxOutputBytes;
    }

    public void setMaxOutputBytes(int maxOutputBytes) {
        this.maxOutputBytes = maxOutputBytes;
    }
}
