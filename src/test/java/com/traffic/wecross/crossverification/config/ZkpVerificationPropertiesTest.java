package com.traffic.wecross.crossverification.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ZkpVerificationPropertiesTest {
    @Test
    void bindsAllConfigurationFields() throws Exception {
        Map<String, Object> values = new HashMap<>();
        values.put("verification.zkp.mode", "mock");
        values.put("verification.zkp.allow-legacy-mock", "true");
        values.put("verification.zkp.zokrates-executable", "tools/zokrates.exe");
        values.put("verification.zkp.key-root", "keys/root");
        values.put("verification.zkp.temp-root", "temp/root");
        values.put("verification.zkp.timeout-millis", "1234");
        values.put("verification.zkp.max-output-bytes", "2048");

        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("test", values));
        ZkpVerificationProperties properties = new ZkpVerificationProperties();
        Binder.get(environment).bind("verification.zkp", Bindable.ofInstance(properties));
        properties.afterPropertiesSet();

        assertEquals(ZkpVerificationProperties.Mode.MOCK, properties.getMode());
        assertTrue(properties.isAllowLegacyMock());
        assertEquals("tools/zokrates.exe", properties.getZokratesExecutable());
        assertEquals("keys/root", properties.getKeyRoot());
        assertEquals("temp/root", properties.getTempRoot());
        assertEquals(1234L, properties.getTimeoutMillis());
        assertEquals(2048, properties.getMaxOutputBytes());
    }

    @Test
    void defaultsToRealWithoutLegacyFallback() throws Exception {
        ZkpVerificationProperties properties = new ZkpVerificationProperties();
        properties.afterPropertiesSet();

        assertEquals(ZkpVerificationProperties.Mode.REAL, properties.getMode());
        assertFalse(properties.isAllowLegacyMock());
        assertEquals(
                "E:/\u6842\u7535/\u533A\u5757\u94FE/\u591A\u6A21\u6001\u4EA4\u901A\u5927\u6A21\u578B/ZoKrates/target/release/zokrates.exe",
                properties.getZokratesExecutable());
    }

    @Test
    void rejectsLegacyFallbackInRealMode() {
        ZkpVerificationProperties properties = new ZkpVerificationProperties();
        properties.setMode(ZkpVerificationProperties.Mode.REAL);
        properties.setAllowLegacyMock(true);

        assertThrows(IllegalArgumentException.class, properties::afterPropertiesSet);
    }

    @Test
    void rejectsNonPositiveLimits() {
        ZkpVerificationProperties properties = new ZkpVerificationProperties();
        properties.setTimeoutMillis(0);
        assertThrows(IllegalArgumentException.class, properties::afterPropertiesSet);

        properties.setTimeoutMillis(1);
        properties.setMaxOutputBytes(0);
        assertThrows(IllegalArgumentException.class, properties::afterPropertiesSet);
    }
}
