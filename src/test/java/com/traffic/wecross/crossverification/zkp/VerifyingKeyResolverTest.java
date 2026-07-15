package com.traffic.wecross.crossverification.zkp;

import com.traffic.wecross.crossverification.config.ZkpVerificationProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class VerifyingKeyResolverTest {
    @TempDir
    Path tempDirectory;

    @Test
    void resolvesARegularKeyInsideTheConfiguredRoot() throws Exception {
        Path keyRoot = Files.createDirectories(tempDirectory.resolve("keys"));
        Path keyDirectory = Files.createDirectories(keyRoot.resolve("traffic-speed-range-v1"));
        Path expected = keyDirectory.resolve("verification.key");
        Files.write(expected, "public-key".getBytes(StandardCharsets.UTF_8));

        VerifyingKeyResolver resolver = resolver(keyRoot);

        assertEquals(expected.toRealPath(), resolver.resolve("traffic-speed-range-v1"));
    }

    @Test
    void acceptsOnlySimpleSafeIdentifiers() throws Exception {
        Path keyRoot = Files.createDirectories(tempDirectory.resolve("keys"));
        VerifyingKeyResolver resolver = resolver(keyRoot);

        resolver.validateKeyId("circuit.v1_key-01");
        String[] invalidIds = {
                null,
                "",
                " ",
                "../outside",
                "..",
                "a..b",
                "a/b",
                "a\\b",
                "/absolute",
                "C:\\absolute",
                " leading",
                "trailing ",
                "id:variant"
        };
        for (String invalidId : invalidIds) {
            assertThrows(IllegalArgumentException.class, () -> resolver.validateKeyId(invalidId), invalidId);
        }
    }

    @Test
    void rejectsMissingKeysInsteadOfEscapingTheRoot() throws Exception {
        Path keyRoot = Files.createDirectories(tempDirectory.resolve("keys"));
        VerifyingKeyResolver resolver = resolver(keyRoot);

        assertThrows(IllegalArgumentException.class, () -> resolver.resolve("missing-key"));
        assertThrows(IllegalArgumentException.class, () -> resolver.resolve("../outside"));
    }

    private VerifyingKeyResolver resolver(Path keyRoot) {
        ZkpVerificationProperties properties = new ZkpVerificationProperties();
        properties.setKeyRoot(keyRoot.toString());
        return new VerifyingKeyResolver(properties);
    }
}
