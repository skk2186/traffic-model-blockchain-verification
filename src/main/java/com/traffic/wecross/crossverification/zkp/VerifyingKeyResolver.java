package com.traffic.wecross.crossverification.zkp;

import com.traffic.wecross.crossverification.config.ZkpVerificationProperties;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Pattern;

@Component
public class VerifyingKeyResolver {
    private static final Pattern SAFE_KEY_ID = Pattern.compile("^[A-Za-z0-9._-]+$");
    private static final String VERIFICATION_KEY_FILE = "verification.key";

    private final ZkpVerificationProperties properties;

    public VerifyingKeyResolver(ZkpVerificationProperties properties) {
        this.properties = properties;
    }

    public Path resolve(String verifyingKeyId) {
        validateKeyId(verifyingKeyId);
        try {
            Path root = Paths.get(properties.getKeyRoot()).toAbsolutePath().normalize().toRealPath();
            Path candidate = root.resolve(verifyingKeyId).resolve(VERIFICATION_KEY_FILE).normalize();
            if (!candidate.startsWith(root)) {
                throw new IllegalArgumentException("verifyingKeyId resolves outside the configured key root");
            }
            if (!Files.isRegularFile(candidate)) {
                throw new IllegalArgumentException("verification key does not exist: " + verifyingKeyId);
            }
            Path realCandidate = candidate.toRealPath();
            if (!realCandidate.startsWith(root)) {
                throw new IllegalArgumentException("verification key resolves outside the configured key root");
            }
            return realCandidate;
        } catch (IOException e) {
            throw new IllegalArgumentException("unable to resolve verification key: " + verifyingKeyId, e);
        }
    }

    public void validateKeyId(String verifyingKeyId) {
        if (verifyingKeyId == null || verifyingKeyId.trim().isEmpty()) {
            throw new IllegalArgumentException("verifyingKeyId must not be empty");
        }
        if (!verifyingKeyId.equals(verifyingKeyId.trim())) {
            throw new IllegalArgumentException("verifyingKeyId must not contain surrounding whitespace");
        }
        if (verifyingKeyId.contains("..") || !SAFE_KEY_ID.matcher(verifyingKeyId).matches()) {
            throw new IllegalArgumentException(
                    "verifyingKeyId may contain only letters, digits, dots, underscores and hyphens, without '..'");
        }
        if (Paths.get(verifyingKeyId).isAbsolute()
                || verifyingKeyId.indexOf('/') >= 0
                || verifyingKeyId.indexOf('\\') >= 0) {
            throw new IllegalArgumentException("verifyingKeyId must be a simple identifier, not a path");
        }
    }
}
