package com.traffic.wecross.crossverification.threshold;

import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class PemPublicKeyParser {
    private static final String BEGIN = "-----BEGIN PUBLIC KEY-----";
    private static final String END = "-----END PUBLIC KEY-----";

    public PublicKey parse(String pem) {
        if (pem == null || pem.trim().isEmpty()) {
            throw new IllegalArgumentException("public key PEM must not be empty");
        }
        String normalized = pem.replace("\r", "").trim();
        if (!normalized.startsWith(BEGIN) || !normalized.endsWith(END)) {
            throw new IllegalArgumentException("public key must be X.509 SubjectPublicKeyInfo PEM");
        }
        String body = normalized
                .replace(BEGIN, "")
                .replace(END, "")
                .replaceAll("\\s", "");
        try {
            byte[] der = Base64.getDecoder().decode(body);
            PublicKey publicKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
            if (!(publicKey instanceof ECPublicKey)) {
                throw new IllegalArgumentException("public key must be an EC P-256 key");
            }
            if (!isP256(((ECPublicKey) publicKey).getParams())) {
                throw new IllegalArgumentException("public key must use P-256");
            }
            return publicKey;
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("public key PEM could not be parsed", e);
        }
    }

    private boolean isP256(ECParameterSpec candidate) throws Exception {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec p256 = parameters.getParameterSpec(ECParameterSpec.class);
        return candidate.getCofactor() == p256.getCofactor()
                && candidate.getOrder().equals(p256.getOrder())
                && candidate.getCurve().equals(p256.getCurve())
                && candidate.getGenerator().equals(p256.getGenerator());
    }
}
