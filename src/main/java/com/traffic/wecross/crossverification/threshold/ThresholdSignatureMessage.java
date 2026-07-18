package com.traffic.wecross.crossverification.threshold;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class ThresholdSignatureMessage {
    private static final byte[] DOMAIN =
            "WECROSS-FROST-ED25519-V1".getBytes(StandardCharsets.US_ASCII);

    private ThresholdSignatureMessage() {
    }

    public static byte[] encode(
            String policyId,
            String businessId,
            int threshold,
            int totalNodes,
            List<Integer> participantIds,
            String message) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream output = new DataOutputStream(bytes);
            writeBytes(output, DOMAIN);
            writeText(output, policyId);
            writeText(output, businessId);
            output.writeInt(threshold);
            output.writeInt(totalNodes);
            List<Integer> normalizedParticipants = new ArrayList<>(participantIds);
            Collections.sort(normalizedParticipants);
            output.writeInt(normalizedParticipants.size());
            for (Integer participantId : normalizedParticipants) {
                output.writeInt(participantId);
            }
            writeText(output, message);
            output.flush();
            return bytes.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("threshold signature payload could not be encoded", e);
        }
    }

    private static void writeText(DataOutputStream output, String value) throws IOException {
        writeBytes(output, value.getBytes(StandardCharsets.UTF_8));
    }

    private static void writeBytes(DataOutputStream output, byte[] value) throws IOException {
        output.writeInt(value.length);
        output.write(value);
    }
}
