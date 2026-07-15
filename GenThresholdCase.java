import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.Base64;

public class GenThresholdCase {
  static final String POLICY_ID = "traffic-consortium-dev-local";
  static final String MESSAGE = "traffic speed range approved";

  public static void main(String[] args) throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
    g.initialize(new ECGenParameterSpec("secp256r1"));

    Map<Integer, KeyPair> keys = new LinkedHashMap<>();
    for (int i = 1; i <= 5; i++) keys.put(i, g.generateKeyPair());

    Files.createDirectories(Paths.get("config/threshold"));

    StringBuilder policy = new StringBuilder();
    policy.append("{\n");
    policy.append("  \"policyId\": \"").append(POLICY_ID).append("\",\n");
    policy.append("  \"scheme\": \"ECDSA-P256-SHA256\",\n");
    policy.append("  \"threshold\": 3,\n");
    policy.append("  \"totalNodes\": 5,\n");
    policy.append("  \"publicKeys\": {\n");
    for (int i = 1; i <= 5; i++) {
      policy.append("    \"").append(i).append("\": \"").append(pem(keys.get(i))).append("\"");
      policy.append(i == 5 ? "\n" : ",\n");
    }
    policy.append("  }\n");
    policy.append("}\n");
    Files.write(Paths.get("config/threshold/" + POLICY_ID + ".json"), policy.toString().getBytes("UTF-8"));

    String s1 = sign(MESSAGE, keys.get(1));
    String s2 = sign(MESSAGE, keys.get(2));
    String s4 = sign(MESSAGE, keys.get(4));
    String bad = sign("wrong message", keys.get(3));

    String valid = request("traffic-threshold-valid", MESSAGE, "1", s1, "2", s2, "4", s4);
    String two = request2("traffic-threshold-two", MESSAGE, "1", s1, "2", s2);
    String forged = request("traffic-threshold-forged", MESSAGE, "1", s1, "2", s2, "3", bad);

    Files.write(Paths.get("threshold-valid-request.json"), valid.getBytes("UTF-8"));
    Files.write(Paths.get("threshold-two-valid-request.json"), two.getBytes("UTF-8"));
    Files.write(Paths.get("threshold-forged-request.json"), forged.getBytes("UTF-8"));
  }

  static String request(String biz, String msg, String id1, String sig1, String id2, String sig2, String id3, String sig3) {
    return "{\n" +
      "  \"businessId\":\"" + biz + "\",\n" +
      "  \"message\":\"" + msg + "\",\n" +
      "  \"threshold\":3,\n" +
      "  \"totalNodes\":5,\n" +
      "  \"participantIds\":[" + id1 + "," + id2 + "," + id3 + "],\n" +
      "  \"signatureBundle\":{\n" +
      "    \"scheme\":\"ECDSA-P256-SHA256\",\n" +
      "    \"policyId\":\"" + POLICY_ID + "\",\n" +
      "    \"participantSignatures\":{\n" +
      "      \"" + id1 + "\":\"" + sig1 + "\",\n" +
      "      \"" + id2 + "\":\"" + sig2 + "\",\n" +
      "      \"" + id3 + "\":\"" + sig3 + "\"\n" +
      "    }\n" +
      "  },\n" +
      "  \"writeLedger\":false,\n" +
      "  \"ledgerTargets\":[]\n" +
      "}\n";
  }

  static String request2(String biz, String msg, String id1, String sig1, String id2, String sig2) {
    return "{\n" +
      "  \"businessId\":\"" + biz + "\",\n" +
      "  \"message\":\"" + msg + "\",\n" +
      "  \"threshold\":3,\n" +
      "  \"totalNodes\":5,\n" +
      "  \"participantIds\":[" + id1 + "," + id2 + "],\n" +
      "  \"signatureBundle\":{\n" +
      "    \"scheme\":\"ECDSA-P256-SHA256\",\n" +
      "    \"policyId\":\"" + POLICY_ID + "\",\n" +
      "    \"participantSignatures\":{\n" +
      "      \"" + id1 + "\":\"" + sig1 + "\",\n" +
      "      \"" + id2 + "\":\"" + sig2 + "\"\n" +
      "    }\n" +
      "  },\n" +
      "  \"writeLedger\":false,\n" +
      "  \"ledgerTargets\":[]\n" +
      "}\n";
  }

  static String sign(String msg, KeyPair kp) throws Exception {
    Signature s = Signature.getInstance("SHA256withECDSA");
    s.initSign(kp.getPrivate());
    s.update(msg.getBytes("UTF-8"));
    return Base64.getEncoder().encodeToString(s.sign());
  }

  static String pem(KeyPair kp) throws Exception {
    String b = Base64.getMimeEncoder(64, "\n".getBytes("US-ASCII")).encodeToString(kp.getPublic().getEncoded());
    return ("-----BEGIN PUBLIC KEY-----\n" + b + "\n-----END PUBLIC KEY-----").replace("\n", "\\n");
  }
}
