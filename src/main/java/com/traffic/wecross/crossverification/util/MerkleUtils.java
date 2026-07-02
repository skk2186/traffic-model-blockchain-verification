package com.traffic.wecross.crossverification.util;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class MerkleUtils {
    private MerkleUtils() {
    }

    public static MerkleTree buildTree(List<String> leafItems) {
        List<String> leafHashes = new ArrayList<>();
        for (String leafItem : leafItems) {
            leafHashes.add(HashUtils.hex(HashUtils.sha256((leafItem == null ? "" : leafItem).getBytes(StandardCharsets.UTF_8))));
        }

        List<List<String>> layers = new ArrayList<>();
        layers.add(leafHashes);
        List<String> current = leafHashes;
        while (current.size() > 1) {
            List<String> next = new ArrayList<>();
            for (int i = 0; i < current.size(); i += 2) {
                String left = current.get(i);
                String right = i + 1 < current.size() ? current.get(i + 1) : left;
                next.add(HashUtils.hex(HashUtils.sha256(concatHex(left, right))));
            }
            layers.add(next);
            current = next;
        }

        MerkleTree tree = new MerkleTree();
        tree.leafHashes = leafHashes;
        tree.layers = layers;
        tree.rootHash = current.get(0);
        return tree;
    }

    public static List<Map<String, Object>> proofPath(MerkleTree tree, Integer sampleIndex) {
        List<Map<String, Object>> proofPath = new ArrayList<>();
        if (sampleIndex == null) {
            return proofPath;
        }

        int index = sampleIndex;
        for (int layerIndex = 0; layerIndex < tree.layers.size() - 1; layerIndex++) {
            List<String> layer = tree.layers.get(layerIndex);
            int siblingIndex;
            String position;
            if (index % 2 == 0) {
                siblingIndex = index + 1 < layer.size() ? index + 1 : index;
                position = "RIGHT";
            } else {
                siblingIndex = index - 1;
                position = "LEFT";
            }

            Map<String, Object> node = new LinkedHashMap<>();
            node.put("layer", layerIndex);
            node.put("position", position);
            node.put("hash", layer.get(siblingIndex));
            proofPath.add(node);
            index = index / 2;
        }
        return proofPath;
    }

    private static byte[] concatHex(String leftHex, String rightHex) {
        byte[] left = fromHex(leftHex);
        byte[] right = fromHex(rightHex);
        byte[] result = new byte[left.length + right.length];
        System.arraycopy(left, 0, result, 0, left.length);
        System.arraycopy(right, 0, result, left.length, right.length);
        return result;
    }

    private static byte[] fromHex(String hex) {
        int length = hex.length();
        byte[] result = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            result[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return result;
    }

    public static class MerkleTree {
        public List<String> leafHashes;
        public List<List<String>> layers;
        public String rootHash;
    }
}
