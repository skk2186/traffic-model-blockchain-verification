package com.traffic.wecross.crossverification.util;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public final class JsonUtils {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private JsonUtils() {
    }

    public static String toJson(Object value) {
        try {
            return OBJECT_MAPPER.writeValueAsString(value);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to serialize verification object", e);
        }
    }

    public static <T> T fromJson(String json, Class<T> valueType) {
        if (json == null || json.trim().isEmpty()) {
            return null;
        }
        try {
            return OBJECT_MAPPER.readValue(json, valueType);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to deserialize verification object", e);
        }
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> mapFromJson(String json) {
        if (json == null || json.trim().isEmpty()) {
            return Collections.emptyMap();
        }
        try {
            return OBJECT_MAPPER.readValue(json, LinkedHashMap.class);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to deserialize verification detail", e);
        }
    }

    public static Map<String, Object> detail() {
        return new LinkedHashMap<>();
    }
}
