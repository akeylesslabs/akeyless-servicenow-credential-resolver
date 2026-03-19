package com.snc.discovery;

import com.fasterxml.jackson.jr.ob.JSON;

import java.util.HashMap;
import java.util.Map;

final class ServiceNowCredentialMapper {
    private static final JSON JSON_STD = JSON.std;

    Map<String, String> mapToServiceNow(String snType, String raw, ResolverConfig.MappingConfig mappingConfig) throws Exception {
        Map<String, String> out = new HashMap<>();
        if (raw == null || raw.isEmpty()) {
            return out;
        }

        Object parsed = tryParseJson(raw);
        if (!(parsed instanceof Map)) {
            out.put("password", raw);
            return out;
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> node = (Map<String, Object>) parsed;
        String type = snType.toLowerCase();

        switch (type) {
            case "windows":
            case "basic":
            case "ssh_password":
            case "vmware":
            case "jdbc":
            case "jms":
                putIf(out, "username", node, mappingConfig.getUsernameField());
                putIf(out, "password", node, mappingConfig.getPasswordField());
                break;
            case "ssh_private_key":
                putIf(out, "username", node, mappingConfig.getUsernameField());
                putIf(out, "private_key", node, mappingConfig.getPrivateKeyField());
                putIf(out, "passphrase", node, mappingConfig.getPassphraseField());
                break;
            case "snmpv3":
                putIf(out, "username", node, mappingConfig.getUsernameField());
                putIf(out, "auth-protocol", node, "auth_protocol");
                putIf(out, "auth-key", node, "auth_key");
                putIf(out, "privacy-protocol", node, "privacy_protocol");
                putIf(out, "privacy-key", node, "privacy_key");
                break;
            default:
                putIf(out, "username", node, mappingConfig.getUsernameField());
                putIf(out, "password", node, mappingConfig.getPasswordField());
        }
        return out;
    }

    private static void putIf(Map<String, String> out, String snField, Map<String, Object> node, String jsonField) {
        Object v = node.get(jsonField);
        if (v != null) {
            out.put(snField, asString(v));
        }
    }

    private static Object tryParseJson(String raw) {
        try {
            return JSON_STD.anyFrom(raw);
        } catch (Exception ignore) {
            return null;
        }
    }

    private static String asString(Object v) {
        if (v == null) {
            return null;
        }
        if (v instanceof String) {
            return (String) v;
        }
        if (v instanceof Number || v instanceof Boolean) {
            return String.valueOf(v);
        }
        try {
            return JSON_STD.asString(v);
        } catch (Exception e) {
            return String.valueOf(v);
        }
    }
}

