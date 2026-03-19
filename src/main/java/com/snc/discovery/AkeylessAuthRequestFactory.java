package com.snc.discovery;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

final class AkeylessAuthRequestFactory {

    Map<String, Object> buildAuthRequest(ResolverConfig.AuthConfig config) throws Exception {
        String accessType = normalizeAccessType(config.getAccessType());
        Map<String, Object> authReq = new HashMap<>();
        authReq.put("access-type", accessType);
        authReq.put("access-id", must(
            config.getAccessId(),
            "Missing Akeyless access id: set MID 'ext.cred.akeyless.access_id' or env 'AKEYLESS_ACCESS_ID'"
        ));

        switch (accessType) {
            case "access_key":
                authReq.put("access-key", must(
                    config.getAccessKey(),
                    "Missing Akeyless access key: set MID 'ext.cred.akeyless.access_key' or env 'AKEYLESS_ACCESS_KEY'"
                ));
                break;
            case "aws_iam":
            case "azure_ad":
            case "gcp":
                break;
            case "universal_identity":
                authReq.put("uid-token", must(
                    config.getUidToken(),
                    "Missing Akeyless UID token: set MID 'ext.cred.akeyless.uid_token' or env 'AKEYLESS_UID_TOKEN'"
                ));
                break;
            case "cert":
                authReq.put("cert-data", resolveAuthMaterial(
                    config.getCertData(),
                    config.getCertFileName(),
                    "certificate",
                    "ext.cred.akeyless.cert_data",
                    "AKEYLESS_CERT_DATA",
                    "ext.cred.akeyless.cert_file_name",
                    "AKEYLESS_CERT_FILE_NAME"
                ));
                authReq.put("key-data", resolveAuthMaterial(
                    config.getKeyData(),
                    config.getKeyFileName(),
                    "private key",
                    "ext.cred.akeyless.key_data",
                    "AKEYLESS_KEY_DATA",
                    "ext.cred.akeyless.key_file_name",
                    "AKEYLESS_KEY_FILE_NAME"
                ));
                break;
            default:
                throw new IllegalArgumentException(
                    "Unsupported access type '" + accessType + "'. Supported: access_key, aws_iam, azure_ad, gcp, universal_identity (or uid), cert (or certificate)"
                );
        }
        return authReq;
    }

    boolean isCloudIdType(String type) {
        String t = normalizeAccessType(type);
        return "aws_iam".equals(t) || "azure_ad".equals(t) || "gcp".equals(t);
    }

    String normalizeAccessType(String type) {
        if (type == null) {
            return null;
        }
        String t = type.trim().toLowerCase();
        if ("uid".equals(t)) {
            return "universal_identity";
        }
        if ("certificate".equals(t)) {
            return "cert";
        }
        return t;
    }

    private String resolveAuthMaterial(
        String inlineData,
        String fileName,
        String label,
        String inlineProp,
        String inlineEnv,
        String fileProp,
        String fileEnv
    ) throws Exception {
        if (inlineData != null && !inlineData.trim().isEmpty()) {
            return normalizeAuthMaterial(inlineData);
        }
        if (fileName != null && !fileName.trim().isEmpty()) {
            byte[] bytes = Files.readAllBytes(Paths.get(fileName.trim()));
            return Base64.getEncoder().encodeToString(bytes);
        }
        throw new IllegalArgumentException(
            "Missing Akeyless " + label + ": set MID '" + inlineProp + "' or '" + fileProp + "', or env '" + inlineEnv + "' or '" + fileEnv + "'"
        );
    }

    private String normalizeAuthMaterial(String value) {
        String trimmed = value.trim();
        if (trimmed.startsWith("-----BEGIN")) {
            return Base64.getEncoder().encodeToString(trimmed.getBytes(StandardCharsets.UTF_8));
        }
        return trimmed;
    }

    private static String must(String val, String msg) {
        if (val == null || val.isEmpty()) {
            throw new IllegalArgumentException(msg);
        }
        return val;
    }
}

