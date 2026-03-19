package com.snc.discovery;

import com.fasterxml.jackson.jr.ob.JSON;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

final class AkeylessGatewayClient {
    interface CloudIdSupplier {
        String getCloudId(String accessType) throws Exception;
    }

    private static final JSON JSON_STD = JSON.std;
    private final AkeylessHttpTransport transport;
    private final AkeylessAuthRequestFactory authFactory;
    private final CloudIdSupplier cloudIdSupplier;

    AkeylessGatewayClient(
        AkeylessHttpTransport transport,
        AkeylessAuthRequestFactory authFactory,
        CloudIdSupplier cloudIdSupplier
    ) {
        this.transport = transport;
        this.authFactory = authFactory;
        this.cloudIdSupplier = cloudIdSupplier;
    }

    String getSecretValue(String secretPath, ResolverConfig.AuthConfig config) throws Exception {
        Map<String, Object> authReq = authFactory.buildAuthRequest(config);
        String accessType = (String) authReq.get("access-type");
        if (authFactory.isCloudIdType(accessType)) {
            authReq.put("cloud-id", cloudIdSupplier.getCloudId(accessType));
        }
        authReq.put("json", true);

        Map<String, Object> authResp = postWithLegacyFallback(config.getGatewayUrl(), "/auth", authReq);
        String token = asString(authResp.get("token"));
        if (token == null || token.isEmpty()) {
            throw new AkeylessCredentialResolverException("Akeyless auth returned empty token");
        }

        Map<String, Object> gsvReq = new HashMap<>();
        gsvReq.put("token", token);
        gsvReq.put("name", secretPath);
        gsvReq.put("names", Collections.singletonList(secretPath));
        gsvReq.put("json", true);

        Map<String, Object> gsvResp = postWithLegacyFallback(config.getGatewayUrl(), "/get-secret-value", gsvReq);
        Object secretsObj = gsvResp.containsKey("secrets") ? gsvResp.get("secrets") : gsvResp;
        Object value = null;
        if (secretsObj instanceof Map) {
            value = ((Map<?, ?>) secretsObj).get(secretPath);
        }
        if (value == null) {
            throw new AkeylessCredentialResolverException("Secret value not found for name: " + secretPath);
        }

        if (isContainer(value)) {
            return JSON_STD.asString(value);
        }
        String out = asString(value);
        return out != null ? out : "";
    }

    private Map<String, Object> postWithLegacyFallback(String gwUrl, String endpoint, Object payload) throws Exception {
        try {
            return transport.postJson(joinUrl(gwUrl, "/v2" + endpoint), payload);
        } catch (AkeylessCredentialResolverException e) {
            if (e.getMessage() != null && e.getMessage().contains("HTTP 404")) {
                return transport.postJson(joinUrl(gwUrl, endpoint), payload);
            }
            throw e;
        }
    }

    private static String joinUrl(String base, String path) {
        if (base == null || base.isEmpty()) {
            return path;
        }
        boolean bSlash = base.endsWith("/");
        boolean pSlash = path.startsWith("/");
        if (bSlash && pSlash) {
            return base + path.substring(1);
        }
        if (!bSlash && !pSlash) {
            return base + "/" + path;
        }
        return base + path;
    }

    private static boolean isContainer(Object v) {
        return v instanceof Map || v instanceof Iterable || (v != null && v.getClass().isArray());
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

