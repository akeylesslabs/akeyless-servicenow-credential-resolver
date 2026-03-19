package com.snc.discovery;

import com.fasterxml.jackson.jr.ob.JSON;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;
import java.util.Objects;

final class DefaultHttpTransport implements AkeylessHttpTransport {
    private static final JSON JSON_STD = JSON.std;

    @Override
    public Map<String, Object> postJson(String url, Object payload) throws Exception {
        byte[] body = payload == null ? new byte[0] : JSON_STD.asBytes(payload);
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setConnectTimeout(15_000);
        conn.setReadTimeout(30_000);
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("Accept", "application/json");
        if (body.length > 0) {
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body);
            }
        }

        int code = conn.getResponseCode();
        try (InputStream is = code >= 200 && code < 300 ? conn.getInputStream() : conn.getErrorStream()) {
            if (is == null) {
                throw new AkeylessCredentialResolverException("HTTP error: " + code + " with empty body from " + url);
            }
            Object resp = JSON_STD.anyFrom(is);
            if (code < 200 || code >= 300) {
                String bodyStr = JSON_STD.asString(Objects.requireNonNullElse(resp, ""));
                throw new AkeylessCredentialResolverException("HTTP " + code + " from " + url + ": " + bodyStr);
            }
            if (!(resp instanceof Map)) {
                throw new AkeylessCredentialResolverException(
                    "Unexpected response type from " + url + ": " + resp.getClass().getSimpleName()
                );
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> out = (Map<String, Object>) resp;
            return out;
        } finally {
            conn.disconnect();
        }
    }
}

