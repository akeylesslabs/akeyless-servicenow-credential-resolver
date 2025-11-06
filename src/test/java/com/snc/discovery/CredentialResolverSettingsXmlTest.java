package com.snc.discovery;

import io.akeyless.cloudid.CloudIdProvider;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

public class CredentialResolverSettingsXmlTest {

    @After
    public void cleanup() {
        CredentialResolver.resetHttpTransport();
        System.clearProperty("ext.cred.akeyless.gw_url");
        System.clearProperty("ext.cred.akeyless.access_type");
        System.clearProperty("ext.cred.akeyless.access_id");
        System.clearProperty("ext.cred.akeyless.access_key");
    }

    @Test
    public void testReadsAccessKeyFromSystemProperties() throws Exception {
        System.setProperty("ext.cred.akeyless.gw_url", "https://fake");
        System.setProperty("ext.cred.akeyless.access_type", "access_key");
        System.setProperty("ext.cred.akeyless.access_id", "id-prop");
        System.setProperty("ext.cred.akeyless.access_key", "key-prop");

        CredentialResolver.setHttpTransport((url, payload) -> {
            @SuppressWarnings("unchecked")
            Map<String, Object> p = (Map<String, Object>) payload;
            if (url.endsWith("/auth") || url.endsWith("/v2/auth")) {
                Assert.assertEquals("access_key", p.get("access-type"));
                Assert.assertEquals("id-prop", p.get("access-id"));
                Assert.assertEquals("key-prop", p.get("access-key"));
                Map<String, Object> out = new HashMap<>();
                out.put("token", "T");
                return out;
            }
            if (url.endsWith("/get-secret-value") || url.endsWith("/v2/get-secret-value")) {
                Map<String, Object> secrets = new HashMap<>();
                secrets.put("/s", "pw");
                Map<String, Object> out = new HashMap<>();
                out.put("secrets", secrets);
                return out;
            }
            throw new AssertionError("Unexpected URL: " + url);
        });

        CredentialResolver cr = new CredentialResolver();
        Map<String, String> args = new HashMap<>();
        args.put(CredentialResolver.ARG_ID, "/s");
        args.put(CredentialResolver.ARG_TYPE, "ssh_password");
        Map<String, String> out = cr.resolve(args);
        Assert.assertEquals("pw", out.get("password"));
    }

    @Test
    public void testReadsCloudIdTypeFromSystemProperties() throws Exception {
        System.setProperty("ext.cred.akeyless.gw_url", "https://fake");
        System.setProperty("ext.cred.akeyless.access_type", "azure_ad");
        System.setProperty("ext.cred.akeyless.access_id", "id-prop-2");

        CredentialResolver.setHttpTransport((url, payload) -> {
            @SuppressWarnings("unchecked")
            Map<String, Object> p = (Map<String, Object>) payload;
            if (url.endsWith("/auth") || url.endsWith("/v2/auth")) {
                Assert.assertEquals("azure_ad", p.get("access-type"));
                Assert.assertEquals("id-prop-2", p.get("access-id"));
                Assert.assertEquals("CLOUD-ID-2", p.get("cloud-id"));
                Map<String, Object> out = new HashMap<>();
                out.put("token", "T2");
                return out;
            }
            if (url.endsWith("/get-secret-value") || url.endsWith("/v2/get-secret-value")) {
                Map<String, Object> secrets = new HashMap<>();
                secrets.put("/s2", "pw2");
                Map<String, Object> out = new HashMap<>();
                out.put("secrets", secrets);
                return out;
            }
            throw new AssertionError("Unexpected URL: " + url);
        });

        CredentialResolver cr = new CredentialResolver() {
            @Override
            protected CloudIdProvider getCloudIdProvider(String type) {
                return () -> "CLOUD-ID-2";
            }
        };
        Map<String, String> args = new HashMap<>();
        args.put(CredentialResolver.ARG_ID, "/s2");
        args.put(CredentialResolver.ARG_TYPE, "ssh_password");
        Map<String, String> out = cr.resolve(args);
        Assert.assertEquals("pw2", out.get("password"));
    }
}


