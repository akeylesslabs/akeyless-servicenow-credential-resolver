package com.snc.discovery;

import io.akeyless.cloudid.CloudIdProvider;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

public class CredentialResolverAuthTest {

    private static class RecordingHttp implements CredentialResolver.HttpTransport {
        Map<String, Object> lastAuthPayload;
        String lastAuthUrl;

        @Override
        public Map<String, Object> postJson(String url, Object payload) throws Exception {
            @SuppressWarnings("unchecked")
            Map<String, Object> p = (Map<String, Object>) payload;
            if (url.endsWith("/v2/auth") || url.endsWith("/auth")) {
                lastAuthUrl = url;
                lastAuthPayload = p;
                Map<String, Object> out = new HashMap<>();
                out.put("token", "TKN");
                return out;
            }
            if (url.endsWith("/v2/get-secret-value") || url.endsWith("/get-secret-value")) {
                String name = (String) p.get("name");
                Map<String, Object> secrets = new HashMap<>();
                secrets.put(name, "pw123");
                Map<String, Object> out = new HashMap<>();
                out.put("secrets", secrets);
                return out;
            }
            throw new AssertionError("Unexpected URL: " + url);
        }
    }

    @Before
    public void setUp() {
        System.setProperty("ext.cred.akeyless.gw_url", "https://fake");
    }

    @After
    public void tearDown() {
        CredentialResolver.resetHttpTransport();
        System.clearProperty("ext.cred.akeyless.gw_url");
        System.clearProperty("ext.cred.akeyless.access_type");
        System.clearProperty("ext.cred.akeyless.access_id");
        System.clearProperty("ext.cred.akeyless.access_key");
    }

    @Test
    public void testAccessKeyAuthFlow() throws Exception {
        System.setProperty("ext.cred.akeyless.access_type", "access_key");
        System.setProperty("ext.cred.akeyless.access_id", "id1");
        System.setProperty("ext.cred.akeyless.access_key", "k1");

        RecordingHttp http = new RecordingHttp();
        CredentialResolver.setHttpTransport(http);

        CredentialResolver cr = new CredentialResolver();
        Map<String, String> args = new HashMap<>();
        args.put(CredentialResolver.ARG_ID, "/s");
        args.put(CredentialResolver.ARG_TYPE, "ssh_password");
        Map<String, String> out = cr.resolve(args);

        Assert.assertEquals("pw123", out.get("password"));
        Assert.assertNotNull(http.lastAuthPayload);
        Assert.assertEquals("access_key", http.lastAuthPayload.get("access-type"));
        Assert.assertEquals("id1", http.lastAuthPayload.get("access-id"));
        Assert.assertEquals("k1", http.lastAuthPayload.get("access-key"));
        Assert.assertFalse(http.lastAuthPayload.containsKey("cloud-id"));
    }

    @Test
    public void testAwsIamAuthFlowAddsCloudId() throws Exception {
        System.setProperty("ext.cred.akeyless.access_type", "aws_iam");
        System.setProperty("ext.cred.akeyless.access_id", "id2");

        RecordingHttp http = new RecordingHttp();
        CredentialResolver.setHttpTransport(http);

        // Override CloudID provider to avoid external calls
        CredentialResolver cr = new CredentialResolver() {
            @Override
            protected CloudIdProvider getCloudIdProvider(String type) {
                return () -> "CLOUD-ID";
            }
        };

        Map<String, String> args = new HashMap<>();
        args.put(CredentialResolver.ARG_ID, "/s2");
        args.put(CredentialResolver.ARG_TYPE, "ssh_password");
        Map<String, String> out = cr.resolve(args);

        Assert.assertEquals("pw123", out.get("password"));
        Assert.assertNotNull(http.lastAuthPayload);
        Assert.assertEquals("aws_iam", http.lastAuthPayload.get("access-type"));
        Assert.assertEquals("id2", http.lastAuthPayload.get("access-id"));
        Assert.assertEquals("CLOUD-ID", http.lastAuthPayload.get("cloud-id"));
        Assert.assertFalse(http.lastAuthPayload.containsKey("access-key"));
    }

    @Test
    public void testUnsupportedAccessTypeThrows() throws Exception {
        System.setProperty("ext.cred.akeyless.access_type", "password");
        System.setProperty("ext.cred.akeyless.access_id", "idx");

        RecordingHttp http = new RecordingHttp();
        CredentialResolver.setHttpTransport(http);

        CredentialResolver cr = new CredentialResolver();
        Map<String, String> args = new HashMap<>();
        args.put(CredentialResolver.ARG_ID, "/sx");
        args.put(CredentialResolver.ARG_TYPE, "ssh_password");
        try {
            cr.resolve(args);
            Assert.fail("Expected IllegalArgumentException for unsupported access type");
        } catch (IllegalArgumentException expected) {
            // ok
        }
    }
}


