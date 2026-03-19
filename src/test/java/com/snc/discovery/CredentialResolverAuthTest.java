package com.snc.discovery;

import io.akeyless.cloudid.CloudIdProvider;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class CredentialResolverAuthTest {

    private static class RecordingHttp implements CredentialResolver.HttpTransport {
        Map<String, Object> lastAuthPayload;

        @Override
        public Map<String, Object> postJson(String url, Object payload) throws Exception {
            @SuppressWarnings("unchecked")
            Map<String, Object> p = (Map<String, Object>) payload;
            if (url.endsWith("/v2/auth") || url.endsWith("/auth")) {
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
        System.clearProperty("ext.cred.akeyless.uid_token");
        System.clearProperty("ext.cred.akeyless.cert_data");
        System.clearProperty("ext.cred.akeyless.cert_file_name");
        System.clearProperty("ext.cred.akeyless.key_data");
        System.clearProperty("ext.cred.akeyless.key_file_name");
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
    public void testUniversalIdentityAuthFlowUsesUidToken() throws Exception {
        System.setProperty("ext.cred.akeyless.access_type", "uid");
        System.setProperty("ext.cred.akeyless.access_id", "id3");
        System.setProperty("ext.cred.akeyless.uid_token", "u-123");

        RecordingHttp http = new RecordingHttp();
        CredentialResolver.setHttpTransport(http);

        CredentialResolver cr = new CredentialResolver();
        Map<String, String> args = new HashMap<>();
        args.put(CredentialResolver.ARG_ID, "/s3");
        args.put(CredentialResolver.ARG_TYPE, "ssh_password");
        Map<String, String> out = cr.resolve(args);

        Assert.assertEquals("pw123", out.get("password"));
        Assert.assertEquals("universal_identity", http.lastAuthPayload.get("access-type"));
        Assert.assertEquals("id3", http.lastAuthPayload.get("access-id"));
        Assert.assertEquals("u-123", http.lastAuthPayload.get("uid-token"));
        Assert.assertFalse(http.lastAuthPayload.containsKey("cloud-id"));
    }

    @Test
    public void testCertificateAuthFlowUsesInlinePemData() throws Exception {
        System.setProperty("ext.cred.akeyless.access_type", "certificate");
        System.setProperty("ext.cred.akeyless.access_id", "id4");
        System.setProperty("ext.cred.akeyless.cert_data", "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----");
        System.setProperty("ext.cred.akeyless.key_data", "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----");

        RecordingHttp http = new RecordingHttp();
        CredentialResolver.setHttpTransport(http);

        CredentialResolver cr = new CredentialResolver();
        Map<String, String> args = new HashMap<>();
        args.put(CredentialResolver.ARG_ID, "/s4");
        args.put(CredentialResolver.ARG_TYPE, "ssh_password");
        Map<String, String> out = cr.resolve(args);

        Assert.assertEquals("pw123", out.get("password"));
        Assert.assertEquals("cert", http.lastAuthPayload.get("access-type"));
        Assert.assertEquals(
                Base64.getEncoder().encodeToString("-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----".getBytes(StandardCharsets.UTF_8)),
                http.lastAuthPayload.get("cert-data")
        );
        Assert.assertEquals(
                Base64.getEncoder().encodeToString("-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----".getBytes(StandardCharsets.UTF_8)),
                http.lastAuthPayload.get("key-data")
        );
    }

    @Test
    public void testCertificateAuthFlowReadsFiles() throws Exception {
        System.setProperty("ext.cred.akeyless.access_type", "cert");
        System.setProperty("ext.cred.akeyless.access_id", "id5");

        Path certFile = Files.createTempFile("akeyless-cert", ".pem");
        Path keyFile = Files.createTempFile("akeyless-key", ".pem");
        try {
            Files.write(certFile, "CERT-FILE".getBytes(StandardCharsets.UTF_8));
            Files.write(keyFile, "KEY-FILE".getBytes(StandardCharsets.UTF_8));

            System.setProperty("ext.cred.akeyless.cert_file_name", certFile.toString());
            System.setProperty("ext.cred.akeyless.key_file_name", keyFile.toString());

            RecordingHttp http = new RecordingHttp();
            CredentialResolver.setHttpTransport(http);

            CredentialResolver cr = new CredentialResolver();
            Map<String, String> args = new HashMap<>();
            args.put(CredentialResolver.ARG_ID, "/s5");
            args.put(CredentialResolver.ARG_TYPE, "ssh_password");
            Map<String, String> out = cr.resolve(args);

            Assert.assertEquals("pw123", out.get("password"));
            Assert.assertEquals(Base64.getEncoder().encodeToString("CERT-FILE".getBytes(StandardCharsets.UTF_8)), http.lastAuthPayload.get("cert-data"));
            Assert.assertEquals(Base64.getEncoder().encodeToString("KEY-FILE".getBytes(StandardCharsets.UTF_8)), http.lastAuthPayload.get("key-data"));
        } finally {
            Files.deleteIfExists(certFile);
            Files.deleteIfExists(keyFile);
        }
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


