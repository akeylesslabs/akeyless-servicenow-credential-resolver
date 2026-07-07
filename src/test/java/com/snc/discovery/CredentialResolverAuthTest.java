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
        String itemTypeForDescribe = "STATIC_SECRET";
        int authCallCount = 0;

        @Override
        public Map<String, Object> postJson(String url, Object payload) throws Exception {
            @SuppressWarnings("unchecked")
            Map<String, Object> p = (Map<String, Object>) payload;
            if (url.endsWith("/v2/auth") || url.endsWith("/auth")) {
                authCallCount++;
                lastAuthPayload = p;
                Map<String, Object> out = new HashMap<>();
                out.put("token", "TKN");
                return out;
            }
            if (url.endsWith("/v2/describe-item") || url.endsWith("/describe-item")) {
                Map<String, Object> out = new HashMap<>();
                out.put("item_type", itemTypeForDescribe);
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
            if (url.endsWith("/v2/get-rotated-secret-value") || url.endsWith("/get-rotated-secret-value") || url.endsWith("/rotated-secret-get-value")) {
                Map<String, Object> value = new HashMap<>();
                value.put("username", "alexey-rotated");
                value.put("password", "Hxt3=NsX7y%W");
                Map<String, Object> out = new HashMap<>();
                out.put("value", value);
                return out;
            }
            if (url.endsWith("/v2/get-dynamic-secret-value") || url.endsWith("/get-dynamic-secret-value")) {
                Map<String, Object> out = new HashMap<>();
                out.put("id", "tmp.p-ud.66KVK");
                out.put("user", "tmp.p-ud.66KVK");
                out.put("password", "dyn-pass-9");
                out.put("ttl_in_minutes", "60");
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
        CredentialResolver.resetTokenCache();
        System.clearProperty("ext.cred.akeyless.gw_url");
        System.clearProperty("ext.cred.akeyless.access_type");
        System.clearProperty("ext.cred.akeyless.access_id");
        System.clearProperty("ext.cred.akeyless.access_key");
        System.clearProperty("ext.cred.akeyless.uid_token");
        System.clearProperty("ext.cred.akeyless.uid_token_file");
        System.clearProperty("ext.cred.akeyless.cert_data");
        System.clearProperty("ext.cred.akeyless.key_data");
        System.clearProperty("ext.cred.akeyless.cert_file_name");
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

        Assert.assertEquals("pw123", out.get(CredentialResolver.VAL_PSWD));
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

        Assert.assertEquals("pw123", out.get(CredentialResolver.VAL_PSWD));
        Assert.assertNotNull(http.lastAuthPayload);
        Assert.assertEquals("aws_iam", http.lastAuthPayload.get("access-type"));
        Assert.assertEquals("id2", http.lastAuthPayload.get("access-id"));
        Assert.assertEquals("CLOUD-ID", http.lastAuthPayload.get("cloud-id"));
        Assert.assertFalse(http.lastAuthPayload.containsKey("access-key"));
    }

    @Test
    public void testUidAuthReadsTokenFromFile() throws Exception {
        System.setProperty("ext.cred.akeyless.access_type", "uid");
        System.setProperty("ext.cred.akeyless.access_id", "iduidfile");
        Path tokenPath = Files.createTempFile("akeyless-uid-token", ".txt");
        try {
            Files.write(tokenPath, "uid-token-from-file\nignored-second-line".getBytes(StandardCharsets.UTF_8));
            System.setProperty("ext.cred.akeyless.uid_token_file", tokenPath.toString());

            RecordingHttp http = new RecordingHttp();
            CredentialResolver.setHttpTransport(http);

            CredentialResolver cr = new CredentialResolver();
            Map<String, String> args = new HashMap<>();
            args.put(CredentialResolver.ARG_ID, "/suidfile");
            args.put(CredentialResolver.ARG_TYPE, "ssh_password");
            Map<String, String> out = cr.resolve(args);

            Assert.assertEquals("pw123", out.get(CredentialResolver.VAL_PSWD));
            Assert.assertEquals("universal_identity", http.lastAuthPayload.get("access-type"));
            Assert.assertEquals("iduidfile", http.lastAuthPayload.get("access-id"));
            Assert.assertEquals("uid-token-from-file", http.lastAuthPayload.get("uid-token"));
        } finally {
            Files.deleteIfExists(tokenPath);
        }
    }

    @Test
    public void testUidAuthPrefersFileOverInlineToken() throws Exception {
        System.setProperty("ext.cred.akeyless.access_type", "uid");
        System.setProperty("ext.cred.akeyless.access_id", "iduidprefer");
        System.setProperty("ext.cred.akeyless.uid_token", "uid-token-inline");
        Path tokenPath = Files.createTempFile("akeyless-uid-token-prefer", ".txt");
        try {
            Files.write(tokenPath, "uid-token-from-file".getBytes(StandardCharsets.UTF_8));
            System.setProperty("ext.cred.akeyless.uid_token_file", tokenPath.toString());

            RecordingHttp http = new RecordingHttp();
            CredentialResolver.setHttpTransport(http);

            CredentialResolver cr = new CredentialResolver();
            Map<String, String> args = new HashMap<>();
            args.put(CredentialResolver.ARG_ID, "/suidprefer");
            args.put(CredentialResolver.ARG_TYPE, "ssh_password");
            cr.resolve(args);

            Assert.assertEquals("uid-token-from-file", http.lastAuthPayload.get("uid-token"));
        } finally {
            Files.deleteIfExists(tokenPath);
        }
    }

    @Test
    public void testUidAuthFallsBackToInlineWhenFileMissing() throws Exception {
        System.setProperty("ext.cred.akeyless.access_type", "uid");
        System.setProperty("ext.cred.akeyless.access_id", "iduidfallback");
        System.setProperty("ext.cred.akeyless.uid_token", "uid-token-inline-fallback");
        System.setProperty("ext.cred.akeyless.uid_token_file", "/nonexistent/uid-token.txt");

        RecordingHttp http = new RecordingHttp();
        CredentialResolver.setHttpTransport(http);

        CredentialResolver cr = new CredentialResolver();
        Map<String, String> args = new HashMap<>();
        args.put(CredentialResolver.ARG_ID, "/suidfallback");
        args.put(CredentialResolver.ARG_TYPE, "ssh_password");
        cr.resolve(args);

        Assert.assertEquals("uid-token-inline-fallback", http.lastAuthPayload.get("uid-token"));
    }

    @Test
    public void testUidAliasAuthFlowUsesUidToken() throws Exception {
        System.setProperty("ext.cred.akeyless.access_type", "uid");
        System.setProperty("ext.cred.akeyless.access_id", "iduid");
        System.setProperty("ext.cred.akeyless.uid_token", "uid-token-123");

        RecordingHttp http = new RecordingHttp();
        CredentialResolver.setHttpTransport(http);

        CredentialResolver cr = new CredentialResolver();
        Map<String, String> args = new HashMap<>();
        args.put(CredentialResolver.ARG_ID, "/suid");
        args.put(CredentialResolver.ARG_TYPE, "ssh_password");
        Map<String, String> out = cr.resolve(args);

        Assert.assertEquals("pw123", out.get(CredentialResolver.VAL_PSWD));
        Assert.assertEquals("universal_identity", http.lastAuthPayload.get("access-type"));
        Assert.assertEquals("iduid", http.lastAuthPayload.get("access-id"));
        Assert.assertEquals("uid-token-123", http.lastAuthPayload.get("uid-token"));
    }

    @Test
    public void testCertificateAliasUsesInlineMaterial() throws Exception {
        System.setProperty("ext.cred.akeyless.access_type", "certificate");
        System.setProperty("ext.cred.akeyless.access_id", "idcert");
        System.setProperty("ext.cred.akeyless.cert_data", "CERT-DATA");
        System.setProperty("ext.cred.akeyless.key_data", "KEY-DATA");

        RecordingHttp http = new RecordingHttp();
        CredentialResolver.setHttpTransport(http);

        CredentialResolver cr = new CredentialResolver();
        Map<String, String> args = new HashMap<>();
        args.put(CredentialResolver.ARG_ID, "/scert");
        args.put(CredentialResolver.ARG_TYPE, "ssh_password");
        Map<String, String> out = cr.resolve(args);

        Assert.assertEquals("pw123", out.get(CredentialResolver.VAL_PSWD));
        Assert.assertEquals("certificate", http.lastAuthPayload.get("access-type"));
        Assert.assertEquals("idcert", http.lastAuthPayload.get("access-id"));
        Assert.assertEquals(
            Base64.getEncoder().encodeToString("CERT-DATA".getBytes(StandardCharsets.UTF_8)),
            http.lastAuthPayload.get("cert-data")
        );
        Assert.assertEquals(
            Base64.getEncoder().encodeToString("KEY-DATA".getBytes(StandardCharsets.UTF_8)),
            http.lastAuthPayload.get("key-data")
        );
    }

    @Test
    public void testCertAuthReadsMaterialFromFiles() throws Exception {
        System.setProperty("ext.cred.akeyless.access_type", "cert");
        System.setProperty("ext.cred.akeyless.access_id", "idcertfile");
        Path certPath = Files.createTempFile("akeyless-cert", ".pem");
        Path keyPath = Files.createTempFile("akeyless-key", ".pem");
        Files.write(certPath, "CERT-FILE-DATA".getBytes(StandardCharsets.UTF_8));
        Files.write(keyPath, "KEY-FILE-DATA".getBytes(StandardCharsets.UTF_8));
        System.setProperty("ext.cred.akeyless.cert_file_name", certPath.toString());
        System.setProperty("ext.cred.akeyless.key_file_name", keyPath.toString());

        RecordingHttp http = new RecordingHttp();
        CredentialResolver.setHttpTransport(http);

        CredentialResolver cr = new CredentialResolver();
        Map<String, String> args = new HashMap<>();
        args.put(CredentialResolver.ARG_ID, "/scertfile");
        args.put(CredentialResolver.ARG_TYPE, "ssh_password");
        Map<String, String> out = cr.resolve(args);

        Assert.assertEquals("pw123", out.get(CredentialResolver.VAL_PSWD));
        Assert.assertEquals("certificate", http.lastAuthPayload.get("access-type"));
        Assert.assertEquals(
            Base64.getEncoder().encodeToString(Files.readAllBytes(certPath)),
            http.lastAuthPayload.get("cert-data")
        );
        Assert.assertEquals(
            Base64.getEncoder().encodeToString(Files.readAllBytes(keyPath)),
            http.lastAuthPayload.get("key-data")
        );

        Files.deleteIfExists(certPath);
        Files.deleteIfExists(keyPath);
    }

    @Test
    public void testCertAuthWithoutMaterialThrows() throws Exception {
        System.setProperty("ext.cred.akeyless.access_type", "cert");
        System.setProperty("ext.cred.akeyless.access_id", "idmissing");

        RecordingHttp http = new RecordingHttp();
        CredentialResolver.setHttpTransport(http);

        CredentialResolver cr = new CredentialResolver();
        Map<String, String> args = new HashMap<>();
        args.put(CredentialResolver.ARG_ID, "/smissing");
        args.put(CredentialResolver.ARG_TYPE, "ssh_password");

        try {
            cr.resolve(args);
            Assert.fail("Expected IllegalArgumentException for missing certificate material");
        } catch (IllegalArgumentException expected) {
            Assert.assertTrue(expected.getMessage().contains("Missing Akeyless certificate material"));
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

    @Test
    public void testDynamicSecretFlowMapsUserToUsername() throws Exception {
        System.setProperty("ext.cred.akeyless.access_type", "access_key");
        System.setProperty("ext.cred.akeyless.access_id", "id1");
        System.setProperty("ext.cred.akeyless.access_key", "k1");

        RecordingHttp http = new RecordingHttp();
        http.itemTypeForDescribe = "DYNAMIC_SECRET";
        CredentialResolver.setHttpTransport(http);

        CredentialResolver cr = new CredentialResolver();
        Map<String, String> args = new HashMap<>();
        args.put(CredentialResolver.ARG_ID, "/ldap-dyn");
        args.put(CredentialResolver.ARG_TYPE, "ssh_password");
        Map<String, String> out = cr.resolve(args);

        Assert.assertEquals("tmp.p-ud.66KVK", out.get(CredentialResolver.VAL_USER));
        Assert.assertEquals("dyn-pass-9", out.get(CredentialResolver.VAL_PSWD));
    }

    @Test
    public void testRotatedSecretFlowReturnsUsernameAndPassword() throws Exception {
        System.setProperty("ext.cred.akeyless.access_type", "access_key");
        System.setProperty("ext.cred.akeyless.access_id", "id1");
        System.setProperty("ext.cred.akeyless.access_key", "k1");

        RecordingHttp http = new RecordingHttp();
        http.itemTypeForDescribe = "ROTATED_SECRET";
        CredentialResolver.setHttpTransport(http);

        CredentialResolver cr = new CredentialResolver();
        Map<String, String> args = new HashMap<>();
        args.put(CredentialResolver.ARG_ID, "/ldap-rotated");
        args.put(CredentialResolver.ARG_TYPE, "ldap");
        Map<String, String> out = cr.resolve(args);

        Assert.assertEquals("alexey-rotated", out.get(CredentialResolver.VAL_USER));
        Assert.assertEquals("Hxt3=NsX7y%W", out.get(CredentialResolver.VAL_PSWD));
    }

    @Test
    public void testDescribeItemFailurePropagates() throws Exception {
        System.setProperty("ext.cred.akeyless.access_type", "access_key");
        System.setProperty("ext.cred.akeyless.access_id", "id1");
        System.setProperty("ext.cred.akeyless.access_key", "k1");

        CredentialResolver.setHttpTransport((url, payload) -> {
            if (url.endsWith("/v2/auth") || url.endsWith("/auth")) {
                Map<String, Object> out = new HashMap<>();
                out.put("token", "TKN");
                return out;
            }
            if (url.endsWith("/v2/describe-item") || url.endsWith("/describe-item")) {
                throw new AkeylessCredentialResolverException("HTTP 503 from https://fake/v2/describe-item: unavailable");
            }
            throw new AssertionError("Unexpected URL after describe failure: " + url);
        });

        CredentialResolver cr = new CredentialResolver();
        Map<String, String> args = new HashMap<>();
        args.put(CredentialResolver.ARG_ID, "/s");
        args.put(CredentialResolver.ARG_TYPE, "ssh_password");
        try {
            cr.resolve(args);
            Assert.fail("Expected AkeylessCredentialResolverException from describe-item");
        } catch (AkeylessCredentialResolverException expected) {
            Assert.assertTrue(expected.getMessage().contains("503"));
        }
    }

    @Test
    public void testUnsupportedItemTypeThrows() throws Exception {
        System.setProperty("ext.cred.akeyless.access_type", "access_key");
        System.setProperty("ext.cred.akeyless.access_id", "id1");
        System.setProperty("ext.cred.akeyless.access_key", "k1");

        RecordingHttp http = new RecordingHttp();
        http.itemTypeForDescribe = "TARGET";
        CredentialResolver.setHttpTransport(http);

        CredentialResolver cr = new CredentialResolver();
        Map<String, String> args = new HashMap<>();
        args.put(CredentialResolver.ARG_ID, "/odd");
        args.put(CredentialResolver.ARG_TYPE, "ssh_password");
        try {
            cr.resolve(args);
            Assert.fail("Expected AkeylessCredentialResolverException for unsupported item_type");
        } catch (AkeylessCredentialResolverException expected) {
            Assert.assertTrue(expected.getMessage().contains("Unsupported Akeyless item_type"));
            Assert.assertTrue(expected.getMessage().contains("TARGET"));
        }
    }

    @Test
    public void testSecondResolveReusesCachedToken() throws Exception {
        System.setProperty("ext.cred.akeyless.access_type", "access_key");
        System.setProperty("ext.cred.akeyless.access_id", "id1");
        System.setProperty("ext.cred.akeyless.access_key", "k1");

        RecordingHttp http = new RecordingHttp();
        CredentialResolver.setHttpTransport(http);

        CredentialResolver cr = new CredentialResolver();
        Map<String, String> args = new HashMap<>();
        args.put(CredentialResolver.ARG_ID, "/s");
        args.put(CredentialResolver.ARG_TYPE, "ssh_password");

        cr.resolve(args);
        cr.resolve(args);

        Assert.assertEquals(1, http.authCallCount);
    }

    @Test
    public void testAuthErrorOnDescribeTriggersReauthAndRetry() throws Exception {
        System.setProperty("ext.cred.akeyless.access_type", "access_key");
        System.setProperty("ext.cred.akeyless.access_id", "id1");
        System.setProperty("ext.cred.akeyless.access_key", "k1");

        final int[] authCallCount = {0};
        final int[] describeCallCount = {0};
        CredentialResolver.setHttpTransport((url, payload) -> {
            if (url.endsWith("/v2/auth") || url.endsWith("/auth")) {
                authCallCount[0]++;
                Map<String, Object> out = new HashMap<>();
                out.put("token", "TKN-" + authCallCount[0]);
                return out;
            }
            if (url.endsWith("/v2/describe-item") || url.endsWith("/describe-item")) {
                describeCallCount[0]++;
                if (describeCallCount[0] == 1) {
                    throw new AkeylessCredentialResolverException(
                        "HTTP 401 from https://fake/v2/describe-item: invalid token");
                }
                Map<String, Object> out = new HashMap<>();
                out.put("item_type", "STATIC_SECRET");
                return out;
            }
            if (url.endsWith("/v2/get-secret-value") || url.endsWith("/get-secret-value")) {
                @SuppressWarnings("unchecked")
                Map<String, Object> p = (Map<String, Object>) payload;
                String name = (String) p.get("name");
                Map<String, Object> secrets = new HashMap<>();
                secrets.put(name, "pw123");
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

        Assert.assertEquals("pw123", out.get(CredentialResolver.VAL_PSWD));
        Assert.assertEquals(2, authCallCount[0]);
        Assert.assertEquals(2, describeCallCount[0]);
    }

    @Test
    public void testNonAuthErrorDoesNotReauth() throws Exception {
        System.setProperty("ext.cred.akeyless.access_type", "access_key");
        System.setProperty("ext.cred.akeyless.access_id", "id1");
        System.setProperty("ext.cred.akeyless.access_key", "k1");

        final int[] authCallCount = {0};
        CredentialResolver.setHttpTransport((url, payload) -> {
            if (url.endsWith("/v2/auth") || url.endsWith("/auth")) {
                authCallCount[0]++;
                Map<String, Object> out = new HashMap<>();
                out.put("token", "TKN");
                return out;
            }
            if (url.endsWith("/v2/describe-item") || url.endsWith("/describe-item")) {
                throw new AkeylessCredentialResolverException(
                    "HTTP 503 from https://fake/v2/describe-item: unavailable");
            }
            throw new AssertionError("Unexpected URL after describe failure: " + url);
        });

        CredentialResolver cr = new CredentialResolver();
        Map<String, String> args = new HashMap<>();
        args.put(CredentialResolver.ARG_ID, "/s");
        args.put(CredentialResolver.ARG_TYPE, "ssh_password");
        try {
            cr.resolve(args);
            Assert.fail("Expected AkeylessCredentialResolverException from describe-item");
        } catch (AkeylessCredentialResolverException expected) {
            Assert.assertTrue(expected.getMessage().contains("503"));
        }
        Assert.assertEquals(1, authCallCount[0]);
    }
}


