package com.snc.discovery;

import org.junit.Test;
import org.junit.Assert;

import java.lang.reflect.Method;
import java.util.Map;

public class CredentialResolverMappingTest {

    @SuppressWarnings("unchecked")
    private Map<String, String> invokeMapToServiceNow(String type, String raw,
                                                      String fUser, String fPass, String fPk, String fPhr) throws Exception {
        CredentialResolver cr = new CredentialResolver();
        Method m = CredentialResolver.class.getDeclaredMethod("mapToServiceNow",
                String.class, String.class, String.class, String.class, String.class, String.class);
        m.setAccessible(true);
        return (Map<String, String>) m.invoke(cr, type, raw, fUser, fPass, fPk, fPhr);
    }

    @Test
    public void testEmptyRawReturnsEmptyMap() throws Exception {
        Map<String, String> out = invokeMapToServiceNow("basic", "", "username", "password", "private_key", "passphrase");
        Assert.assertTrue(out.isEmpty());
    }

    @Test
    public void testPlainStringRawBecomesPassword() throws Exception {
        Map<String, String> out = invokeMapToServiceNow("basic", "t0ken123", "username", "password", "private_key", "passphrase");
        Assert.assertEquals("t0ken123", out.get("password"));
        Assert.assertEquals(1, out.size());
    }

    @Test
    public void testBasicWithJsonDefaultFields() throws Exception {
        String raw = "{\"username\":\"Ssa\",\"password\":\"ddd\"}";
        Map<String, String> out = invokeMapToServiceNow("basic", raw, "username", "password", "private_key", "passphrase");
        Assert.assertEquals("Ssa", out.get("username"));
        Assert.assertEquals("ddd", out.get("password"));
        Assert.assertEquals(2, out.size());
    }

    @Test
    public void testBasicWithJsonCustomFieldNames() throws Exception {
        String raw = "{\"user_name\":\"alice\",\"pwd\":\"secret\"}";
        Map<String, String> out = invokeMapToServiceNow("basic", raw, "user_name", "pwd", "private_key", "passphrase");
        Assert.assertEquals("alice", out.get("username"));
        Assert.assertEquals("secret", out.get("password"));
        Assert.assertEquals(2, out.size());
    }

    @Test
    public void testSshPrivateKeyMapping() throws Exception {
        String raw = "{\"username\":\"ssh-user\",\"private_key\":\"---KEY---\",\"passphrase\":\"pp\"}";
        Map<String, String> out = invokeMapToServiceNow("ssh_private_key", raw, "username", "password", "private_key", "passphrase");
        Assert.assertEquals("ssh-user", out.get("username"));
        Assert.assertEquals("---KEY---", out.get("private_key"));
        Assert.assertEquals("pp", out.get("passphrase"));
        Assert.assertEquals(3, out.size());
    }

    @Test
    public void testSnmpV3Mapping() throws Exception {
        String raw = "{\"username\":\"snmpu\",\"auth_protocol\":\"SHA\",\"auth_key\":\"ak\",\"privacy_protocol\":\"AES\",\"privacy_key\":\"pk\"}";
        Map<String, String> out = invokeMapToServiceNow("snmpv3", raw, "username", "password", "private_key", "passphrase");
        Assert.assertEquals("snmpu", out.get("username"));
        Assert.assertEquals("SHA", out.get("auth-protocol"));
        Assert.assertEquals("ak", out.get("auth-key"));
        Assert.assertEquals("AES", out.get("privacy-protocol"));
        Assert.assertEquals("pk", out.get("privacy-key"));
        Assert.assertEquals(5, out.size());
    }

    @Test
    public void testUnknownTypeFallsBackToUserPass() throws Exception {
        String raw = "{\"user_field\":\"uu\",\"pass_field\":\"pp\"}";
        Map<String, String> out = invokeMapToServiceNow("custom_type", raw, "user_field", "pass_field", "private_key", "passphrase");
        Assert.assertEquals("uu", out.get("username"));
        Assert.assertEquals("pp", out.get("password"));
        Assert.assertEquals(2, out.size());
    }
}


