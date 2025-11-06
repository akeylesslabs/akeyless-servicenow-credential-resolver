package com.snc.discovery;

import org.junit.Assert;
import org.junit.Test;

import java.lang.reflect.Method;

public class CredentialResolverPresenceTest {

    @Test
    public void testGetVersion() {
        CredentialResolver r = new CredentialResolver();
        Assert.assertEquals("1.0", r.getVersion());
    }

    @Test
    public void testMustThrowsOnEmpty() throws Exception {
        Method m = CredentialResolver.class.getDeclaredMethod("must", String.class, String.class);
        m.setAccessible(true);
        try {
            m.invoke(null, "", "msg");
            Assert.fail("should have thrown");
        } catch (Exception e) {
            // expected
        }
    }
}


