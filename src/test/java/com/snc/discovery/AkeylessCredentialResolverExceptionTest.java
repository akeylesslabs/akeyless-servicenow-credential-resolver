package com.snc.discovery;

import org.junit.Assert;
import org.junit.Test;

public class AkeylessCredentialResolverExceptionTest {

    @Test
    public void testConstructors() {
        AkeylessCredentialResolverException e1 = new AkeylessCredentialResolverException("m");
        Assert.assertEquals("m", e1.getMessage());
        Exception cause = new Exception("c");
        AkeylessCredentialResolverException e2 = new AkeylessCredentialResolverException("m2", cause);
        Assert.assertEquals("m2", e2.getMessage());
        Assert.assertEquals(cause, e2.getCause());
        AkeylessCredentialResolverException e3 = new AkeylessCredentialResolverException(cause);
        Assert.assertEquals(cause, e3.getCause());
        AkeylessCredentialResolverException e4 = new AkeylessCredentialResolverException("m4", cause, true, true);
        Assert.assertEquals("m4", e4.getMessage());
    }
}


