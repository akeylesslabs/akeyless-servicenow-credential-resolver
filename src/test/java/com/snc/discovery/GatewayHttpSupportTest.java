package com.snc.discovery;

import org.junit.After;
import org.junit.Assert;
import org.junit.Test;

import javax.net.ssl.SSLContext;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;

public class GatewayHttpSupportTest {

  @After
  public void tearDown() {
    GatewayHttpSupport.resetProxyAuthenticatorForTests();
    System.clearProperty(GatewayHttpSupport.PROP_CA);
    System.clearProperty(GatewayHttpSupport.PROP_CA_FILE);
    System.clearProperty(GatewayHttpSupport.PROP_PROXY_HOST);
    System.clearProperty(GatewayHttpSupport.PROP_PROXY_PORT);
    System.clearProperty(GatewayHttpSupport.PROP_PROXY_USERNAME);
    System.clearProperty(GatewayHttpSupport.PROP_PROXY_PASSWORD);
    System.clearProperty(GatewayHttpSupport.MID_PROXY_USE);
    System.clearProperty(GatewayHttpSupport.MID_PROXY_HOST);
    System.clearProperty(GatewayHttpSupport.MID_PROXY_PORT);
  }

  @Test
  public void testParseAndBuildSslContextFromSelfSignedPem() throws Exception {
    String pem = generateSelfSignedPem();
    SSLContext ctx = GatewayHttpSupport.buildSslContext(pem);
    Assert.assertNotNull(ctx);
    Assert.assertNotNull(ctx.getSocketFactory());
  }

  @Test
  public void testBuildSslContextNullWhenNoCa() throws Exception {
    Assert.assertNull(GatewayHttpSupport.buildSslContext(null));
    Assert.assertNull(GatewayHttpSupport.buildSslContext("   "));
  }

  @Test
  public void testParsePemRejectsGarbage() {
    try {
      GatewayHttpSupport.buildSslContext("not-a-cert");
      Assert.fail("expected IllegalArgumentException");
    } catch (IllegalArgumentException expected) {
      Assert.assertTrue(
          expected.getMessage().contains("No X.509")
              || expected.getMessage().contains("Failed to parse"));
    } catch (Exception e) {
      Assert.fail("unexpected: " + e);
    }
  }

  @Test
  public void testResolveCaPemFromFile() throws Exception {
    String pem = generateSelfSignedPem();
    Path tmp = Files.createTempFile("akeyless-ca", ".pem");
    try {
      Files.writeString(tmp, pem, StandardCharsets.UTF_8);
      Map<String, String> props = new HashMap<>();
      props.put(GatewayHttpSupport.PROP_CA_FILE, tmp.toString());
      String resolved = GatewayHttpSupport.resolveCaPem(mapProp(props));
      Assert.assertTrue(resolved.contains("BEGIN CERTIFICATE"));
    } finally {
      Files.deleteIfExists(tmp);
    }
  }

  @Test
  public void testResolveProxyFromAkeylessProps() {
    Map<String, String> props = new HashMap<>();
    props.put(GatewayHttpSupport.PROP_PROXY_HOST, "proxy.local");
    props.put(GatewayHttpSupport.PROP_PROXY_PORT, "3128");
    props.put(GatewayHttpSupport.PROP_PROXY_USERNAME, "u");
    props.put(GatewayHttpSupport.PROP_PROXY_PASSWORD, "p");

    GatewayHttpSupport.ProxySettings s = GatewayHttpSupport.resolveProxy(mapProp(props));
    Assert.assertNotNull(s);
    Assert.assertEquals("proxy.local", s.host);
    Assert.assertEquals(3128, s.port);
    Assert.assertEquals("u", s.username);
    Assert.assertEquals("p", s.password);
  }

  @Test
  public void testResolveProxyFallsBackToMidProxyWhenEnabled() {
    Map<String, String> props = new HashMap<>();
    props.put(GatewayHttpSupport.MID_PROXY_USE, "true");
    props.put(GatewayHttpSupport.MID_PROXY_HOST, "mid-proxy");
    props.put(GatewayHttpSupport.MID_PROXY_PORT, "8888");

    GatewayHttpSupport.ProxySettings s = GatewayHttpSupport.resolveProxy(mapProp(props));
    Assert.assertNotNull(s);
    Assert.assertEquals("mid-proxy", s.host);
    Assert.assertEquals(8888, s.port);
  }

  @Test
  public void testResolveProxyIgnoresMidProxyWhenDisabled() {
    Map<String, String> props = new HashMap<>();
    props.put(GatewayHttpSupport.MID_PROXY_USE, "false");
    props.put(GatewayHttpSupport.MID_PROXY_HOST, "mid-proxy");
    props.put(GatewayHttpSupport.MID_PROXY_PORT, "8888");

    Assert.assertNull(GatewayHttpSupport.resolveProxy(mapProp(props)));
  }

  @Test
  public void testAkeylessProxyTakesPrecedenceOverMidProxy() {
    Map<String, String> props = new HashMap<>();
    props.put(GatewayHttpSupport.PROP_PROXY_HOST, "akeyless-proxy");
    props.put(GatewayHttpSupport.PROP_PROXY_PORT, "9");
    props.put(GatewayHttpSupport.MID_PROXY_USE, "true");
    props.put(GatewayHttpSupport.MID_PROXY_HOST, "mid-proxy");
    props.put(GatewayHttpSupport.MID_PROXY_PORT, "8888");

    GatewayHttpSupport.ProxySettings s = GatewayHttpSupport.resolveProxy(mapProp(props));
    Assert.assertEquals("akeyless-proxy", s.host);
    Assert.assertEquals(9, s.port);
  }

  @Test
  public void testProxyEnvFieldsResolvedIndependentlyOfPropHost() {
    System.setProperty("AKEYLESS_PROXY_PORT", "9999");
    System.setProperty("AKEYLESS_PROXY_USERNAME", "env-user");
    System.setProperty("AKEYLESS_PROXY_PASSWORD", "env-pass");
    try {
      Map<String, String> props = new HashMap<>();
      props.put(GatewayHttpSupport.PROP_PROXY_HOST, "proxy-from-prop");
      GatewayHttpSupport.ProxySettings s = GatewayHttpSupport.resolveProxy(mapProp(props));
      Assert.assertEquals("proxy-from-prop", s.host);
      Assert.assertEquals(9999, s.port);
      Assert.assertEquals("env-user", s.username);
      Assert.assertEquals("env-pass", s.password);
    } finally {
      System.clearProperty("AKEYLESS_PROXY_PORT");
      System.clearProperty("AKEYLESS_PROXY_USERNAME");
      System.clearProperty("AKEYLESS_PROXY_PASSWORD");
    }
  }

  @Test
  public void testProxyAuthenticatorMatchesOnlyConfiguredHostPort() throws Exception {
    Map<String, String> props = new HashMap<>();
    props.put(GatewayHttpSupport.PROP_PROXY_HOST, "proxy.local");
    props.put(GatewayHttpSupport.PROP_PROXY_PORT, "3128");
    props.put(GatewayHttpSupport.PROP_PROXY_USERNAME, "u");
    props.put(GatewayHttpSupport.PROP_PROXY_PASSWORD, "p");
    GatewayHttpSupport.load(mapProp(props));

    Assert.assertTrue(GatewayHttpSupport.matchesConfiguredProxy("proxy.local", 3128));
    Assert.assertTrue(GatewayHttpSupport.matchesConfiguredProxy("PROXY.LOCAL", 3128));
    Assert.assertFalse(GatewayHttpSupport.matchesConfiguredProxy("other.proxy", 3128));
    Assert.assertFalse(GatewayHttpSupport.matchesConfiguredProxy("proxy.local", 8080));
  }

  @Test
  public void testLoadConfigWiresSslAndProxy() throws Exception {
    String pem = generateSelfSignedPem();
    Map<String, String> props = new HashMap<>();
    props.put(GatewayHttpSupport.PROP_CA, pem);
    props.put(GatewayHttpSupport.PROP_PROXY_HOST, "127.0.0.1");
    props.put(GatewayHttpSupport.PROP_PROXY_PORT, "18080");

    GatewayHttpSupport.Config cfg = GatewayHttpSupport.load(mapProp(props));
    Assert.assertNotNull(cfg.sslContext);
    Assert.assertNotNull(cfg.proxy);
    Assert.assertEquals(java.net.Proxy.Type.HTTP, cfg.proxy.type());
  }

  @Test
  public void testParseMultiplePemCerts() throws Exception {
    String one = generateSelfSignedPem();
    String two = generateSelfSignedPem();
    List<X509Certificate> certs = GatewayHttpSupport.parsePemCertificates(one + "\n" + two);
    Assert.assertEquals(2, certs.size());
  }

  private static BiFunction<String, String, String> mapProp(Map<String, String> props) {
    return (name, dflt) -> {
      String v = props.get(name);
      return v != null ? v : dflt;
    };
  }

  private static String generateSelfSignedPem() throws Exception {
    Path dir = Files.createTempDirectory("akeyless-tls-test");
    Path keystore = dir.resolve("t.jks");
    Path certFile = dir.resolve("t.crt");
    try {
      Process p = new ProcessBuilder(
          "keytool",
          "-genkeypair",
          "-alias", "t",
          "-keyalg", "RSA",
          "-keysize", "2048",
          "-validity", "1",
          "-dname", "CN=gw.example.internal",
          "-storepass", "changeit",
          "-keypass", "changeit",
          "-keystore", keystore.toString()
      ).redirectErrorStream(true).start();
      int code = p.waitFor();
      if (code != 0) {
        throw new IllegalStateException(
            "keytool genkeypair failed: "
                + new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
      }
      Process p2 = new ProcessBuilder(
          "keytool",
          "-exportcert",
          "-alias", "t",
          "-storepass", "changeit",
          "-keystore", keystore.toString(),
          "-rfc",
          "-file", certFile.toString()
      ).redirectErrorStream(true).start();
      int code2 = p2.waitFor();
      if (code2 != 0) {
        throw new IllegalStateException(
            "keytool exportcert failed: "
                + new String(p2.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
      }
      return Files.readString(certFile, StandardCharsets.UTF_8);
    } finally {
      Files.deleteIfExists(certFile);
      Files.deleteIfExists(keystore);
      Files.deleteIfExists(dir);
    }
  }
}
