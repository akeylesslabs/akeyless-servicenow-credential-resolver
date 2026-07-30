package com.snc.discovery;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.Authenticator;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.function.BiFunction;

/**
 * TLS and HTTP proxy helpers for Gateway calls.
 *
 * <p>Custom CA PEMs are merged into the JVM default truststore (hostname verification stays enabled).
 * There is no TLS skip-verify path.
 */
final class GatewayHttpSupport {
  static final String PROP_CA = "ext.cred.akeyless.ca";
  static final String PROP_CA_FILE = "ext.cred.akeyless.ca_file";
  static final String PROP_PROXY_HOST = "ext.cred.akeyless.proxy_host";
  static final String PROP_PROXY_PORT = "ext.cred.akeyless.proxy_port";
  static final String PROP_PROXY_USERNAME = "ext.cred.akeyless.proxy_username";
  static final String PROP_PROXY_PASSWORD = "ext.cred.akeyless.proxy_password";

  static final String MID_PROXY_USE = "mid.proxy.use_proxy";
  static final String MID_PROXY_HOST = "mid.proxy.host";
  static final String MID_PROXY_PORT = "mid.proxy.port";
  static final String MID_PROXY_USERNAME = "mid.proxy.username";
  static final String MID_PROXY_PASSWORD = "mid.proxy.password";

  private static final Object PROXY_AUTH_LOCK = new Object();
  private static volatile boolean proxyAuthenticatorInstalled;
  private static volatile String proxyAuthUser;
  private static volatile String proxyAuthPassword;

  private GatewayHttpSupport() {}

  static final class Config {
    final SSLContext sslContext; // null => JVM defaults
    final Proxy proxy; // null => JVM default proxy selector
    final String proxyUsername;
    final String proxyPassword;

    Config(SSLContext sslContext, Proxy proxy, String proxyUsername, String proxyPassword) {
      this.sslContext = sslContext;
      this.proxy = proxy;
      this.proxyUsername = proxyUsername;
      this.proxyPassword = proxyPassword;
    }
  }

  /**
   * @param getProp (name, default) -> value; typically {@code CredentialResolver::getMidProp}
   */
  static Config load(BiFunction<String, String, String> getProp) throws Exception {
    SSLContext ssl = buildSslContext(resolveCaPem(getProp));
    ProxySettings proxySettings = resolveProxy(getProp);
    Proxy proxy = null;
    String user = null;
    String pass = null;
    if (proxySettings != null) {
      proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxySettings.host, proxySettings.port));
      user = proxySettings.username;
      pass = proxySettings.password;
      if (user != null && !user.isEmpty()) {
        installProxyAuthenticator(user, pass == null ? "" : pass);
      }
    }
    return new Config(ssl, proxy, user, pass);
  }

  static void applyTls(HttpsURLConnection conn, SSLContext sslContext) {
    if (sslContext != null) {
      conn.setSSLSocketFactory(sslContext.getSocketFactory());
      // Keep the JVM default HostnameVerifier — never disable hostname checks.
    }
  }

  static String resolveCaPem(BiFunction<String, String, String> getProp) throws IOException {
    String inline = trimToNull(getProp.apply(PROP_CA, null));
    if (inline == null) {
      inline = trimToNull(envOr("AKEYLESS_CA", null));
    }
    if (inline != null) {
      return inline;
    }
    String file = trimToNull(getProp.apply(PROP_CA_FILE, null));
    if (file == null) {
      file = trimToNull(envOr("AKEYLESS_CA_FILE", null));
    }
    if (file != null) {
      return Files.readString(Path.of(file), StandardCharsets.UTF_8);
    }
    return null;
  }

  static SSLContext buildSslContext(String caPem) throws Exception {
    if (caPem == null || caPem.isBlank()) {
      return null;
    }
    List<X509Certificate> extras;
    try {
      extras = parsePemCertificates(caPem);
    } catch (Exception e) {
      throw new IllegalArgumentException(
          "Failed to parse certificates from " + PROP_CA + " / " + PROP_CA_FILE
              + ". Provide one or more PEM certificates (-----BEGIN CERTIFICATE-----).",
          e);
    }
    if (extras.isEmpty()) {
      throw new IllegalArgumentException(
          "No X.509 certificates found in " + PROP_CA + " / " + PROP_CA_FILE
              + ". Provide one or more PEM certificates (-----BEGIN CERTIFICATE-----).");
    }

    X509TrustManager defaultTm = defaultTrustManager();
    KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
    trustStore.load(null, null);

    int i = 0;
    for (X509Certificate cert : defaultTm.getAcceptedIssuers()) {
      trustStore.setCertificateEntry("jvm-" + (i++), cert);
    }
    for (X509Certificate cert : extras) {
      trustStore.setCertificateEntry("akeyless-ca-" + (i++), cert);
    }

    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(trustStore);
    SSLContext ctx = SSLContext.getInstance("TLS");
    ctx.init(null, tmf.getTrustManagers(), null);
    return ctx;
  }

  static List<X509Certificate> parsePemCertificates(String pem) throws Exception {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    Collection<? extends Certificate> certs =
        cf.generateCertificates(new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
    List<X509Certificate> out = new ArrayList<>();
    for (Certificate c : certs) {
      if (c instanceof X509Certificate) {
        out.add((X509Certificate) c);
      }
    }
    return out;
  }

  static ProxySettings resolveProxy(BiFunction<String, String, String> getProp) {
    String host = trimToNull(getProp.apply(PROP_PROXY_HOST, null));
    String portRaw = trimToNull(getProp.apply(PROP_PROXY_PORT, null));
    String user = trimToNull(getProp.apply(PROP_PROXY_USERNAME, null));
    String pass = getProp.apply(PROP_PROXY_PASSWORD, null);

    if (host == null) {
      host = trimToNull(envOr("AKEYLESS_PROXY_HOST", null));
      if (portRaw == null) {
        portRaw = trimToNull(envOr("AKEYLESS_PROXY_PORT", null));
      }
      if (user == null) {
        user = trimToNull(envOr("AKEYLESS_PROXY_USERNAME", null));
      }
      if (pass == null || pass.isEmpty()) {
        pass = envOr("AKEYLESS_PROXY_PASSWORD", null);
      }
    }

    if (host == null) {
      // Fall back to MID Server proxy settings when enabled.
      if (!isTruthy(getProp.apply(MID_PROXY_USE, null))) {
        return null;
      }
      host = trimToNull(getProp.apply(MID_PROXY_HOST, null));
      portRaw = trimToNull(getProp.apply(MID_PROXY_PORT, null));
      user = trimToNull(getProp.apply(MID_PROXY_USERNAME, null));
      pass = getProp.apply(MID_PROXY_PASSWORD, null);
    }

    if (host == null) {
      return null;
    }
    int port = 8080;
    if (portRaw != null) {
      try {
        port = Integer.parseInt(portRaw.trim());
      } catch (NumberFormatException e) {
        throw new IllegalArgumentException("Invalid proxy port: " + portRaw);
      }
    }
    if (port <= 0 || port > 65535) {
      throw new IllegalArgumentException("Invalid proxy port: " + port);
    }
    return new ProxySettings(host, port, user, pass);
  }

  static final class ProxySettings {
    final String host;
    final int port;
    final String username;
    final String password;

    ProxySettings(String host, int port, String username, String password) {
      this.host = host;
      this.port = port;
      this.username = username;
      this.password = password;
    }
  }

  private static void installProxyAuthenticator(String user, String password) {
    synchronized (PROXY_AUTH_LOCK) {
      proxyAuthUser = user;
      proxyAuthPassword = password;
      if (!proxyAuthenticatorInstalled) {
        Authenticator.setDefault(new Authenticator() {
          @Override
          protected PasswordAuthentication getPasswordAuthentication() {
            if (getRequestorType() != RequestorType.PROXY) {
              return null;
            }
            String u = proxyAuthUser;
            if (u == null || u.isEmpty()) {
              return null;
            }
            String p = proxyAuthPassword;
            return new PasswordAuthentication(u, p == null ? new char[0] : p.toCharArray());
          }
        });
        proxyAuthenticatorInstalled = true;
      }
    }
  }

  private static X509TrustManager defaultTrustManager() throws Exception {
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init((KeyStore) null);
    for (TrustManager tm : tmf.getTrustManagers()) {
      if (tm instanceof X509TrustManager) {
        return (X509TrustManager) tm;
      }
    }
    throw new IllegalStateException("No default X509TrustManager available");
  }

  private static boolean isTruthy(String v) {
    if (v == null) {
      return false;
    }
    String s = v.trim().toLowerCase(Locale.ROOT);
    return "true".equals(s) || "1".equals(s) || "yes".equals(s);
  }

  private static String trimToNull(String v) {
    if (v == null) {
      return null;
    }
    String t = v.trim();
    return t.isEmpty() ? null : t;
  }

  private static String envOr(String name, String dflt) {
    String v = System.getProperty(name);
    if (v == null || v.isEmpty()) {
      v = System.getenv(name);
    }
    return v == null || v.isEmpty() ? dflt : v;
  }

  /** Test-only: clear proxy authenticator state. */
  static void resetProxyAuthenticatorForTests() {
    synchronized (PROXY_AUTH_LOCK) {
      proxyAuthUser = null;
      proxyAuthPassword = null;
      // Authenticator.setDefault(null) clears; safe in unit tests
      Authenticator.setDefault(null);
      proxyAuthenticatorInstalled = false;
    }
  }
}
