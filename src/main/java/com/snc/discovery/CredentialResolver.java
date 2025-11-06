package com.snc.discovery;

import com.fasterxml.jackson.jr.ob.JSON;
import io.akeyless.cloudid.CloudIdProvider;
import io.akeyless.cloudid.CloudProviderFactory;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.File;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class CredentialResolver {
  private static final Log LOG = LogFactory.getLog(CredentialResolver.class);
  public static final String ARG_ID = "id"; // the string identifier as configured on the ServiceNow instance
  public static final String ARG_IP = "ip"; // a dotted-form string IPv4 address (like "10.22.231.12") of the target system
  public static final String ARG_TYPE = "type"; // the string type (ssh, snmp, etc.) of credential
  public static final String ARG_MID = "mid"; // the MID server making the request

  // Keys that may optionally be populated on resolve's output Map
  public static final String VAL_USER = "user"; // the string username for the credential
  public static final String VAL_PSWD = "pswd"; // the string password for the credential
  public static final String VAL_PASSPHRASE = "passphrase"; // the string pass phrase for the credential
  public static final String VAL_PKEY = "pkey"; // the string private key for the credential
  public static final String VAL_AUTHPROTO = "authprotocol"; // the string authentication protocol for the credential
  public static final String VAL_AUTHKEY = "authkey"; // the string authentication key for the credential
  public static final String VAL_PRIVPROTO = "privprotocol"; // the string privacy protocol for the credential
  public static final String VAL_PRIVKEY = "privkey"; // the string privacy key for the credential

  private static final JSON JSON_STD = JSON.std;

  // -------- Testable HTTP transport seam --------
  interface HttpTransport {
    Map<String, Object> postJson(String url, Object payload) throws Exception;
  }

  private static class DefaultHttpTransport implements HttpTransport {
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
          throw new AkeylessCredentialResolverException("Unexpected response type from " + url + ": " + resp.getClass().getSimpleName());
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> map = (Map<String, Object>) resp;
        return map;
      } finally {
        conn.disconnect();
      }
    }
  }

  private static HttpTransport HTTP = new DefaultHttpTransport();

  static void setHttpTransport(HttpTransport transport) {
    HTTP = transport != null ? transport : new DefaultHttpTransport();
  }

  static void resetHttpTransport() {
    HTTP = new DefaultHttpTransport();
  }

  public Map<String, String> resolve(Map<String, String> args) throws Exception {
    LOG.info("Akeyless resolver: resolving secret for args " + args);
    
    // --- 1) Inputs from SN
    final String snType = must(args.get(ARG_TYPE), "Missing arg 'type'");
    final String secretPath = must(args.get(ARG_ID), "Missing arg 'id' (use your Akeyless secret path)");

    // --- 2) MID properties (all set from the ServiceNow UI)
    // Optional mapping overrides
    final String fUser = getMidProp("ext.cred.akeyless.map.username", "username");
    final String fPass = getMidProp("ext.cred.akeyless.map.password", "password");
    final String fPk   = getMidProp("ext.cred.akeyless.map.private_key", "private_key");
    final String fPhr  = getMidProp("ext.cred.akeyless.map.passphrase", "passphrase");

  

    // --- 4) Fetch value
    String raw = getSecretValue(secretPath); // String or JSON (for dynamic/structured secrets)

    // --- 5) Map to SN credential fields
    Map<String,String> out = mapToServiceNow(snType, raw, fUser, fPass, fPk, fPhr);

    LOG.info("Akeyless resolver: resolved secret for path '" + secretPath + "' -> fields " + out.keySet());
    return out;
  }
  private String getSecretValue(String secretPath) throws Exception {
    String gwUrl = getMidProp("ext.cred.akeyless.gw_url", envOr("AKEYLESS_GW_URL", "https://api.akeyless.io"));
    String accessType = getMidProp("ext.cred.akeyless.access_type", envOr("AKEYLESS_ACCESS_TYPE", "access_key"));
    String accessId = must(getMidProp("ext.cred.akeyless.access_id", envOr("AKEYLESS_ACCESS_ID", null)),
            "Missing Akeyless access id: set MID 'ext.cred.akeyless.access_id' or env 'AKEYLESS_ACCESS_ID'");
    String accessKey = getMidProp("ext.cred.akeyless.access_key", envOr("AKEYLESS_ACCESS_KEY", null));

    // --- Auth
    Map<String, Object> authReq = new HashMap<>();
    switch (accessType) {
      case "access_key":
        authReq.put("access-type", "access_key");
        authReq.put("access-id", accessId);
        authReq.put("access-key", accessKey);
        break;
      case "aws_iam":
        authReq.put("access-type", "aws_iam");
        authReq.put("access-id", accessId);
        break;
      case "azure_ad":
        authReq.put("access-type", "azure_ad");
        authReq.put("access-id", accessId);
        break;
      case "gcp":
        authReq.put("access-type", "gcp");
        authReq.put("access-id", accessId);
        break;
      default:
        throw new IllegalArgumentException("Unsupported access type '" + accessType + "'. Supported: access_key, aws_iam, azure_ad, gcp");
    } 
    if (isCloudIdType(accessType)) {
      CloudIdProvider provider = getCloudIdProvider((String) authReq.get("access-type"));
      String cloudId = provider.getCloudId();
      authReq.put("cloud-id", cloudId);
    }
    authReq.put("json", true);

    Map<String, Object> authResp;
    try {
      authResp = httpPostJson(joinUrl(gwUrl, "/v2/auth"), authReq);
    } catch (AkeylessCredentialResolverException e) {
      if (e.getMessage() != null && e.getMessage().contains("HTTP 404")) {
        authResp = httpPostJson(joinUrl(gwUrl, "/auth"), authReq);
      } else {
        throw e;
      }
    }
    String token = asString(authResp.get("token"));
    if (token == null || token.isEmpty()) {
      throw new AkeylessCredentialResolverException("Akeyless auth returned empty token");
    }

    // --- Get secret value
    Map<String, Object> gsvReq = new HashMap<>();
    gsvReq.put("token", token);
    gsvReq.put("name", secretPath);
    gsvReq.put("names", Collections.singletonList(secretPath));
    gsvReq.put("json", true);
    Map<String, Object> gsvResp;
    try {
      gsvResp = httpPostJson(joinUrl(gwUrl, "/v2/get-secret-value"), gsvReq);
    } catch (AkeylessCredentialResolverException e) {
      if (e.getMessage() != null && e.getMessage().contains("HTTP 404")) {
        gsvResp = httpPostJson(joinUrl(gwUrl, "/get-secret-value"), gsvReq);
      } else {
        throw e;
      }
    }

    Object secretsObj = gsvResp.containsKey("secrets") ? gsvResp.get("secrets") : gsvResp;
    Object value = null;
    if (secretsObj instanceof Map) {
      value = ((Map<?, ?>) secretsObj).get(secretPath);
    }
    if (value == null) {
      throw new AkeylessCredentialResolverException("Secret value not found for name: " + secretPath);
    }
    if (isContainer(value)) {
      return JSON_STD.asString(value);
    }
    String v = asString(value);
    return v != null ? v : "";
  }

  private static String envOr(String name, String dflt) {
    String v = System.getProperty(name);
    if (v == null || v.isEmpty()) v = System.getenv(name);
    return v == null || v.isEmpty() ? dflt : v;
  }

  private static String joinUrl(String base, String path) {
    if (base == null || base.isEmpty()) return path;
    boolean bSlash = base.endsWith("/");
    boolean pSlash = path.startsWith("/");
    if (bSlash && pSlash) return base + path.substring(1);
    if (!bSlash && !pSlash) return base + "/" + path;
    return base + path;
  }

  private static Map<String, Object> httpPostJson(String url, Object payload) throws Exception {
    return HTTP.postJson(url, payload);
  }


  // -------- Mapping helpers --------

  private Map<String,String> mapToServiceNow(
      String snType, String raw, String fUser, String fPass, String fPk, String fPhr
  ) throws Exception {
    Map<String,String> out = new HashMap<>();
    if (raw == null || raw.isEmpty()) return out;

    Object parsed = tryParseJson(raw);
    if (!(parsed instanceof Map)) {
      // Treat raw value as a single secret (password/token)
      out.put("password", raw);
      return out;
    }
    @SuppressWarnings("unchecked")
    Map<String, Object> node = (Map<String, Object>) parsed;

    String type = snType.toLowerCase();

    switch (type) {
      case "windows":
      case "basic":
      case "ssh_password":
      case "vmware":
      case "jdbc":
      case "jms":
        putIf(out, "username", node, fUser);
        putIf(out, "password", node, fPass);
        break;

      case "ssh_private_key":
        putIf(out, "username",    node, fUser);
        putIf(out, "private_key", node, fPk);
        putIf(out, "passphrase",  node, fPhr);
        break;

      case "snmpv3":
        // Example JSON:
        // {"username":"u","auth_protocol":"SHA","auth_key":"...","privacy_protocol":"AES","privacy_key":"..."}
        putIf(out, "username",         node, fUser);
        putIf(out, "auth-protocol",    node, "auth_protocol");
        putIf(out, "auth-key",         node, "auth_key");
        putIf(out, "privacy-protocol", node, "privacy_protocol");
        putIf(out, "privacy-key",      node, "privacy_key");
        break;

      default:
        // Best effort for custom credential types: username/password if present
        putIf(out, "username", node, fUser);
        putIf(out, "password", node, fPass);
    }
    return out;
  }

  private static void putIf(Map<String,String> out, String snField, Map<String, Object> node,  String jsonField) {
    Object v = node.get(jsonField);
    if (v != null) out.put(snField, asString(v));
  }

  private static Object tryParseJson(String raw)  {
    try { return JSON_STD.anyFrom(raw); }
    catch (Exception ignore) { return null; }
  }

  private static boolean isContainer(Object v) {
    return v instanceof Map || v instanceof Iterable || (v != null && v.getClass().isArray());
  }

  private static String asString(Object v) {
    if (v == null) return null;
    if (v instanceof String) return (String) v;
    if (v instanceof Number || v instanceof Boolean) return String.valueOf(v);
    try {
      return JSON_STD.asString(v);
    } catch (Exception e) {
      return String.valueOf(v);
    }
  }

  private static boolean isCloudIdType(String type) {
    if (type == null) return false;
    String t = type.toLowerCase();
    return "aws_iam".equals(t) || "azure_ad".equals(t) || "gcp".equals(t);
  }

  // Seam for testing CloudID provider
  protected CloudIdProvider getCloudIdProvider(String type) {
    return CloudProviderFactory.getCloudIdProvider(type);
  }

  // -------- MID property helpers --------


private static String getMidProp(String name, String dflt) {
  try {
    Class<?> c = Class.forName("com.service_now.mid.services.Config");
    Object cfg = c.getMethod("get").invoke(null); // Config.get()
    String v = (String) c.getMethod("getProperty", String.class).invoke(cfg, name);
    if (v == null) v = (String) c.getMethod("getProperty", String.class).invoke(cfg, "mid.property." + name);
    return v != null ? v : dflt;
  } catch (Throwable t) {
    // when running unit tests outside the MID, fall back to sysprops/env
    String v = System.getProperty(name);
    if (v == null) v = System.getenv(name.replace('.', '_').toUpperCase());
    return v != null ? v : dflt;
  }
}

  // -------- settings.xml support (optional) --------
  
  private static String must(String val, String msg) {
    if (val == null || val.isEmpty()) throw new IllegalArgumentException(msg);
    return val;
  }

  // Optional (some samples include this; harmless if unused)
  public String getVersion() { return "1.0"; }

  public static void main(String[] args) throws Exception {
    setPropIfMissing("AKEYLESS_GW_URL", "https://api.akeyless.io");
    setPropIfMissing("AKEYLESS_ACCESS_TYPE", "aws_iam");
    setPropIfMissing("AKEYLESS_ACCESS_ID", "p-gjtlpxwh40y8"/* "p-udmwluop9b50"*/);
    //setPropIfMissing("AKEYLESS_ACCESS_KEY", "zZ4UMVAJzRPOorpa9JbKOglpW8CbYik+YPRcM8mH/Zc=");

    CredentialResolver cr = new CredentialResolver();
    HashMap<String, String> input = new HashMap<>();
    input.put(CredentialResolver.ARG_ID, "/aaa");
    input.put(CredentialResolver.ARG_TYPE, "ssh_password");
    Map<String, String> result = cr.resolve(input);
    System.out.println(result);
  }

  private static void setPropIfMissing(String name, String value) {
    boolean envSet = System.getenv(name) != null && !System.getenv(name).isEmpty();
    boolean propSet = System.getProperty(name) != null && !System.getProperty(name).isEmpty();
    if (!envSet && !propSet) {
      System.setProperty(name, value);
    }
  }
}

