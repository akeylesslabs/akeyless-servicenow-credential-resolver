package com.snc.discovery;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.jr.ob.JSON;
import io.akeyless.cloudid.CloudIdProvider;
import io.akeyless.cloudid.CloudProviderFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLHandshakeException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class CredentialResolver {
  private static final AkeylessFileLogger FILE_LOG = AkeylessFileLogger.getInstance();
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

  /**
   * Second-pass JSON parse for secrets that embed PEM / certs / SSH keys with raw newlines inside quoted
   * strings (invalid for strict JSON). Enabled only when {@code -----BEGIN} is present after strict parse fails.
   */
  private static final JSON JSON_LENIENT_PEM = JSON.builder(
      JsonFactory.builder()
          .enable(JsonReadFeature.ALLOW_UNESCAPED_CONTROL_CHARS)
          .build()
  ).build();

  // -------- Testable HTTP transport seam --------
  interface HttpTransport {
    Map<String, Object> postJson(String url, Object payload) throws Exception;
  }

  private static class DefaultHttpTransport implements HttpTransport {
    @Override
    public Map<String, Object> postJson(String url, Object payload) throws Exception {
      byte[] body = payload == null ? new byte[0] : JSON_STD.asBytes(payload);
      GatewayHttpSupport.Config httpCfg = GatewayHttpSupport.load(CredentialResolver::getMidProp);
      URL target = new URL(url);
      HttpURLConnection conn = httpCfg.proxy != null
          ? (HttpURLConnection) target.openConnection(httpCfg.proxy)
          : (HttpURLConnection) target.openConnection();
      try {
        if (conn instanceof HttpsURLConnection) {
          GatewayHttpSupport.applyTls((HttpsURLConnection) conn, httpCfg.sslContext);
        }
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setConnectTimeout(15_000);
        conn.setReadTimeout(30_000);
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("Accept", "application/json");
        // Request-scoped Basic proxy auth (supplements host/port-scoped Authenticator for CONNECT).
        if (httpCfg.proxyUsername != null && !httpCfg.proxyUsername.isEmpty()) {
          String cred = httpCfg.proxyUsername + ":"
              + (httpCfg.proxyPassword == null ? "" : httpCfg.proxyPassword);
          conn.setRequestProperty(
              "Proxy-Authorization",
              "Basic " + Base64.getEncoder().encodeToString(cred.getBytes(StandardCharsets.UTF_8)));
        }
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
          // Non-2xx: read raw text so HTML/plain proxy/Gateway errors still yield "HTTP <code>"
          // and preserve /v2 -> legacy endpoint fallback.
          if (code < 200 || code >= 300) {
            String bodyStr = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            throw new AkeylessCredentialResolverException("HTTP " + code + " from " + url + ": " + bodyStr);
          }
          Object resp = JSON_STD.anyFrom(is);
          if (resp == null) {
            throw new AkeylessCredentialResolverException("Unexpected null JSON response from " + url);
          }
          if (!(resp instanceof Map)) {
            throw new AkeylessCredentialResolverException(
                "Unexpected response type from " + url + ": " + resp.getClass().getSimpleName());
          }
          @SuppressWarnings("unchecked")
          Map<String, Object> map = (Map<String, Object>) resp;
          return map;
        }
      } catch (SSLHandshakeException e) {
        throw new AkeylessCredentialResolverException(
            "TLS handshake failed for " + url + ": " + e.getMessage()
                + ". If the Gateway uses a private or self-signed CA, set MID property '"
                + GatewayHttpSupport.PROP_CA + "' (PEM) or '" + GatewayHttpSupport.PROP_CA_FILE
                + "'. The hostname in ext.cred.akeyless.gw_url must match a certificate SAN/CN"
                + " (hostname verification is always enabled).",
            e);
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

  // -------- Auth token cache (JVM-wide, refreshed on auth errors) --------
  private static final Object TOKEN_CACHE_LOCK = new Object();
  private static volatile String cachedToken;
  private static volatile String cachedGwUrl;

  @FunctionalInterface
  private interface TokenOperation<T> {
    T apply(String token) throws Exception;
  }

  protected static void invalidateTokenCache() {
    synchronized (TOKEN_CACHE_LOCK) {
      cachedToken = null;
      cachedGwUrl = null;
    }
  }

  private String getCachedOrAuthenticateToken(String gwUrl) throws Exception {
    synchronized (TOKEN_CACHE_LOCK) {
      if (cachedToken != null && gwUrl.equals(cachedGwUrl)) {
        return cachedToken;
      }
      String token = authenticateAkeyless(gwUrl);
      cachedToken = token;
      cachedGwUrl = gwUrl;
      return token;
    }
  }

  private static boolean isAuthenticationError(AkeylessCredentialResolverException e) {
    return getHttpStatusCode(e) == 401;
  }

  private static int getHttpStatusCode(AkeylessCredentialResolverException e) {
    String msg = e.getMessage();
    if (msg == null || !msg.startsWith("HTTP ")) {
      return -1;
    }
    int fromIdx = msg.indexOf(" from ", 5);
    if (fromIdx < 0) {
      return -1;
    }
    try {
      return Integer.parseInt(msg.substring(5, fromIdx));
    } catch (NumberFormatException ex) {
      return -1;
    }
  }

  private <T> T withCachedToken(String gwUrl, TokenOperation<T> operation) throws Exception {
    String token = getCachedOrAuthenticateToken(gwUrl);
    try {
      return operation.apply(token);
    } catch (AkeylessCredentialResolverException e) {
      if (!isAuthenticationError(e)) {
        throw e;
      }
      logInfo("Akeyless resolver: cached token rejected, re-authenticating");
      invalidateTokenCache();
      String freshToken = getCachedOrAuthenticateToken(gwUrl);
      return operation.apply(freshToken);
    }
  }

  public Map<String, String> resolve(Map<String, String> args) throws Exception {
    logInfo("Akeyless resolver: resolving secret for args " + args);
    try {
      // --- 1) Inputs from SN
      final String snType = must(args.get(ARG_TYPE), "Missing arg 'type'");
      final String secretPath = must(args.get(ARG_ID), "Missing arg 'id' (use your Akeyless secret path)");
      final String host = args.get(ARG_IP);

      // --- 2) MID properties (all set from the ServiceNow UI)
      // Optional mapping overrides
      final String fUser = getMidProp("ext.cred.akeyless.map.username", "username");
      final String fPass = getMidProp("ext.cred.akeyless.map.password", "password");
      final String fPk   = getMidProp("ext.cred.akeyless.map.private_key", "private_key");
      final String fPhr  = getMidProp("ext.cred.akeyless.map.passphrase", "passphrase");

      // --- 4) Fetch value
      String raw = getSecretValue(secretPath, host); // String or JSON (for dynamic/structured secrets)

      // --- 5) Map to SN credential fields
      Map<String,String> out = mapToServiceNow(snType, raw, fUser, fPass, fPk, fPhr);

      logInfo("Akeyless resolver: resolved secret for path '" + secretPath + "' -> fields " + out.keySet());
      return out;
    } catch (Exception e) {
      logError("Akeyless resolver: resolve failed", e);
      throw e;
    }
  }
  private static final String ITEM_TYPE_STATIC = "STATIC_SECRET";
  private static final String ITEM_TYPE_ROTATED = "ROTATED_SECRET";
  private static final String ITEM_TYPE_DYNAMIC = "DYNAMIC_SECRET";

  /**
   * Auth, describe-item, then fetch secret payload as a string (plain or JSON) for {@link #mapToServiceNow}.
   */
  private String getSecretValue(String secretPath, String host) throws Exception {
    String gwUrl = getMidProp("ext.cred.akeyless.gw_url", envOr("AKEYLESS_GW_URL", "https://api.akeyless.io"));
    String itemType = withCachedToken(gwUrl, token -> describeItemType(gwUrl, token, secretPath));
    logInfo("Akeyless resolver: described item '" + secretPath + "' as type '" + itemType + "'");
    String normalizedType = itemType == null ? "" : itemType.trim();
    if (itemTypeEquals(normalizedType, ITEM_TYPE_STATIC)) {
      return withCachedToken(gwUrl, token -> getStaticSecretPayload(gwUrl, token, secretPath));
    }
    if (itemTypeEquals(normalizedType, ITEM_TYPE_ROTATED)) {
      return withCachedToken(gwUrl, token -> getRotatedSecretPayload(gwUrl, token, secretPath, host));
    }
    if (itemTypeEquals(normalizedType, ITEM_TYPE_DYNAMIC)) {
      return withCachedToken(gwUrl, token -> getDynamicSecretPayload(gwUrl, token, secretPath));
    }
    throw new AkeylessCredentialResolverException(
        "Unsupported Akeyless item_type '" + itemType + "' for name: " + secretPath);
  }

  private static boolean itemTypeEquals(String actual, String expected) {
    return expected.equalsIgnoreCase(actual);
  }

  private String authenticateAkeyless(String gwUrl) throws Exception {
    String accessTypeRaw = getMidProp("ext.cred.akeyless.access_type", envOr("AKEYLESS_ACCESS_TYPE", "access_key"));
    String accessType = normalizeAccessType(accessTypeRaw);
    String accessId = must(getMidProp("ext.cred.akeyless.access_id", envOr("AKEYLESS_ACCESS_ID", null)),
            "Missing Akeyless access id: set MID 'ext.cred.akeyless.access_id' or env 'AKEYLESS_ACCESS_ID'");
    String accessKey = getMidProp("ext.cred.akeyless.access_key", envOr("AKEYLESS_ACCESS_KEY", null));
    String uidTokenFile = getMidProp("ext.cred.akeyless.uid_token_file", envOr("AKEYLESS_UID_TOKEN_FILE", null));
    String uidTokenInline = getMidProp("ext.cred.akeyless.uid_token", envOr("AKEYLESS_UID_TOKEN", null));
    String uidToken = resolveUidToken(uidTokenFile, uidTokenInline);
    String certData = getMidProp("ext.cred.akeyless.cert_data", envOr("AKEYLESS_CERT_DATA", null));
    String keyData = getMidProp("ext.cred.akeyless.key_data", envOr("AKEYLESS_KEY_DATA", null));
    String certFileName = getMidProp("ext.cred.akeyless.cert_file_name", envOr("AKEYLESS_CERT_FILE_NAME", null));
    String keyFileName = getMidProp("ext.cred.akeyless.key_file_name", envOr("AKEYLESS_KEY_FILE_NAME", null));
    Map<String, Object> authReq = new HashMap<>();
    switch (accessType) {
      case "access_key":
        authReq.put("access-type", "access_key");
        authReq.put("access-id", accessId);
        authReq.put("access-key", must(accessKey,
            "Missing Akeyless access key: set MID 'ext.cred.akeyless.access_key' or env 'AKEYLESS_ACCESS_KEY'"));
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
      case "universal_identity":
        authReq.put("access-type", "universal_identity");
        authReq.put("access-id", accessId);
        authReq.put("uid-token", must(uidToken,
            "Missing Akeyless UID token: set MID 'ext.cred.akeyless.uid_token_file' (preferred) or "
                + "'ext.cred.akeyless.uid_token' (fallback), or env 'AKEYLESS_UID_TOKEN_FILE' / 'AKEYLESS_UID_TOKEN'"));
        break;
      case "cert":
        authReq.put("access-type", "certificate");
        authReq.put("access-id", accessId);
        authReq.put("cert-data", base64(resolvePemMaterial(
            "certificate",
            certData,
            certFileName,
            "ext.cred.akeyless.cert_data",
            "ext.cred.akeyless.cert_file_name"
        )));
        authReq.put("key-data", base64(resolvePemMaterial(
            "private key",
            keyData,
            keyFileName,
            "ext.cred.akeyless.key_data",
            "ext.cred.akeyless.key_file_name"
        )));
        break;
      default:
        throw new IllegalArgumentException("Unsupported access type '" + accessTypeRaw
            + "'. Supported: access_key, aws_iam, azure_ad, gcp, universal_identity (uid), cert (certificate)");
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
    logInfo("Akeyless resolver: authenticated via access_type '" + accessType + "'");
    return token;
  }

  private String describeItemType(String gwUrl, String token, String secretPath) throws Exception {
    Map<String, Object> req = new HashMap<>();
    req.put("token", token);
    req.put("name", secretPath);
    req.put("accessibility", "regular");
    req.put("bastion-details", false);
    req.put("der-certificate-format", false);
    req.put("gateway-details", false);
    req.put("item-custom-fields-details", false);
    req.put("json", false);
    req.put("services-details", false);
    req.put("show-versions", false);
    Map<String, Object> resp;
    try {
      resp = httpPostJson(joinUrl(gwUrl, "/v2/describe-item"), req);
    } catch (AkeylessCredentialResolverException e) {
      if (e.getMessage() != null && e.getMessage().contains("HTTP 404")) {
        resp = httpPostJson(joinUrl(gwUrl, "/describe-item"), req);
      } else {
        throw e;
      }
    }
    String itemType = asString(resp.get("item_type"));
    if (itemType == null || itemType.isEmpty()) {
      throw new AkeylessCredentialResolverException("describe-item returned no item_type for name: " + secretPath);
    }
    return itemType;
  }

  private String getStaticSecretPayload(String gwUrl, String token, String secretPath) throws Exception {
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

  private String getDynamicSecretPayload(String gwUrl, String token, String secretPath) throws Exception {
    Map<String, Object> dsvReq = new HashMap<>();
    dsvReq.put("token", token);
    dsvReq.put("name", secretPath);
    dsvReq.put("json", true);
    dsvReq.put("timeout", 15);
    Map<String, Object> dsvResp;
    try {
      dsvResp = httpPostJson(joinUrl(gwUrl, "/v2/get-dynamic-secret-value"), dsvReq);
    } catch (AkeylessCredentialResolverException e) {
      if (e.getMessage() != null && e.getMessage().contains("HTTP 404")) {
        dsvResp = httpPostJson(joinUrl(gwUrl, "/get-dynamic-secret-value"), dsvReq);
      } else {
        throw e;
      }
    }
    Map<String, Object> norm = new HashMap<>(dsvResp);
    if (norm.containsKey("user") && !norm.containsKey("username")) {
      norm.put("username", norm.get("user"));
    }
    return JSON_STD.asString(norm);
  }

  private String getRotatedSecretPayload(String gwUrl, String token, String secretPath, String host) throws Exception {
    Map<String, Object> req = new HashMap<>();
    req.put("token", token);
    // API variants: some use "name", others use "names" (string)
    req.put("name", secretPath);
    req.put("names", secretPath);
    req.put("json", true);
    req.put("ignore-cache", getMidProp("ext.cred.akeyless.ignore_cache", "false"));
    if (host != null && !host.isEmpty()) {
      req.put("host", host);
    }

    Map<String, Object> resp;
    try {
      resp = httpPostJson(joinUrl(gwUrl, "/v2/get-rotated-secret-value"), req);
    } catch (AkeylessCredentialResolverException e) {
      if (e.getMessage() != null && e.getMessage().contains("HTTP 404")) {
        try {
          resp = httpPostJson(joinUrl(gwUrl, "/get-rotated-secret-value"), req);
        } catch (AkeylessCredentialResolverException e2) {
          if (e2.getMessage() != null && e2.getMessage().contains("HTTP 404")) {
            resp = httpPostJson(joinUrl(gwUrl, "/rotated-secret-get-value"), req);
          } else {
            throw e2;
          }
        }
      } else {
        throw e;
      }
    }

    Object value = resp.get("value");
    if (value == null && resp.containsKey(secretPath)) {
      value = resp.get(secretPath);
    }
    if (value == null) {
      throw new AkeylessCredentialResolverException("Rotated secret value not found for name: " + secretPath);
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

  private static String normalizeAccessType(String raw) {
    if (raw == null) {
      return "access_key";
    }
    String v = raw.trim().toLowerCase();
    if ("uid".equals(v)) {
      return "universal_identity";
    }
    if ("certificate".equals(v)) {
      return "cert";
    }
    return v;
  }

  private static String resolveUidToken(String uidTokenFile, String uidTokenInline) {
    if (uidTokenFile != null && !uidTokenFile.isEmpty()) {
      try {
        String tokenFromFile;
        try (var lines = Files.lines(Path.of(uidTokenFile), StandardCharsets.UTF_8)) {
          tokenFromFile = lines
              .map(String::trim)
              .filter(line -> !line.isEmpty())
              .findFirst()
              .orElse(null);
        }
        if (tokenFromFile != null && !tokenFromFile.isEmpty()) {
          return tokenFromFile;
        }
        logWarn("UID token file '" + uidTokenFile + "' is empty; falling back to inline uid_token");
      } catch (IOException e) {
        logWarn("Unable to read UID token file '" + uidTokenFile + "'; falling back to inline uid_token", e);
      }
    }
    return uidTokenInline;
  }

  private static byte[] resolvePemMaterial(
      String materialName,
      String inlineData,
      String fileName,
      String inlinePropName,
      String filePropName
  ) {
    if (inlineData != null && !inlineData.isEmpty()) {
      return inlineData.getBytes(StandardCharsets.UTF_8);
    }
    if (fileName != null && !fileName.isEmpty()) {
      try {
        return Files.readAllBytes(Path.of(fileName));
      } catch (IOException e) {
        throw new IllegalArgumentException("Unable to read " + materialName + " file '" + fileName + "'", e);
      }
    }
    throw new IllegalArgumentException("Missing Akeyless " + materialName + " material: set MID '"
        + inlinePropName + "'/'" + filePropName + "' or env '"
        + inlinePropName.replace('.', '_').toUpperCase() + "'/'"
        + filePropName.replace('.', '_').toUpperCase() + "'");
  }

  private static String base64(byte[] data) {
    return Base64.getEncoder().encodeToString(data);
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
      out.put(VAL_PSWD, raw);
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
        putIf(out, VAL_USER, node, fUser);
        putIf(out, VAL_PSWD, node, fPass);
        break;

      case "ssh_private_key":
      case "sn_cfg_ansible": 
	    case "sn_disco_certmgmt_certificate_ca":
	    case "cfg_chef_credentials":
	    case "infoblox": 
      case "api_key":
        putIf(out, VAL_USER, node, fUser);
        putIf(out, VAL_PKEY, node, fPk);
        putIf(out, VAL_PASSPHRASE, node, fPhr);
        break;

      case "snmpv3":
        // Example JSON:
        // {"username":"u","auth_protocol":"SHA","auth_key":"...","privacy_protocol":"AES","privacy_key":"..."}
        putIf(out, VAL_USER,         node, fUser);
        putIf(out, VAL_AUTHPROTO,    node, "auth_protocol");
        putIf(out, VAL_AUTHKEY,      node, "auth_key");
        putIf(out, VAL_PRIVPROTO,    node, "privacy_protocol");
        putIf(out, VAL_PRIVKEY,      node, "privacy_key");
        break;

      default:
        // Best effort for custom credential types: username/password if present
        putIf(out, VAL_USER, node, fUser);
        putIf(out, VAL_PSWD, node, fPass);
    }
    return out;
  }

  private static void putIf(Map<String,String> out, String snField, Map<String, Object> node,  String jsonField) {
    Object v = node.get(jsonField);
    if (v != null) out.put(snField, asString(v));
  }

  /**
   * Parse JSON text. If strict parsing fails and the text looks like it contains PEM/certificate material,
   * retry with a lenient factory that allows unescaped control characters inside strings.
   */
  private static Object tryParseJson(String raw) {
    if (raw == null) {
      return null;
    }
    String trimmed = raw.trim();
    if (trimmed.startsWith("\uFEFF")) {
      trimmed = trimmed.substring(1).trim();
    }
    if (trimmed.isEmpty()) {
      return null;
    }
    Object strict = parseJsonWith(JSON_STD, trimmed);
    if (strict != null) {
      return strict;
    }
    if (containsPemOrCertificateMarker(trimmed)) {
      return parseJsonWith(JSON_LENIENT_PEM, trimmed);
    }
    return null;
  }

  private static boolean containsPemOrCertificateMarker(String s) {
    return s.indexOf("-----BEGIN") >= 0;
  }

  private static Object parseJsonWith(JSON json, String raw) {
    byte[] utf8 = raw.getBytes(StandardCharsets.UTF_8);
    try (InputStream in = new ByteArrayInputStream(utf8)) {
      return json.anyFrom(in);
    } catch (Exception e) {
      return null;
    }
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

  private static void logInfo(String message) {
    FILE_LOG.info(message);
  }

  private static void logWarn(String message) {
    FILE_LOG.warn(message);
  }

  private static void logWarn(String message, Throwable t) {
    FILE_LOG.warn(message, t);
  }

  private static void logError(String message, Throwable t) {
    FILE_LOG.error(message, t);
  }

  // Optional (some samples include this; harmless if unused)
  public String getVersion() { return "1.0"; }

  public static void main(String[] args) throws Exception {
    //setPropIfMissing("AKEYLESS_GW_URL", "http://localhost:8080");
    setPropIfMissing("AKEYLESS_ACCESS_TYPE", "universal_identity");
    setPropIfMissing("AKEYLESS_ACCESS_ID", "p-qwj5c3lzu2nh");
    setPropIfMissing("AKEYLESS_UID_TOKEN", "token");
    
    CredentialResolver cr = new CredentialResolver();
    HashMap<String, String> input = new HashMap<>();
    input.put(CredentialResolver.ARG_ID, "alexey1");
    //input.put(CredentialResolver.ARG_ID, "LDAPSAlexey");
    //input.put(CredentialResolver.ARG_ID, "LDAPSAlexeyRotated");
    //input.put(CredentialResolver.ARG_ID, "WindowsRotated");
    //input.put(CredentialResolver.ARG_ID, "SSHRotatedSecret");
    //input.put(CredentialResolver.ARG_ID, "SSHKeyRotatedSecret");
    //input.put(CredentialResolver.ARG_ID, "RDPDynamic");
    input.put(CredentialResolver.ARG_TYPE, "ssh_password");
    //input.put(CredentialResolver.ARG_TYPE, "ssh_password");
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

