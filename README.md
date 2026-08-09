## Akeyless ServiceNow Credential Resolver

### Overview

This project provides a ServiceNow MID external credential resolver that retrieves secrets from Akeyless and maps them to ServiceNow Discovery credential fields. The resolver class is `com.snc.discovery.CredentialResolver`.


### Prerequisites

- ServiceNow instance (Quebec+ recommended) with Discovery and External Credentials enabled.
- MID Server installed and connected to your instance.
- Network access from the MID Server host to the Akeyless Gateway (default `https://api.akeyless.io`, or your private gateway URL). If traffic must go through an HTTP proxy, see [Gateway TLS and HTTP proxy](#gateway-tls-and-http-proxy).
- An Akeyless Access ID and one of the supported authentication methods listed below.

### Supported Akeyless authentication methods

- `access_key`: Access ID + Access Key
- `aws_iam`: CloudID from AWS
- `azure_ad`: CloudID from Azure
- `gcp`: CloudID from GCP
- `universal_identity` (or alias `uid`): Access ID + UID token
- `cert` (or alias `certificate`): Access ID + client certificate/private key material

For cloud-based methods, the resolver detects CloudID using the cloud environment. Ensure the MID Server is running where a CloudID can be obtained (e.g., EC2 with an instance profile, Azure VM with a managed identity, GCP VM with default credentials). For local/dev use, prefer `access_key`.

### Build the JAR

This is a Maven project. Build a versioned JAR so the filename is stable in MID:

```bash
mvn -Drevision=1.0.0 clean package
```

The default build runs **Maven Shade** so the main JAR includes **Jackson JR** (`jackson-jr-objects`, `jackson-core`) and **cloudid-lightweight** (required on the MID). For a thin JAR only: `mvn -Pthin -Drevision=1.0.0 clean package`.

Artifacts:
- With `-Drevision=1.0.0`: `target/akeyless-servicenow-credential-resolver-1.0.0.jar`
- Without a revision property, Maven will produce `akeyless-servicenow-credential-resolver-null.jar`.
- The file in `target/` is the shaded artifact; `target/original-*.jar` is the pre-shade JAR.

### Install the resolver on the MID Server

1) Upload the JAR to the MID Server via the instance UI
- Navigate: MID Server → JAR files → New
- Set a descriptive Name (e.g., `akeyless-servicenow-credential-resolver`)
- Manage Attachments → upload the built JAR from `target/`
- Submit

2) Ensure the MID downloads the JAR
- The MID will sync and place the JAR in its `agent` lib cache.
- If not picked up, restart the MID service to force a sync.

### Configure MID properties (Akeyless parameters)

Set the following MID properties on your instance (System Properties or MID Properties). Property names are case-sensitive.

- `ext.cred.akeyless.gw_url` (string): Akeyless Gateway. Default: `https://api.akeyless.io`
- `ext.cred.akeyless.access_type` (string): One of `access_key`, `aws_iam`, `azure_ad`, `gcp`, `universal_identity`/`uid`, `cert`/`certificate`. Default: `access_key`
- `ext.cred.akeyless.access_id` (string): Your Akeyless Access ID (required)
- `ext.cred.akeyless.access_key` (string): Your Akeyless Access Key (required for `access_key` only)
- `ext.cred.akeyless.uid_token_file` (string): File path on the MID host containing the UID token for `universal_identity` / `uid` (preferred; first non-empty line is used). Supported encodings: plain **ASCII**, **UTF-8** (with or without BOM), **UTF-16** LE/BE with BOM, and BOM-less **UTF-16 LE**. ASCII tokens do not need conversion to UTF-8.
- `ext.cred.akeyless.uid_token` (string): Inline UID token for `universal_identity` / `uid` (fallback when `uid_token_file` is unset or unreadable)
- `ext.cred.akeyless.cert_data` (string): Inline certificate PEM/text for `cert` auth
- `ext.cred.akeyless.key_data` (string): Inline private key PEM/text for `cert` auth
- `ext.cred.akeyless.cert_file_name` (string): File path to certificate PEM on MID host (alternative to `cert_data`)
- `ext.cred.akeyless.key_file_name` (string): File path to private key PEM on MID host (alternative to `key_data`)
- `ext.cred.akeyless.ignore_cache` (boolean string `true|false`): For Rotated Secrets only, pass `ignore-cache` to Akeyless when fetching a rotated value. Default: `false`

TLS trust and HTTP proxy (see [Gateway TLS and HTTP proxy](#gateway-tls-and-http-proxy) for behavior and test flows):
- `ext.cred.akeyless.ca` (string): One or more X.509 CA or self-signed server certificates in PEM format. Merged into the JVM default truststore for Gateway HTTPS calls. Hostname verification stays enabled.
- `ext.cred.akeyless.ca_file` (string): File path on the MID host to a PEM file (alternative to `ext.cred.akeyless.ca`)
- `ext.cred.akeyless.proxy_host` (string): Explicit HTTP proxy host for Akeyless Gateway traffic
- `ext.cred.akeyless.proxy_port` (string): Proxy port (default `8080` when host is set)
- `ext.cred.akeyless.proxy_username` / `ext.cred.akeyless.proxy_password` (optional): Proxy Basic authentication
- If `ext.cred.akeyless.proxy_host` is unset and `mid.proxy.use_proxy=true`, the resolver falls back to `mid.proxy.host` / `mid.proxy.port` / `mid.proxy.username` / `mid.proxy.password`

Optional field mapping overrides for JSON secrets (see Mapping section below):
- `ext.cred.akeyless.map.username` (default: `username`)
- `ext.cred.akeyless.map.password` (default: `password`)
- `ext.cred.akeyless.map.private_key` (default: `private_key`)
- `ext.cred.akeyless.map.passphrase` (default: `passphrase`)

Environment/system property alternatives
- The resolver also supports the following system properties or environment variables:
  - `AKEYLESS_GW_URL`
  - `AKEYLESS_ACCESS_TYPE`
  - `AKEYLESS_ACCESS_ID` (required)
  - `AKEYLESS_ACCESS_KEY` (when using `access_key`)
  - `AKEYLESS_UID_TOKEN_FILE` (preferred file path when using `universal_identity`/`uid`)
  - `AKEYLESS_UID_TOKEN` (inline fallback when using `universal_identity`/`uid`)
  - `AKEYLESS_CERT_DATA` / `AKEYLESS_KEY_DATA` (inline cert auth)
  - `AKEYLESS_CERT_FILE_NAME` / `AKEYLESS_KEY_FILE_NAME` (file-based cert auth)
  - `AKEYLESS_CA` / `AKEYLESS_CA_FILE` (Gateway TLS trust)
  - `AKEYLESS_PROXY_HOST` / `AKEYLESS_PROXY_PORT` / `AKEYLESS_PROXY_USERNAME` / `AKEYLESS_PROXY_PASSWORD`
- As a fallback for any `ext.cred.*` property, an environment variable with the uppercased name and dots replaced by underscores is also read (e.g., `EXT_CRED_AKEYLESS_GW_URL`).
- Precedence: MID properties override environment/system variables.

### Configure MID config.xml (secure local parameters)

Add sensitive Akeyless credentials in the MID’s `config.xml`.

Edit the file on each MID host:

- Linux: `/opt/agent/config.xml`
- Windows: `C:\ServiceNow\agent\config.xml`

Insert your parameters inside the `<parameters>` block:

```xml
<parameters>
    ...
    <!-- Akeyless secure credentials -->
    <parameter name="ext.cred.akeyless.gw_url" value="https://api.akeyless.io" />
    <parameter name="ext.cred.akeyless.access_type" value="access_key" />
    <parameter name="ext.cred.akeyless.access_id" value="AKEYLESS_ACCESS_ID" />
    <parameter name="ext.cred.akeyless.access_key" value="AKEYLESS_SECRET_KEY" secure="true" />
    <!-- Universal Identity example (file-based, preferred) -->
    <!-- <parameter name="ext.cred.akeyless.access_type" value="uid" /> -->
    <!-- <parameter name="ext.cred.akeyless.uid_token_file" value="/opt/agent/creds/uid_token.txt" /> -->
    <!-- On Windows, write the token file as ASCII or UTF-8 without BOM, e.g.:
         [System.IO.File]::WriteAllText($path, $token.Trim(), [System.Text.UTF8Encoding]::new($false))
         Avoid bare Out-File / Set-Content (Windows PowerShell 5 defaults to UTF-16). -->
    <!-- Universal Identity example (inline fallback) -->
    <!-- <parameter name="ext.cred.akeyless.uid_token" value="UID_TOKEN" secure="true" /> -->
    <!-- Certificate auth (inline) -->
    <!-- <parameter name="ext.cred.akeyless.access_type" value="certificate" /> -->
    <!-- <parameter name="ext.cred.akeyless.cert_data" value="-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----" secure="true" /> -->
    <!-- <parameter name="ext.cred.akeyless.key_data" value="-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----" secure="true" /> -->
    <!-- Certificate auth (file-based on MID host) -->
    <!-- <parameter name="ext.cred.akeyless.cert_file_name" value="/opt/agent/certs/client.crt" /> -->
    <!-- <parameter name="ext.cred.akeyless.key_file_name" value="/opt/agent/certs/client.key" /> -->

    <!-- Optional JSON mapping overrides -->
    <parameter name="ext.cred.akeyless.map.username" value="username" />
    <parameter name="ext.cred.akeyless.map.password" value="password" />
    <parameter name="ext.cred.akeyless.map.private_key" value="private_key" />
    <parameter name="ext.cred.akeyless.map.passphrase" value="passphrase" />

    <!-- Private / self-signed Gateway CA (PEM). Prefer ca_file for large PEMs. -->
    <!-- <parameter name="ext.cred.akeyless.ca_file" value="/opt/agent/certs/akeyless-gw-ca.pem" /> -->
    <!-- Or inline: <parameter name="ext.cred.akeyless.ca" value="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----" /> -->

    <!-- Explicit proxy for Akeyless Gateway calls (overrides mid.proxy.* when set) -->
    <!-- <parameter name="ext.cred.akeyless.proxy_host" value="proxy.example.com" /> -->
    <!-- <parameter name="ext.cred.akeyless.proxy_port" value="3128" /> -->
    <!-- <parameter name="ext.cred.akeyless.proxy_username" value="proxy-user" /> -->
    <!-- <parameter name="ext.cred.akeyless.proxy_password" value="proxy-pass" secure="true" /> -->
</parameters>
```

Then restart the MID service:

```bash
sudo service mid restart
```

Or on Windows (from an elevated Command Prompt):

```bat
net stop mid
net start mid
```

### Gateway TLS and HTTP proxy

Gateway HTTPS calls use the MID JVM truststore by default. There is **no** TLS skip-verify path (`curl -k` is not equivalent): the hostname in `ext.cred.akeyless.gw_url` must match a certificate SAN/CN.

| Scenario | What to configure |
|----------|-------------------|
| Public CA–signed Gateway (e.g. `api.akeyless.io`) | Nothing extra |
| Private / self-signed Gateway CA | `ext.cred.akeyless.ca` or `ext.cred.akeyless.ca_file` (prefer file for large PEMs) |
| HTTP forward proxy between MID and Gateway | `ext.cred.akeyless.proxy_*`, **or** `mid.proxy.use_proxy=true` with `mid.proxy.*`, **or** JVM `https.proxyHost` / `https.proxyPort` when neither is set |
| Proxy + private CA together | Set both CA and proxy properties; TLS remains end-to-end to the Gateway via HTTP `CONNECT` |
| Proxy that performs TLS inspection (MITM) | Also trust the **proxy** CA (same `ca` / `ca_file` mechanism) |

Proxy notes:
- Only **HTTP** proxies are supported (HTTPS targets use `CONNECT`). SOCKS is not supported.
- Explicit `ext.cred.akeyless.proxy_host` overrides MID `mid.proxy.*`.
- Configuring `mid.proxy.*` for instance traffic alone is not enough unless `mid.proxy.use_proxy=true` (fallback) or you set `ext.cred.akeyless.proxy_*`.

### Configure a Discovery Credential to use this resolver

1) Create a new credential
- Navigate: Discovery → Credentials → New
- Choose a credential Type (e.g., Windows, SSH Password, SSH Private Key, VMware, JDBC, JMS, SNMPv3)
- Select “External credential store”
- Fully Qualified Class Name (FQCN): `com.snc.discovery.CredentialResolver`
- Credential ID: The Akeyless secret path (e.g., `/prod/app/db`) to fetch

2) Save and test
- Click “Test credential”, select a MID Server and a target if required by the type.

### What to store in Akeyless and how it’s mapped

The resolver accepts either:
- A plain string secret → mapped as a password/token
- A JSON object → fields are mapped to ServiceNow credential fields as per the credential Type

Item types (Static / Rotated / Dynamic)
- The resolver first calls `describe-item` to determine the Akeyless `item_type`.
- Based on `item_type`, it then calls:
  - `STATIC_SECRET` → `get-secret-value`
  - `ROTATED_SECRET` → `get-rotated-secret-value` (also sends `ignore-cache` when `ext.cred.akeyless.ignore_cache=true`)
  - `DYNAMIC_SECRET` → `get-dynamic-secret-value`
- If ServiceNow provides an `ip` argument for the credential test/run, the resolver passes it as `host` when fetching rotated secrets (some rotated secrets are host-scoped).

Default mapping (can be overridden via `ext.cred.akeyless.map.*`):
- Username field: `username`
- Password field: `password`
- Private key field: `private_key`
- Passphrase field: `passphrase`

Per-Type mapping summary
- Windows, Basic, SSH Password, VMware, JDBC, JMS:
  - Uses JSON fields: `username`, `password` (or your overridden names)
- SSH Private Key (and key-style credential types like `sn_cfg_ansible`, `sn_disco_certmgmt_certificate_ca`, `cfg_chef_credentials`, `infoblox`, `api_key`):
  - Uses JSON fields: `username`, `private_key`, `passphrase`
- SNMPv3:
  - Uses JSON fields: `username`, `auth_protocol`, `auth_key`, `privacy_protocol`, `privacy_key`
  - Mapped to ServiceNow fields: `username`, `auth-protocol`, `auth-key`, `privacy-protocol`, `privacy-key`
- Any other type:
  - Best-effort: `username` and `password` if present

Examples

Basic / Windows / SSH Password (JSON in Akeyless):
```json
{
  "username": "alice",
  "password": "secret"
}
```

SSH Private Key:
```json
{
  "username": "ssh-user",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
  "passphrase": "optional"
}
```

SNMPv3:
```json
{
  "username": "snmpu",
  "auth_protocol": "SHA",
  "auth_key": "authKeyHere",
  "privacy_protocol": "AES",
  "privacy_key": "privacyKeyHere"
}
```

Custom field names via mapping overrides (example):
- Set `ext.cred.akeyless.map.username = user_name`
- Set `ext.cred.akeyless.map.password = pwd`

Then a JSON like:
```json
{
  "user_name": "alice",
  "pwd": "secret"
}
```
will map to ServiceNow `username = alice`, `password = secret`.

### CloudID notes (aws_iam / azure_ad / gcp)

- When `ext.cred.akeyless.access_type` (or `AKEYLESS_ACCESS_TYPE`) is `aws_iam`, `azure_ad`, or `gcp`, the resolver fetches a CloudID and sends it to Akeyless during auth.
- Ensure the MID Server host is running in the target cloud with the appropriate identity, or that cloud SDK environment is present to retrieve a CloudID.
- Do not set `access_key` when using CloudID-based methods.

### Token caching

- After a successful `/auth` call, the Akeyless session token is cached in memory for the lifetime of the MID Server JVM.
- Subsequent `resolve()` calls reuse the cached token and skip authentication until Akeyless rejects it with **HTTP 401**.
- When an API call fails with an authentication error, the cache is cleared, a fresh token is obtained, and the failed call is retried once.
- There is no configurable TTL; token refresh is driven only by authentication failures from Akeyless.

### Troubleshooting

- TLS / `SSLHandshakeException` / “Hostname validation”:
  - The resolver uses the MID JVM truststore by default and **always** verifies the Gateway hostname against the certificate SAN/CN. `curl -k` is not equivalent.
  - Private or self-signed Gateway CA: set `ext.cred.akeyless.ca` (PEM) or `ext.cred.akeyless.ca_file`. This trusts the certificate; it does **not** disable hostname checks.
  - If the error is specifically hostname validation, ensure `ext.cred.akeyless.gw_url` uses a host name present on the certificate (not an IP unless the cert has that IP SAN).
  - Alternatively, import the CA into the MID JRE truststore (`agent/jre/lib/security/cacerts` or an external truststore via `wrapper-override.conf`) as described in ServiceNow MID SSL docs.
- Proxy connectivity:
  - Configuring only `mid.proxy.*` for instance traffic is not enough unless `mid.proxy.use_proxy=true` (the resolver will then reuse those settings) **or** you set `ext.cred.akeyless.proxy_*`.
  - JVM system properties `https.proxyHost` / `https.proxyPort` are still honored when no explicit Akeyless/MID proxy is configured.
- HTTP 400 “Missing required parameter - timestamp” on `/auth`:
  - Usually indicates the wrong auth flow or missing parameters. Verify `access_type` is set correctly. For CloudID flows, do not set an `access_key`. For `access_key` flows, ensure both `access_id` and `access_key` are set. For `uid`, set `uid_token_file` (preferred) or `uid_token` (fallback). For `cert`, provide cert/key material (inline or file-based).
- UID token file encoding (`uid_token_file`):
  - **Recommended:** plain ASCII or UTF-8 **without BOM**. Akeyless UID/child tokens are ASCII-safe; do not convert ASCII to UTF-8 if the converter adds a BOM.
  - The resolver auto-detects UTF-8 with BOM, UTF-16 LE/BE with BOM, and BOM-less UTF-16 LE so Windows PowerShell writers still work.
  - Windows write examples:

```powershell
[System.IO.File]::WriteAllText($path, $token.Trim(), [System.Text.UTF8Encoding]::new($false))
[System.IO.File]::WriteAllText($path, $token.Trim(), [System.Text.Encoding]::ASCII)
```

  - Avoid bare `Out-File` / `Set-Content` in Windows PowerShell 5 (defaults to UTF-16). Prefer `-Encoding utf8NoBOM` on PowerShell 7+, or the `WriteAllText` examples above.
  - `MalformedInputException` / `UncheckedIOException: Input length = 1` on older jars: the file was UTF-16 (or otherwise not UTF-8). Upgrade the jar, or rewrite the file as ASCII/UTF-8 without BOM.
  - HTTP **401** from `/auth` with a “UTF-8” file: check for a UTF-8 BOM, confirm `access_id` matches the Universal Identity that issued the child token, confirm the file is a single-line current child token, and check logs for `UID token source=file-fallback-inline` (file unreadable → stale inline fallback).
  - Successful UID auth logs include `UID token source=… len=… encoding=…` (token value is never logged).
- HTTP 404 from `/v2/*` endpoints:
  - The resolver automatically falls back to the non-`/v2` endpoints. If both fail, verify the gateway URL and network reachability.
- “Secret value not found for name …”:
  - Confirm the Credential ID (secret path) is correct and the Akeyless identity has permission to read it.
- JSON secret looks correct but everything lands in **`pswd`** (one blob):
  - Often the secret is **not valid strict JSON** because a PEM/certificate/SSH key was pasted with **real line breaks inside the quotes**. Prefer storing JSON with `\n` inside the string. If the payload still contains `-----BEGIN`, the resolver **retries** parsing with a lenient Jackson mode that allows unescaped control characters inside quoted strings.
- Logging:
  - Resolver logs go through Commons Logging. Check the MID Server logs for entries containing “Akeyless resolver”.
  - The plugin also writes its own daily-rotated log files under the MID agent `logs/` folder (for example `/opt/agent/logs/akeyless-resolver-YYYY-MM-DD.log` on Linux, or `C:\ServiceNow\agent\logs\akeyless-resolver-YYYY-MM-DD.log` on Windows).
  - File logs contain the same safe diagnostic messages as the MID logs (args, secret path, item type, resolved field keys). Secret values and tokens are never written to the file.

### CI/CD Pipeline

This project uses GitHub Actions for automated testing and publishing to Maven Central.

#### Setup

**GPG Key**: Published to `keys.openpgp.org` (fingerprint: `2BF78FF1D9D1EB92391F24E8201BDF6FEC105F84`) for Maven artifact signing. Maven Central automatically verifies signatures using the public key from keyservers.

**Central Portal Authentication**: Uses publishing tokens (not OSSRH username/password) stored as `MAVEN_CENTRAL_USERNAME` and `MAVEN_CENTRAL_PASSWORD` secrets.

#### Pipeline Behavior

- **Pull Requests**: Runs tests only (no deployment)
- **Manual Dispatch on Main Branch**: Deploys release version to staging (specify version manually, requires manual publish in portal)
- **Manual Dispatch on Other Branches**: Deploys SNAPSHOT version (`${version}-SNAPSHOT`, auto-publishes if enabled)

#### Manual Deployment

Deployments only happen when you manually trigger the workflow:

1. Go to GitHub Actions → "CI/CD" workflow → "Run workflow"
2. Choose branch to deploy from
3. **Version is required for all deployments** - Enter the base version number

**Deployment behavior:**
- **Main branch**: Deploys `1.0.0` to staging → **Manual publish required** in Maven Central Portal
- **Feature branches**: Deploys `1.0.0-SNAPSHOT` → **Auto-publishes**

**Version types:**
- **Snapshots** (`1.0.0-SNAPSHOT`, `1.1.0-SNAPSHOT`): Development versions that can be overwritten multiple times
- **Releases** (`1.0.0`, `1.0.1`, `1.1.0`): Permanent versions requiring manual publishing

**Semantic versioning:** `MAJOR.MINOR.PATCH`
- **MAJOR**: Breaking changes
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, backward compatible

**Deployment examples:**
- Enter `1.0.0` on main branch → deploys `1.0.0` (manual publish needed)
- Enter `1.0.0` on feature branch → deploys `1.0.0-SNAPSHOT` (auto-publishes)

**Why manual for releases?** Maven Central deployments are permanent - manual publishing gives you final control over when releases become public. Snapshots auto-publish for faster development iteration.

### Testing

#### Unit tests (local)

```bash
mvn test -Drevision=1.0.0-TEST
```

These cover CA PEM parsing / SSLContext build, proxy resolution precedence (Akeyless props vs `mid.proxy.*`), and proxy authenticator host/port matching. They do **not** call a live Gateway.

#### End-to-end on a MID Server

Use this flow after building and installing the shaded JAR (see [Install the resolver on the MID Server](#install-the-resolver-on-the-mid-server)).

**1) Baseline MID configuration**

On the MID host, edit `config.xml` (Linux: `/opt/agent/config.xml`, Windows: `C:\ServiceNow\agent\config.xml`) or set the same names as MID properties in the instance.

Minimum for `access_key` against a public Gateway:

```xml
<parameter name="ext.cred.akeyless.gw_url" value="https://api.akeyless.io" />
<parameter name="ext.cred.akeyless.access_type" value="access_key" />
<parameter name="ext.cred.akeyless.access_id" value="YOUR_ACCESS_ID" />
<parameter name="ext.cred.akeyless.access_key" value="YOUR_ACCESS_KEY" secure="true" />
```

Restart the MID after changes:

```bash
sudo service mid restart
```

**2) Create and test a Discovery credential**

1. Discovery → Credentials → New → choose a type (e.g. SSH Password / Windows).
2. Enable **External credential store**.
3. Fully Qualified Class Name: `com.snc.discovery.CredentialResolver`
4. Credential ID: an Akeyless secret path the identity can read (e.g. `/lab/snc/test`).
5. Save → **Test credential** → select this MID Server (and a target if the type requires one).

Success means auth + secret fetch + field mapping work. Failures appear in MID logs and in `/opt/agent/logs/akeyless-resolver-YYYY-MM-DD.log` (Windows: `C:\ServiceNow\agent\logs\`).

**3) Private / self-signed Gateway HTTPS**

1. Export the Gateway CA (or self-signed server cert) as PEM to the MID host, e.g. `/opt/agent/certs/akeyless-gw-ca.pem`.
2. Ensure `gw_url` uses a hostname that appears on the certificate (not a raw IP unless the cert has that IP SAN):

```xml
<parameter name="ext.cred.akeyless.gw_url" value="https://gw.example.internal" />
<parameter name="ext.cred.akeyless.ca_file" value="/opt/agent/certs/akeyless-gw-ca.pem" />
```

3. Restart MID → run **Test credential** again.
4. Optional negative check: remove `ca_file`, restart, retest — expect a TLS handshake error mentioning `ext.cred.akeyless.ca` / `ca_file`.
5. Optional hostname check: point `gw_url` at an IP or wrong name while keeping a valid CA — expect hostname validation failure (trust alone is not enough).

Host-level sanity check (not identical to the Java path, but useful):

```bash
openssl s_client -connect gw.example.internal:443 -servername gw.example.internal </dev/null
```

**4) HTTP proxy between MID and Gateway**

1. Confirm the proxy allows `CONNECT` to the Gateway host and port (usually 443).
2. Prefer an explicit Akeyless proxy (does not require `mid.proxy.use_proxy`):

```xml
<parameter name="ext.cred.akeyless.proxy_host" value="proxy.example.com" />
<parameter name="ext.cred.akeyless.proxy_port" value="3128" />
<!-- Optional Basic auth -->
<!-- <parameter name="ext.cred.akeyless.proxy_username" value="proxy-user" /> -->
<!-- <parameter name="ext.cred.akeyless.proxy_password" value="proxy-pass" secure="true" /> -->
```

Or reuse the MID instance proxy when it is already enabled:

```xml
<!-- Only used when ext.cred.akeyless.proxy_host is unset -->
<parameter name="mid.proxy.use_proxy" value="true" />
<parameter name="mid.proxy.host" value="proxy.example.com" />
<parameter name="mid.proxy.port" value="3128" />
```

3. Restart MID → **Test credential**.
4. On the proxy, confirm a `CONNECT gw.example.internal:443` (or your Gateway host:port) from the MID host.

Host-level sanity check:

```bash
curl -v --proxy http://proxy.example.com:3128 \
  --cacert /opt/agent/certs/akeyless-gw-ca.pem \
  https://gw.example.internal/
```

**5) Combined: private CA + proxy**

Use both blocks from steps 3 and 4 in the same `config.xml`, restart MID, then **Test credential**. This is the closest path to a locked-down enterprise deployment (TLS to Gateway through an HTTP forward proxy).

**6) Suggested validation matrix**

| Case | Config | Expected |
|------|--------|----------|
| Public Gateway, no proxy | Baseline only | Test credential succeeds |
| Private CA, no `ca_file` | Private `gw_url` only | TLS handshake failure |
| Private CA + `ca_file` | Step 3 | Test credential succeeds |
| Wrong hostname in `gw_url` | Valid CA, mismatched host | Hostname validation failure |
| Proxy without proxy props | Proxy required on network, no config | Connection / timeout failure |
| Explicit `proxy_*` | Step 4 | Success; proxy shows `CONNECT` |
| `mid.proxy.*` fallback | `use_proxy=true`, no `proxy_host` | Same as explicit proxy |
| Private CA + proxy | Step 5 | Success end-to-end |

For cloud-based auth types (`aws_iam` / `azure_ad` / `gcp`), run the MID on a host with a valid cloud identity. For local/dev, prefer `access_key`.

### License

Apache-2.0
