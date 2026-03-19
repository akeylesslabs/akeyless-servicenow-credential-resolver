package com.snc.discovery;

final class ResolverConfig {
    private final AuthConfig auth;
    private final MappingConfig mapping;

    ResolverConfig(AuthConfig auth, MappingConfig mapping) {
        this.auth = auth;
        this.mapping = mapping;
    }

    AuthConfig getAuth() {
        return auth;
    }

    MappingConfig getMapping() {
        return mapping;
    }

    static ResolverConfig load(MidPropertySource props) {
        MappingConfig mapping = new MappingConfig(
            props.getProperty("ext.cred.akeyless.map.username", "username"),
            props.getProperty("ext.cred.akeyless.map.password", "password"),
            props.getProperty("ext.cred.akeyless.map.private_key", "private_key"),
            props.getProperty("ext.cred.akeyless.map.passphrase", "passphrase")
        );

        AuthConfig auth = new AuthConfig(
            props.getProperty("ext.cred.akeyless.gw_url", props.envOr("AKEYLESS_GW_URL", "https://api.akeyless.io")),
            props.getProperty("ext.cred.akeyless.access_type", props.envOr("AKEYLESS_ACCESS_TYPE", "access_key")),
            props.getProperty("ext.cred.akeyless.access_id", props.envOr("AKEYLESS_ACCESS_ID", null)),
            props.getProperty("ext.cred.akeyless.access_key", props.envOr("AKEYLESS_ACCESS_KEY", null)),
            props.getProperty("ext.cred.akeyless.uid_token", props.envOr("AKEYLESS_UID_TOKEN", null)),
            props.getProperty("ext.cred.akeyless.cert_data", props.envOr("AKEYLESS_CERT_DATA", null)),
            props.getProperty("ext.cred.akeyless.cert_file_name", props.envOr("AKEYLESS_CERT_FILE_NAME", null)),
            props.getProperty("ext.cred.akeyless.key_data", props.envOr("AKEYLESS_KEY_DATA", null)),
            props.getProperty("ext.cred.akeyless.key_file_name", props.envOr("AKEYLESS_KEY_FILE_NAME", null))
        );

        return new ResolverConfig(auth, mapping);
    }

    static final class AuthConfig {
        private final String gatewayUrl;
        private final String accessType;
        private final String accessId;
        private final String accessKey;
        private final String uidToken;
        private final String certData;
        private final String certFileName;
        private final String keyData;
        private final String keyFileName;

        AuthConfig(
            String gatewayUrl,
            String accessType,
            String accessId,
            String accessKey,
            String uidToken,
            String certData,
            String certFileName,
            String keyData,
            String keyFileName
        ) {
            this.gatewayUrl = gatewayUrl;
            this.accessType = accessType;
            this.accessId = accessId;
            this.accessKey = accessKey;
            this.uidToken = uidToken;
            this.certData = certData;
            this.certFileName = certFileName;
            this.keyData = keyData;
            this.keyFileName = keyFileName;
        }

        String getGatewayUrl() {
            return gatewayUrl;
        }

        String getAccessType() {
            return accessType;
        }

        String getAccessId() {
            return accessId;
        }

        String getAccessKey() {
            return accessKey;
        }

        String getUidToken() {
            return uidToken;
        }

        String getCertData() {
            return certData;
        }

        String getCertFileName() {
            return certFileName;
        }

        String getKeyData() {
            return keyData;
        }

        String getKeyFileName() {
            return keyFileName;
        }
    }

    static final class MappingConfig {
        private final String usernameField;
        private final String passwordField;
        private final String privateKeyField;
        private final String passphraseField;

        MappingConfig(String usernameField, String passwordField, String privateKeyField, String passphraseField) {
            this.usernameField = usernameField;
            this.passwordField = passwordField;
            this.privateKeyField = privateKeyField;
            this.passphraseField = passphraseField;
        }

        String getUsernameField() {
            return usernameField;
        }

        String getPasswordField() {
            return passwordField;
        }

        String getPrivateKeyField() {
            return privateKeyField;
        }

        String getPassphraseField() {
            return passphraseField;
        }
    }
}

