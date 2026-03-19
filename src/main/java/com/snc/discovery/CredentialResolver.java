package com.snc.discovery;

import io.akeyless.cloudid.CloudIdProvider;
import io.akeyless.cloudid.CloudProviderFactory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.HashMap;
import java.util.Map;

public class CredentialResolver {
    private static final Log LOG = LogFactory.getLog(CredentialResolver.class);

    public static final String ARG_ID = "id";
    public static final String ARG_IP = "ip";
    public static final String ARG_TYPE = "type";
    public static final String ARG_MID = "mid";

    public static final String VAL_USER = "user";
    public static final String VAL_PSWD = "pswd";
    public static final String VAL_PASSPHRASE = "passphrase";
    public static final String VAL_PKEY = "pkey";
    public static final String VAL_AUTHPROTO = "authprotocol";
    public static final String VAL_AUTHKEY = "authkey";
    public static final String VAL_PRIVPROTO = "privprotocol";
    public static final String VAL_PRIVKEY = "privkey";

    // Backward-compatible alias for tests/integration code that referenced nested type.
    interface HttpTransport extends AkeylessHttpTransport {}

    private static AkeylessHttpTransport HTTP = new DefaultHttpTransport();

    static void setHttpTransport(AkeylessHttpTransport transport) {
        HTTP = transport != null ? transport : new DefaultHttpTransport();
    }

    static void resetHttpTransport() {
        HTTP = new DefaultHttpTransport();
    }

    private final MidPropertySource propertySource;
    private final ServiceNowCredentialMapper mapper;
    private final AkeylessAuthRequestFactory authFactory;

    public CredentialResolver() {
        this(new MidPropertySource(), new ServiceNowCredentialMapper(), new AkeylessAuthRequestFactory());
    }

    CredentialResolver(
        MidPropertySource propertySource,
        ServiceNowCredentialMapper mapper,
        AkeylessAuthRequestFactory authFactory
    ) {
        this.propertySource = propertySource;
        this.mapper = mapper;
        this.authFactory = authFactory;
    }

    public Map<String, String> resolve(Map<String, String> args) throws Exception {
        LOG.info("Akeyless resolver: resolving secret for args " + args);

        String snType = must(args.get(ARG_TYPE), "Missing arg 'type'");
        String secretPath = must(args.get(ARG_ID), "Missing arg 'id' (use your Akeyless secret path)");

        ResolverConfig config = ResolverConfig.load(propertySource);
        AkeylessGatewayClient gatewayClient = new AkeylessGatewayClient(
            HTTP,
            authFactory,
            accessType -> getCloudIdProvider(accessType).getCloudId()
        );
        String raw = gatewayClient.getSecretValue(secretPath, config.getAuth());
        Map<String, String> out = mapper.mapToServiceNow(snType, raw, config.getMapping());

        LOG.info("Akeyless resolver: resolved secret for path '" + secretPath + "' -> fields " + out.keySet());
        return out;
    }

    // Seam for testing CloudID provider
    protected CloudIdProvider getCloudIdProvider(String type) {
        return CloudProviderFactory.getCloudIdProvider(type);
    }

    private static String must(String val, String msg) {
        if (val == null || val.isEmpty()) {
            throw new IllegalArgumentException(msg);
        }
        return val;
    }

    public String getVersion() {
        return "1.0";
    }

    public static void main(String[] args) throws Exception {
        setPropIfMissing("AKEYLESS_GW_URL", "https://api.akeyless.io");
        setPropIfMissing("AKEYLESS_ACCESS_TYPE", "universal_identity");
        setPropIfMissing("AKEYLESS_ACCESS_ID", "p-qwj5c3lzu2nh");
        setPropIfMissing("AKEYLESS_UID_TOKEN", "u-AQAAAOgDAACrFVfQGljq7LmoF7IqyjN9iIOY1/JaxFIucXdqNWMzbHp1Mm5o");

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
