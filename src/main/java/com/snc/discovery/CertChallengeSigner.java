package com.snc.discovery;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Objects;

public final class CertChallengeSigner {

    private CertChallengeSigner() {}

    public static byte[] signCertChallengeRsaSha256(
            String storeName,
            char[] storePassword,
            String thumbprint,
            byte[] challenge
    ) throws GeneralSecurityException, IOException {

        KeyStore keyStore = loadKeyStore(storeName, storePassword);

        KeyMaterial km = findByThumbprint(keyStore, thumbprint, storePassword);
        if (!(km.privateKey instanceof java.security.interfaces.RSAPrivateKey)) {
            throw new GeneralSecurityException(
                    "Certificate private key is not RSA. Algorithm=" + km.privateKey.getAlgorithm());
        }

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(km.privateKey);

        // Signature("SHA256withRSA") hashes internally with SHA-256 and then signs with RSA.
        signature.update(challenge);

        return signature.sign();
    }

    /**
     * Loads a KeyStore from a "storeName".
     *
     * Supported forms:
     *   - "WINDOWS-MY" / "WINDOWS-ROOT"      (Windows, provider-dependent)
     *   - "PKCS12:/absolute/or/relative/path"
     *   - "JKS:/absolute/or/relative/path"
     *
     * Notes:
     *   - Native Windows stores are typically available via the SunMSCAPI provider on Windows.
     *   - PKCS12 is the most portable choice across platforms.
     */
    public static KeyStore loadKeyStore(String storeName, char[] storePassword)
            throws GeneralSecurityException, IOException {

        Objects.requireNonNull(storeName, "storeName");
        String upper = storeName.toUpperCase(Locale.ROOT);

        if (upper.equals("WINDOWS-MY") || upper.equals("WINDOWS-ROOT")) {
            KeyStore ks = KeyStore.getInstance(storeName);
            ks.load(null, null);
            return ks;
        }

        if (upper.startsWith("PKCS12:")) {
            String path = storeName.substring("PKCS12:".length());
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (InputStream in = Files.newInputStream(Path.of(path))) {
                ks.load(in, storePassword);
            }
            return ks;
        }

        if (upper.startsWith("JKS:")) {
            String path = storeName.substring("JKS:".length());
            KeyStore ks = KeyStore.getInstance("JKS");
            try (InputStream in = Files.newInputStream(Path.of(path))) {
                ks.load(in, storePassword);
            }
            return ks;
        }

        throw new KeyStoreExceptionWithHint(
                "Unsupported storeName: " + storeName,
                "Use WINDOWS-MY / WINDOWS-ROOT on Windows, or PKCS12:/path/to/file.p12, or JKS:/path/to/file.jks");
    }

    public static KeyMaterial findByThumbprint(
            KeyStore keyStore,
            String thumbprint,
            char[] keyPassword
    ) throws GeneralSecurityException {

        String wanted = normalizeThumbprint(thumbprint);

        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();

            Certificate cert = keyStore.getCertificate(alias);
            if (!(cert instanceof X509Certificate x509)) {
                continue;
            }

            String certThumb = sha1ThumbprintHex(x509);
            if (!certThumb.equals(wanted)) {
                continue;
            }

            if (!keyStore.isKeyEntry(alias)) {
                throw new GeneralSecurityException(
                        "Found certificate with matching thumbprint, but alias has no private key: " + alias);
            }

            Key key = keyStore.getKey(alias, keyPassword);
            if (!(key instanceof PrivateKey privateKey)) {
                throw new GeneralSecurityException(
                        "Found matching alias, but key is not a PrivateKey: " + alias);
            }

            return new KeyMaterial(alias, x509, privateKey);
        }

        throw new GeneralSecurityException("Certificate not found by thumbprint: " + thumbprint);
    }

    /**
     * Windows-style thumbprints are typically SHA-1 over the DER-encoded certificate.
     */
    public static String sha1ThumbprintHex(X509Certificate cert) throws GeneralSecurityException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(cert.getEncoded());
        return toHex(digest);
    }

    public static String normalizeThumbprint(String thumbprint) {
        if (thumbprint == null) {
            throw new IllegalArgumentException("thumbprint is null");
        }
        return thumbprint.replaceAll("[^0-9A-Fa-f]", "").toUpperCase(Locale.ROOT);
    }

    public static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >>> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString().toUpperCase(Locale.ROOT);
    }

    public record KeyMaterial(String alias, X509Certificate certificate, PrivateKey privateKey) {}

    public static final class KeyStoreExceptionWithHint extends GeneralSecurityException {
        public KeyStoreExceptionWithHint(String message, String hint) {
            super(message + ". Hint: " + hint);
        }
    }
}
