import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Enumeration;
import java.util.Properties;

import es.gob.afirma.core.signers.AOSigner;
import es.gob.afirma.signers.cades.AOCAdESSigner;
import es.gob.afirma.signers.pades.AOPDFSigner;

/**
 * Drives the official AutoFirma signers headlessly, so the golden files we
 * diff against are produced by the real thing and not by a reimplementation of
 * a reimplementation.
 *
 * It goes straight to the library API that AutoFirma's own GUI calls, and
 * loads the PKCS#12 with plain JCA instead of AutoFirma's keystore layer, so
 * nothing here needs a display, a browser or the local wss service.
 *
 * The signer is picked from the input the same way AutoFirma does: a PDF goes
 * to PAdES, anything else to CAdES. The two signers are instantiated directly
 * rather than through AOSignerFactory, whose service loading does not resolve
 * on a plain -cp classpath.
 *
 * Usage:
 *   AutofirmaGolden &lt;p12&gt; &lt;password&gt; &lt;in&gt; &lt;out&gt; &lt;algorithm&gt; [key=value]...
 *
 * Recognised keys are AutoFirma's own CAdESExtraParams, the ones that matter
 * here being mode (explicit|implicit), profile (advanced|baseline),
 * signingCertificateV2, includeSigningTimeAttribute, includeMimeTypeAttribute,
 * mimeType and contentTypeOid.
 */
public final class AutofirmaGolden {

    private AutofirmaGolden() {
        // utility entry point
    }

    public static void main(final String[] args) throws Exception {
        if (args.length < 5) {
            System.err.println("usage: AutofirmaGolden <p12> <password> <in> <out> <algorithm> [key=value]...");
            System.exit(2);
        }
        final String p12 = args[0];
        final char[] password = args[1].toCharArray();
        final String in = args[2];
        final String out = args[3];
        final String algorithm = args[4];

        final Properties params = new Properties();
        for (int i = 5; i < args.length; i++) {
            final int eq = args[i].indexOf('=');
            if (eq < 1) {
                throw new IllegalArgumentException("not a key=value pair: " + args[i]);
            }
            params.setProperty(args[i].substring(0, eq), args[i].substring(eq + 1));
        }

        final KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(p12)) {
            ks.load(fis, password);
        }

        final String alias = firstAliasWithKey(ks, password);
        final PrivateKey key = (PrivateKey) ks.getKey(alias, password);
        final Certificate[] chain = ks.getCertificateChain(alias);
        if (key == null || chain == null || chain.length == 0) {
            throw new IOException("no private key or chain under alias " + alias);
        }

        final byte[] data = Files.readAllBytes(Paths.get(in));

        final AOSigner signer = isPdf(data) ? new AOPDFSigner() : new AOCAdESSigner();
        final byte[] signature = signer.sign(data, algorithm, key, chain, params);

        Files.write(Paths.get(out), signature);

        System.out.println("autofirma " + versionHint() + " signed " + in + " -> " + out
                + " (" + signature.length + " bytes, "
                + (isPdf(data) ? "PAdES" : "CAdES") + ", " + algorithm
                + ", mode=" + params.getProperty("mode", "-")
                + ", profile=" + params.getProperty("profile", "-") + ")");
    }

    /** The %PDF magic, which is how AutoFirma itself decides the format. */
    private static boolean isPdf(final byte[] data) {
        return data.length > 5
                && data[0] == '%' && data[1] == 'P' && data[2] == 'D' && data[3] == 'F';
    }

    private static String firstAliasWithKey(final KeyStore ks, final char[] password) throws Exception {
        final Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            final String alias = aliases.nextElement();
            if (ks.isKeyEntry(alias)) {
                return alias;
            }
        }
        throw new IOException("the PKCS#12 holds no key entry");
    }

    /** AutoFirma's own version constant, so the golden files record what produced them. */
    private static String versionHint() {
        final String v = System.getProperty("afirma.version");
        if (v != null) {
            return v;
        }
        final String impl = AutofirmaGolden.class.getPackage() == null ? null
                : AutofirmaGolden.class.getPackage().getImplementationVersion();
        return impl != null ? impl : "unknown";
    }
}
