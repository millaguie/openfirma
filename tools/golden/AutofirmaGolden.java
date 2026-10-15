import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import es.gob.afirma.core.signers.AOSigner;
import es.gob.afirma.signers.cades.AOCAdESSigner;
import es.gob.afirma.signers.pades.AOPDFSigner;
import es.gob.afirma.signers.xades.AOXAdESSigner;
import es.gob.afirma.signvalidation.SignValidity;
import es.gob.afirma.signvalidation.ValidateXMLSignature;

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
 * to PAdES, an XML document to XAdES, anything else to CAdES. The signers are
 * instantiated directly rather than through AOSignerFactory, whose service
 * loading does not resolve on a plain -cp classpath.
 *
 * Usage:
 *   AutofirmaGolden &lt;p12&gt; &lt;password&gt; &lt;in&gt; &lt;out&gt; &lt;algorithm&gt; [key=value]...
 *   AutofirmaGolden --verify &lt;signed file&gt;
 *
 * Recognised keys are AutoFirma's own CAdESExtraParams and XAdESExtraParams,
 * the ones that matter here being mode (explicit|implicit), profile
 * (advanced|baseline), signingCertificateV2, includeSigningTimeAttribute,
 * includeMimeTypeAttribute, mimeType and contentTypeOid for CAdES, and
 * format (XAdES Enveloped|XAdES Enveloping|XAdES Detached), profile and
 * referencesDigestMethod for XAdES.
 *
 * The --verify mode hands the file to AutoFirma's own validator (the
 * ValidateXMLSignature of the afirma-crypto-validation module, which is what
 * the GUI's "validate signature" button calls) and prints one line per
 * verdict, exiting non zero when any of them is KO. Today it only validates
 * XML signatures; that is the independent verdict the XAdES integration test
 * in cargo test needs.
 */
public final class AutofirmaGolden {

    private AutofirmaGolden() {
        // utility entry point
    }

    public static void main(final String[] args) throws Exception {
        if (args.length >= 2 && "--verify".equals(args[0])) {
            System.exit(verify(args[1]));
            return;
        }
        if (args.length < 5) {
            System.err.println("usage: AutofirmaGolden <p12> <password> <in> <out> <algorithm> [key=value]...");
            System.err.println("       AutofirmaGolden --verify <signed file>");
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

        final String formatName;
        final AOSigner signer;
        if (isPdf(data)) {
            signer = new AOPDFSigner();
            formatName = "PAdES";
        }
        else if (isXml(data)) {
            signer = new AOXAdESSigner();
            formatName = "XAdES";
        }
        else {
            signer = new AOCAdESSigner();
            formatName = "CAdES";
        }
        final byte[] signature = signer.sign(data, algorithm, key, chain, params);

        Files.write(Paths.get(out), signature);

        System.out.println("autofirma " + versionHint() + " signed " + in + " -> " + out
                + " (" + signature.length + " bytes, " + formatName + ", " + algorithm
                + ", mode=" + params.getProperty("mode", "-")
                + ", profile=" + params.getProperty("profile", "-")
                + ", format=" + params.getProperty("format", "-") + ")");
    }

    /**
     * Validates a signed file with AutoFirma's own XML validator and prints
     * one line per verdict. Returns the process exit code: 0 when everything
     * is OK, 1 on any KO, 2 when the file cannot be handled.
     */
    private static int verify(final String file) throws Exception {
        final byte[] sign = Files.readAllBytes(Paths.get(file));
        if (!isXml(sign)) {
            System.err.println("--verify only validates XML signatures; " + file + " is not XML");
            return 2;
        }

        // The same validator the AutoFirma GUI uses, with certificate date
        // checking on. The test PKI is generated fresh and short lived, so an
        // expired material failure here is a real failure, not noise.
        final ValidateXMLSignature validator = new ValidateXMLSignature();
        final List<SignValidity> results = validator.validate(sign, true);

        int exit = 0;
        for (final SignValidity validity : results) {
            System.out.println(validity.getValidity().name()
                    + (validity.getError() != null ? " " + validity.getError().name() : ""));
            if (SignValidity.SIGN_DETAIL_TYPE.KO.equals(validity.getValidity())) {
                exit = 1;
            }
        }
        if (results.isEmpty()) {
            System.out.println("KO NO_RESULTS");
            exit = 1;
        }
        return exit;
    }

    /** The %PDF magic, which is how AutoFirma itself decides the format. */
    private static boolean isPdf(final byte[] data) {
        return data.length > 5
                && data[0] == '%' && data[1] == 'P' && data[2] == 'D' && data[3] == 'F';
    }

    /**
     * Whether the data parses as an XML document, which is what routes it to
     * the XAdES signer. External entities and DTD loading are off: the golden
     * inputs are fixed synthetic files.
     */
    private static boolean isXml(final byte[] data) {
        if (data == null || data.length == 0) {
            return false;
        }
        try {
            final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            final DocumentBuilder builder = factory.newDocumentBuilder();
            final Document doc = builder.parse(new ByteArrayInputStream(data));
            final NodeList roots = doc.getChildNodes();
            return roots.getLength() > 0;
        }
        catch (final Exception e) {
            return false;
        }
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
