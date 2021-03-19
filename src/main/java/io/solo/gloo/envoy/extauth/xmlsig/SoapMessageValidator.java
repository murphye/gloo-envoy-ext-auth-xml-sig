package io.solo.gloo.envoy.extauth.xmlsig;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.StringReader;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Base64;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

/**
 * This class takes a SOAP message which uses WS-Security Extentions (WSSE) to
 * embed a <BinarySecurityToken> inside the message. This BinarySecurityToken is
 * actually the RSA public key embedded in a X.509 PEM Base64 encoded
 * certificate. The BinarySecurityToken is also referenced inside the XML
 * <Signature> as a <SecurityTokenReference>. Additionally, the SOAP <Body>
 * contains a WS-Security Utility "Id" to reference the XML <Signature>
 * <Reference> which contains a <DigestValue> that is used to validate the SOAP
 * <Body> itself.
 *
 * So, just to clarify, here is what is validated:
 *
 * 1) The general validity of the client's X.509 certificate (i.e. not expired)
 * 2) The certificate is validated against the certificate chain installed in the
 *    local JVM TrustStore. The cerificate must have been generated from an
 *    installed Certificate Authority (including intermediate CA certs)
 * 3) The digest is used to validate the SOAP message body (to prevent tampering)
 * 4) The SOAP message itself is not expired (i.e. took to long to send)
 */
public class SoapMessageValidator {

    private final static String WSSE_XMLNS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private final static String WSU_XMLNS  = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    private final static String SOAP_XMLNS = "http://schemas.xmlsoap.org/soap/envelope/";

    public static boolean validate(String soapString) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder dBuilder = factory.newDocumentBuilder();
        Document document = dBuilder.parse(new InputSource(new StringReader(soapString)));
        NodeList signatureList = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        NodeList binarySecurityTokenList = document.getElementsByTagNameNS(WSSE_XMLNS, "BinarySecurityToken");
        NodeList bodyList = document.getElementsByTagNameNS(SOAP_XMLNS, "Body");
        NodeList timestampList = document.getElementsByTagNameNS(WSU_XMLNS, "Timestamp");

        if (signatureList.getLength() == 0) {
            throw new Exception("DS <Signature> element not found!");
        }

        if (binarySecurityTokenList.getLength() == 0) {
            throw new Exception("WSSE <BinarySecurityToken> element not found!");
        }

        if (bodyList.getLength() == 0) {
            throw new Exception("SOAP <Body> element not found!");
        }

        if (timestampList.getLength() == 0) {
            throw new Exception("WSU <Timestamp> element not found!");
        }

        Node signatureNode = signatureList.item(0);
        Node binarySecurityNode = binarySecurityTokenList.item(0);
        Node bodyNode = bodyList.item(0);
        Node timestampNode = timestampList.item(0);

        // Check that the SOAP message has not yet expired
        for(int i = 0; i < timestampNode.getChildNodes().getLength(); i++) {
            if(timestampNode.getChildNodes().item(i).getLocalName().equals("Expires")) {
                String dateStr = timestampNode.getChildNodes().item(i).getTextContent();
                if(ZonedDateTime.parse(dateStr).isBefore(ZonedDateTime.now(ZoneId.of("UTC")))) {
                    throw new Exception("SOAP message has expired with a timestamp of: " + dateStr);
                }
                break;
            }
        }

        // Partial Credit: http://rcbj.net/blog01/2012/12/30/convert-an-x509v3-binary-security-token-to-pem-format/
        byte[] decodedCert = Base64.getMimeDecoder().decode(binarySecurityNode.getTextContent().getBytes("UTF-8"));
        InputStream targetStream = new ByteArrayInputStream(decodedCert);
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X509")
                .generateCertificate(targetStream);

        certificate.checkValidity(); // Will throw exceptions such as CertificateExpiredException
        validateAgainstTrustManager(certificate); // Check PublicKey against local TrustStore certificate chain

        RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();
        return validateSignature(timestampNode, signatureNode, bodyNode, publicKey);
    }

    /*
     * Credit: https://stackoverflow.com/a/9443960
     */
    private static boolean validateSignature(Node timestampNode, Node signatureNode, Node bodyTag, PublicKey publicKey) throws Exception {
        // Create a DOM XMLSignatureFactory that will be used to unmarshal the document containing the XMLSignature
        String providerName = System.getProperty("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM",
                (Provider) Class.forName(providerName).getDeclaredConstructor().newInstance());

        // Create a DOMValidateContext and specify a KeyValue KeySelector and document
        // context
        DOMValidateContext valContext = new DOMValidateContext(new SimpleKeySelector(publicKey), signatureNode);
        valContext.setIdAttributeNS((Element) bodyTag, WSU_XMLNS, "Id");
        valContext.setIdAttributeNS((Element) timestampNode, WSU_XMLNS, "Id");

        // Unmarshal and validate the XMLSignature.
        XMLSignature signature = fac.unmarshalXMLSignature(valContext);

        boolean validationResult = signature.validate(valContext);
        return validationResult;

    }

    /*
     * Credit: https://stackoverflow.com/questions/6143646/validate-x509-certificates-using-java-apis/6379434#6379434
     */
    private static void validateAgainstTrustManager(X509Certificate certificate) throws CertificateException, NoSuchAlgorithmException, KeyStoreException {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init((KeyStore)null);

        X509Certificate[] certificateArray = {certificate};
        for (TrustManager trustManager: trustManagerFactory.getTrustManagers()) {
            if (trustManager instanceof X509TrustManager) {
                X509TrustManager x509TrustManager = (X509TrustManager)trustManager;
                x509TrustManager.checkClientTrusted(certificateArray, "RSA");
            }
        }
    }

    /*
     * Credit: https://stackoverflow.com/a/9443960
     * KeySelectorResult with a predefined key. The public key is not stored in the <Signature> directly for SOAP messages.
     */
    private static class SimpleKeySelector extends KeySelector {
        private PublicKey key;

        public SimpleKeySelector(PublicKey key) {
            this.key = key;
        }

        @Override
        public KeySelectorResult select(KeyInfo keyInfo, KeySelector.Purpose purpose, AlgorithmMethod method, XMLCryptoContext context) throws KeySelectorException {
            return new KeySelectorResult() {
                @Override
                public Key getKey() {
                    return key;
                }
            };
        }
    }
}
