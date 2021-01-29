package io.solo.gloo.envoy.extauth.xmlsig;

import java.util.Base64;
import java.util.Iterator;
import java.util.Optional;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import io.vertx.junit5.VertxExtension;

import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.ParserConfigurationException;
import jakarta.xml.soap.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URL;
import java.nio.CharBuffer;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;

@ExtendWith(VertxExtension.class)
// Credit: https://gist.github.com/RevenueGitHubAdmin/2bc2f593040b6f97c0002b5718063fb5
public class SOAPClientSampleTest {


    /*
    Gists provided for illustrative purposes only. Developers can use these as a support tool
    but the Office of the Revenue Commissioners (Revenue) does not provide any warranty with
    these gists.

    In this example we will perform the following steps

    1.Read in an XML file and generate a DOM Document object. The input file should conform to the CoC schema.
    2.Wrap the DOM Document in a SOAP Envelope.
    3.Sign the SOAP Envelope.
    4.Output the generated SOAP Message to a file.
    5.Send message to the web service endpoint.
     */

    //@Disabled
    @Test
    void test() throws Exception {
        SOAPClientSampleTest client = new SOAPClientSampleTest();
        Document doc = client.readInXMLFile();
        SOAPMessage msg = client.createSOAPEnvelope(doc);
        msg = client.signSOAPMessage(msg);
        client.outputSOAPMessageToFile(msg);
    }

    private Document readInXMLFile() throws ParserConfigurationException, SAXException, IOException
    {
        File requestFile = new File("/home/eric/GitHub/gloo-envoy-ext-auth-xml-sig/src/test/resources/invalid.xml");
        javax.xml.parsers.DocumentBuilderFactory dbFactory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
        dbFactory.setNamespaceAware(true);
        javax.xml.parsers.DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.parse(requestFile);

        return doc;
    }


    private SOAPMessage createSOAPEnvelope(Document xmlDocument)
            throws SOAPException {

        // Create SOAP Message
        MessageFactory messageFactory = MessageFactory.newInstance();
        SOAPMessage soapMessage = messageFactory.createMessage();
        SOAPEnvelope soapEnvelope = soapMessage.getSOAPPart().getEnvelope();


        // Add DOM object to SOAP body
        SOAPBody soapBody = soapMessage.getSOAPBody();
        soapBody.addDocument(xmlDocument);
        soapBody.addAttribute(soapEnvelope.createName("Id", "wsu",
                "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"), "Body");

        return soapMessage;
    }

    private SOAPMessage signSOAPMessage(SOAPMessage soapMessage) throws Exception {
        // Create the security element
        SOAPElement soapHeader = soapMessage.getSOAPHeader();

        SOAPElement securityElement = soapHeader.addChildElement("Security",
                "wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");


        securityElement.addNamespaceDeclaration("wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");

        // (i) Extract the certificate from the .p12 file.
        java.security.cert.Certificate cert = getCertificate();

        // (ii) Add Binary Security Token. The base64 encoded value of the ROS digital certificate.
        addBinarySecurityToken(securityElement, cert);

        //(iii) Add Timestamp element
        SOAPElement timestamp = addTimestamp(securityElement, soapMessage);

        // (iv) Add signature element
        addSignature(securityElement, soapMessage.getSOAPBody(), timestamp);

        return soapMessage;
    }

    private SOAPElement addTimestamp(SOAPElement securityElement, SOAPMessage soapMessage) throws SOAPException {
        SOAPElement timestamp = securityElement.addChildElement("Timestamp", "wsu");
        SOAPEnvelope soapEnvelope = soapMessage.getSOAPPart().getEnvelope();

        timestamp.addAttribute(soapEnvelope.createName("Id", "wsu",
                "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"), "TS");

        String DATE_TIME_PATTERN = "yyyy-MM-dd'T'HH:mm:ss.SSSX";
        DateTimeFormatter timeStampFormatter = DateTimeFormatter.ofPattern(DATE_TIME_PATTERN);


        timestamp.addChildElement("Created", "wsu").setValue(timeStampFormatter.format(ZonedDateTime.now().toInstant().atZone(ZoneId.of("UTC"))));
        timestamp.addChildElement("Expires", "wsu").setValue(timeStampFormatter.format(ZonedDateTime.now().plusSeconds(30).toInstant().atZone(ZoneId.of("UTC"))));

        return timestamp;
    }

    private java.security.cert.Certificate getCertificate() throws Exception {

        // (iv) Open the Seat using KeyStore
        //KeyStore keystore = KeyStore.getInstance("PKCS12");
        //keystore.load(new FileInputStream(new File("C:\\projects\\certificates\\999963110.p12")), passwordHashedbase64.toCharArray());

        KeyStore keyStore = PemReader.loadKeyStore(getResourceFile("rsa.crt"), getResourceFile("rsa.key"), Optional.empty());

        // (v) Extract the certificate.
        java.security.cert.Certificate cert = keyStore.getCertificate("key");

        return cert;
    }


    private SOAPElement addBinarySecurityToken(SOAPElement securityElement, java.security.cert.Certificate cert) throws Exception {

        // Get byte array of cert.
        byte[] certByte = cert.getEncoded();

        // Add the Binary Security Token element
        SOAPElement binarySecurityToken = securityElement.addChildElement("BinarySecurityToken", "wsse");

        binarySecurityToken.setAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
        binarySecurityToken.setAttribute("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
        binarySecurityToken.setAttribute("wsu:Id", "X509Token");
        binarySecurityToken.addTextNode(Base64.getEncoder().encodeToString(certByte));
        return securityElement;

    }

    private SOAPElement addSignature(
            SOAPElement securityElement, SOAPBody soapBody, SOAPElement timestamp) throws Exception {

        // Get private key from ROS digital certificate
        PrivateKey key = getKeyFormCert();

        SOAPElement securityTokenReference = addSecurityToken(securityElement);

        // Add signature
        createDetachedSignature(securityElement, key, securityTokenReference, soapBody, timestamp);

        return securityElement;
    }


    private PrivateKey getKeyFormCert() throws Exception {
        // (iv) Open the cert using KeyStore
        //KeyStore keystore = KeyStore.getInstance("PKCS12");
        //keystore.load(new FileInputStream(new File("C:\\projects\\certificates\\999963110.p12")), passwordHashedBase64.toCharArray());

        KeyStore keyStore = PemReader.loadKeyStore(getResourceFile("rsa.crt"), getResourceFile("rsa.key"), Optional.empty());

        // (v) Extract Private Key
        PrivateKey key = (PrivateKey) keyStore.getKey("key", "".toCharArray());
        return key;
    }

    private SOAPElement addSecurityToken(SOAPElement signature)
            throws SOAPException {
        SOAPElement securityTokenReference = signature.addChildElement("SecurityTokenReference", "wsse");
        SOAPElement reference = securityTokenReference.addChildElement("Reference", "wsse");

        reference.setAttribute("URI", "#X509Token");

        return securityTokenReference;
    }

    private void createDetachedSignature(SOAPElement signatureElement, PrivateKey privateKey, SOAPElement securityTokenReference, SOAPBody soapBody, SOAPElement timestamp) throws Exception {


        String providerName = System.getProperty("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
        XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM",(Provider) Class.forName(providerName).newInstance());

        //Digest method
        javax.xml.crypto.dsig.DigestMethod digestMethod = xmlSignatureFactory.newDigestMethod("http://www.w3.org/2001/04/xmlenc#sha512", null);
        ArrayList<Transform> transformList = new ArrayList<Transform>();

        //Transform
        Transform envTransform = xmlSignatureFactory.newTransform("http://www.w3.org/2001/10/xml-exc-c14n#", (TransformParameterSpec) null);
        transformList.add(envTransform);

        //References
        ArrayList<Reference> refList = new ArrayList<Reference>();
        Reference refTS = xmlSignatureFactory.newReference("#TS", digestMethod, transformList, null, null);
        Reference refBody = xmlSignatureFactory.newReference("#Body", digestMethod, transformList, null, null);

        refList.add(refBody);
        refList.add(refTS);

        javax.xml.crypto.dsig.CanonicalizationMethod cm = xmlSignatureFactory.newCanonicalizationMethod("http://www.w3.org/2001/10/xml-exc-c14n#",(C14NMethodParameterSpec) null);

        javax.xml.crypto.dsig.SignatureMethod sm = xmlSignatureFactory.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", null);
        SignedInfo signedInfo = xmlSignatureFactory.newSignedInfo(cm, sm, refList);


        DOMSignContext signContext = new DOMSignContext(privateKey, signatureElement);
        signContext.setDefaultNamespacePrefix("ds");
        signContext.putNamespacePrefix("http://www.w3.org/2000/09/xmldsig#", "ds");

        signContext.setIdAttributeNS
                (soapBody,
                        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Id");


        signContext.setIdAttributeNS
                (timestamp,
                        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Id");

        KeyInfoFactory keyFactory = KeyInfoFactory.getInstance();
        DOMStructure domKeyInfo = new DOMStructure(securityTokenReference);
        javax.xml.crypto.dsig.keyinfo.KeyInfo keyInfo = keyFactory.newKeyInfo(java.util.Collections.singletonList(domKeyInfo));
        javax.xml.crypto.dsig.XMLSignature signature = xmlSignatureFactory.newXMLSignature(signedInfo, keyInfo);
        signContext.setBaseURI("");
        signature.sign(signContext);
    }

    private void outputSOAPMessageToFile(SOAPMessage soapMessage)
            throws SOAPException, IOException {

        File outputFile = new File("/home/eric/GitHub/gloo-envoy-ext-auth-xml-sig/src/test/resources/output.soap.xml");
        java.io.FileOutputStream fos = new java.io.FileOutputStream(outputFile);
        soapMessage.writeTo(fos);
        fos.close();
    }

    private static File getResourceFile(String name)
    {
        URL resource = TestPemReader.class.getClassLoader().getResource(name);
        if (resource == null) {
            throw new IllegalArgumentException("Resource not found " + name);
        }
        return new File(resource.getFile());
    }
}
