package io.solo.gloo.envoy.extauthz.xmlsig;

import java.security.Key;

import javax.xml.crypto.KeySelector;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class XmlSigUtil {

    public boolean validateXmlMessage(Key publicKey, String xmlString)
            throws MarshalException, XMLSignatureException, Exception {
        return validateXmlSignature(publicKey, getXmlSignatureElement(xmlString));
    }

    public Element getXmlSignatureElement(String xmlString) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = factory.newDocumentBuilder();
        Document document = dBuilder.parse(xmlString);
        NodeList nodeList = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (nodeList.getLength() == 0) {
            throw new Exception("XML <Signature> element not found!");
        }
        return (Element) nodeList.item(0);
    }

    public boolean validateXmlSignature(Key publicKey, Element signatureElement)
            throws MarshalException, XMLSignatureException {
        KeySelector ks = KeySelector.singletonKeySelector(publicKey);
        DOMValidateContext vc = new DOMValidateContext(ks, signatureElement);
        XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
        XMLSignature signature = signatureFactory.unmarshalXMLSignature(vc);
        return signature.validate(vc);
    }
}
