package io.solo.gloo.envoy.extauth.xmlsig;

import java.io.File;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class TestPemReader
{
    @Test
    public void testLoadKeyStore()
            throws Exception
    {
        KeyStore keyStore = PemReader.loadKeyStore(getResourceFile("rsa.crt"), getResourceFile("rsa.key"), Optional.empty());
        assertCertificateChain(keyStore);
        assertNotNull(keyStore.getKey("key", new char[0]));
        assertNotNull(keyStore.getCertificate("key"));
    }

    @Test
    public void loadTrustStore()
            throws Exception
    {
        KeyStore keyStore = PemReader.loadTrustStore(getResourceFile("rsa.crt"));
        assertCertificateChain(keyStore);
    }

    private static void assertCertificateChain(KeyStore keyStore)
            throws KeyStoreException
    {
        ArrayList<String> aliases = Collections.list(keyStore.aliases());
        assertEquals(aliases.size(), 1);
        assertNotNull(keyStore.getCertificate(aliases.get(0)));
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
