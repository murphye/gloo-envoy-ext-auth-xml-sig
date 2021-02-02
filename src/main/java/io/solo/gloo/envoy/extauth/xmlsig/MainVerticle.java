package io.solo.gloo.envoy.extauth.xmlsig;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.net.JksOptions;
import io.vertx.grpc.VertxServerBuilder;

public class MainVerticle extends AbstractVerticle {

    @Override
    public void start() throws Exception {
        VertxServerBuilder.forPort(vertx, 8000)
                //.useSsl(options -> options
                        // Needed if you use TLS. Add leaf certificate to a keystore (see README) and enable SSL
                        // .setSsl(true).setUseAlpn(true)
                        // .setKeyStoreOptions(new JksOptions().setPath("acme-keystore.jks").setPassword("changeit")))
                        //.setTrustStoreOptions(new JksOptions().setPath("/acme-truststore.jks").setPassword("changeit")))
                .addService(new XmlSigExtAuthService()).build().start();
    }
}
