package io.solo.gloo.envoy.extauth.xmlsig;

import io.vertx.core.AbstractVerticle;
import io.vertx.grpc.VertxServerBuilder;

public class MainVerticle extends AbstractVerticle {

    @Override
    public void start() throws Exception {
        VertxServerBuilder.forPort(vertx, 8000)
                .addService(new XmlSigExtAuthService()).build().start();
    }
}
