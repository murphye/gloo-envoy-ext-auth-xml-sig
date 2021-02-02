package io.solo.gloo.envoy.extauth.xmlsig;

import io.vertx.core.AbstractVerticle;
import io.vertx.grpc.VertxServerBuilder;

public class MainVerticle extends AbstractVerticle {

    @Override
    public void start() throws Exception {
      VertxServerBuilder
        .forAddress(vertx, "localhost", 5000) // TODO: Change from localhost? Which port to run?
        .addService(new XmlSigExtAuthService())
        .build()
        .start();
    }
}
