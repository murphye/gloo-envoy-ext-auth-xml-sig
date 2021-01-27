package io.solo.gloo.envoy.extauthz.xmlsig;

import io.envoyproxy.envoy.service.auth.v3.CheckRequest;
import io.envoyproxy.envoy.service.auth.v3.CheckResponse;
import io.grpc.stub.StreamObserver;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.concurrent.TimeUnit;

import com.google.rpc.Code;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(VertxExtension.class)
public class XmlSigExtAuthzServiceTest {

    private String getFileString(String fileName) throws IOException {
        File file = new File(getClass().getClassLoader().getResource(fileName).getFile());
        return Files.readString(file.toPath());
    }

    private void validateXml(VertxTestContext testContext, String fileName, boolean shouldFail) throws Throwable {
        XmlSigExtAuthzService xmlSigExtAuthzService = new XmlSigExtAuthzService();

        var checkRequestBuilder = CheckRequest.newBuilder();
        var attributesBuilder = checkRequestBuilder.getAttributesBuilder();
        var requestBuilder = attributesBuilder.getRequestBuilder();
        var httpBuilder = requestBuilder.getHttpBuilder();

        httpBuilder.putHeaders("Content-Type", "text/xml");
        httpBuilder.setBody(getFileString(fileName));

        requestBuilder.setHttp(httpBuilder);
        attributesBuilder.setRequest(requestBuilder);
        checkRequestBuilder.setAttributes(attributesBuilder);

        CheckRequest checkRequest = checkRequestBuilder.build();

        StreamObserver<CheckResponse> responseObserver = new StreamObserver<CheckResponse>(){
            @Override
            public void onNext(CheckResponse checkResponse) {
                if(checkResponse.getStatus().getCode() == Code.OK_VALUE) {
                    if(shouldFail) {
                        // Unexpected success for invalid XML
                        testContext.failNow(new Exception("It should have failed, but had an OK_VALUE instead."));
                    }
                    else {
                        // Expected success for valid XML
                        testContext.completeNow();
                    }
                }
                else {
                    if(shouldFail) {
                        // Expected failure for invalid XML
                        testContext.completeNow();
                    }
                    else {
                        // Unexpected failure for valid XML
                        testContext.failNow(new Exception("Response Code is: " + checkResponse.getStatus().getCode()));
                    }
                }
            }

            @Override
            public void onError(Throwable t) {
                testContext.failNow(t);
            }

            @Override
            public void onCompleted() {
                testContext.completeNow();
            }
        };

        xmlSigExtAuthzService.check(checkRequest, responseObserver);

        assertTrue(testContext.awaitCompletion(1, TimeUnit.SECONDS));

        if (testContext.failed()) {
            throw testContext.causeOfFailure();
        }
    }

    @Test
    void validXml(VertxTestContext testContext) throws Throwable {
        validateXml(testContext, "valid.xml", false);

    }

    @Test
    void invalidXml(VertxTestContext testContext) throws Throwable {
        validateXml(testContext, "invalid.xml", true);

    }
}
