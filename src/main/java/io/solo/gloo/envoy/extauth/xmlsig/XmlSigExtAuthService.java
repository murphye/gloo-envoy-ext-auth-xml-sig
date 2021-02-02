package io.solo.gloo.envoy.extauth.xmlsig;

import io.envoyproxy.envoy.service.auth.v2.AuthorizationGrpc;
import io.envoyproxy.envoy.service.auth.v2.CheckRequest;
import io.envoyproxy.envoy.service.auth.v2.CheckResponse;
import io.grpc.stub.StreamObserver;

import com.google.rpc.Code;
import com.google.rpc.Status;

public class XmlSigExtAuthService extends AuthorizationGrpc.AuthorizationImplBase {
    @Override
    public final void check(CheckRequest checkRequest, StreamObserver<CheckResponse> responseObserver) {
        CheckResponse.Builder checkResponseBuilder = CheckResponse.newBuilder();
        Status.Builder statusBuilder = Status.newBuilder();

        var logger = java.util.logging.Logger.getLogger(XmlSigExtAuthService.class.getName());

        try {
            String contentType = checkRequest.getAttributes().getRequest().getHttp().getHeadersOrThrow("content-type");


            if(contentType.equals("text/xml") || contentType.equals("application/soap+xml")) {

                // The requestBody contains the entire SOAP message
                String requestBody = checkRequest.getAttributes().getRequest().getHttp().getBody();

System.out.println(requestBody);

                if(SoapMessageValidator.validate(requestBody)) {
                    checkResponseBuilder = checkResponseBuilder.setStatus(statusBuilder.setCode(Code.OK_VALUE).build());
                }
                else {
                    checkResponseBuilder = checkResponseBuilder.setStatus(statusBuilder.setCode(Code.PERMISSION_DENIED_VALUE).build());
                }
            }
            else {
                checkResponseBuilder = checkResponseBuilder.setStatus(statusBuilder.setCode(Code.INVALID_ARGUMENT_VALUE).build());
            }
        }
        /* TODO: How to properly handle these types of validation errors (not able to catch here)
        catch(sun.security.validator.ValidatorException ve) {

        }
        */
        catch(Exception e) {
            checkResponseBuilder = checkResponseBuilder.setStatus(statusBuilder.setCode(Code.UNKNOWN_VALUE).build());
            e.printStackTrace();
            logger.severe(e.getMessage());
        }
        CheckResponse checkResponse = checkResponseBuilder.build();
        // TODO: Can we return an error message?

        System.out.println("CheckResponse status code: " + checkResponse.getStatus().getCode());

        logger.info("CheckResponse status code: " + checkResponse.getStatus().getCode());

        responseObserver.onNext(checkResponse);
        responseObserver.onCompleted();
    }
}
