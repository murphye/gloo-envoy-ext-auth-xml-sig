package io.solo.gloo.envoy.extauth.xmlsig;

import io.envoyproxy.envoy.service.auth.v3.AuthorizationGrpc;
import io.envoyproxy.envoy.service.auth.v3.CheckRequest;
import io.envoyproxy.envoy.service.auth.v3.CheckResponse;
import io.grpc.stub.StreamObserver;
import com.google.rpc.Code;
import com.google.rpc.Status;

public class XmlSigExtAuthService extends AuthorizationGrpc.AuthorizationImplBase {
    @Override
    public final void check(CheckRequest checkRequest, StreamObserver<CheckResponse> responseObserver) {
        CheckResponse.Builder checkResponseBuilder = CheckResponse.newBuilder();
        Status.Builder statusBuilder = Status.newBuilder();

        try {
            String contentType = checkRequest.getAttributes().getRequest().getHttp().getHeadersOrThrow("Content-Type");

            if(contentType.equals("text/xml") || contentType.equals("application/soap+xml")) {

                // The requestBody contains the entire SOAP message
                String requestBody = checkRequest.getAttributes().getRequest().getHttp().getBody();

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
        }
        CheckResponse checkResponse = checkResponseBuilder.build();

        responseObserver.onNext(checkResponse);
        responseObserver.onCompleted();
    }
}
