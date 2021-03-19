package io.solo.gloo.envoy.extauth.xmlsig;

import io.envoyproxy.envoy.service.auth.v2.AuthorizationGrpc;
import io.envoyproxy.envoy.service.auth.v2.CheckRequest;
import io.envoyproxy.envoy.service.auth.v2.CheckResponse;
import io.grpc.stub.StreamObserver;

import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.google.rpc.Code;
import com.google.rpc.Status;

public class XmlSigExtAuthService extends AuthorizationGrpc.AuthorizationImplBase {
    @Override
    public final void check(CheckRequest checkRequest, StreamObserver<CheckResponse> responseObserver) {
        CheckResponse.Builder checkResponseBuilder = CheckResponse.newBuilder();
        Status.Builder statusBuilder = Status.newBuilder();

        var logger = Logger.getLogger(XmlSigExtAuthService.class.getName());

        try {
            String contentType = checkRequest.getAttributes().getRequest().getHttp().getHeadersOrThrow("content-type");

            if(contentType.equals("text/xml") || contentType.equals("application/soap+xml")) {

                // The requestBody contains the entire SOAP message
                String requestBody = checkRequest.getAttributes().getRequest().getHttp().getBody();
                logger.log(Level.FINEST, requestBody);

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
        catch(CertificateException ce) {
            checkResponseBuilder = checkResponseBuilder.setStatus(statusBuilder.setCode(Code.PERMISSION_DENIED_VALUE).build());
        }
        catch(Exception e) {
            checkResponseBuilder = checkResponseBuilder.setStatus(statusBuilder.setCode(Code.UNKNOWN_VALUE).build());
            logger.severe(e.getMessage());
            e.printStackTrace();
        }

        CheckResponse checkResponse = checkResponseBuilder.build();
        logger.log(Level.FINEST, "CheckResponse status code: " + checkResponse.getStatus().getCode());

        responseObserver.onNext(checkResponse);
        responseObserver.onCompleted();
    }
}
