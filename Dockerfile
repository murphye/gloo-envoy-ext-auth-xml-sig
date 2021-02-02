FROM openjdk:11

ENV VERTICLE_FILE gloo-envoy-ext-auth-xml-sig-1.0.0-SNAPSHOT-fat.jar

COPY target/$VERTICLE .
COPY certs/acme-truststore.jks .

WORKDIR .
ENTRYPOINT ["sh", "-c"]

EXPOSE 8000
CMD ["exec java -Djavax.net.ssl.trustStore=acme-truststore.jks -Djavax.net.ssl.trustStorePassword=changeit -jar $VERTICLE_FILE "]
