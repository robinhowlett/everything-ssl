package com.robinhowlett.ssl;

import org.apache.catalina.connector.Connector;
import org.apache.commons.io.FileUtils;
import org.apache.coyote.http11.Http11Protocol;
import org.apache.tomcat.util.http.fileupload.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.embedded.EmbeddedServletContainerFactory;
import org.springframework.boot.context.embedded.tomcat.TomcatEmbeddedServletContainerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ClassPathResource;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

/**
 * Configure embedded Tomcat and SSL connectors
 */
@Configuration
public class Config {

    @Autowired
    private Environment env;

    // Embedded Tomcat with HTTP and HTTPS support
    @Bean
    public EmbeddedServletContainerFactory servletContainer() {
        TomcatEmbeddedServletContainerFactory tomcat = new
                TomcatEmbeddedServletContainerFactory();
        tomcat.addAdditionalTomcatConnectors(createSSLConnector());
        return tomcat;
    }

    // Creates an SSL connector, sets two-way SSL, key- and trust stores, passwords, ports etc.
    protected Connector createSSLConnector() {
        Connector connector = new Connector(Http11Protocol.class.getCanonicalName());
        Http11Protocol protocol = (Http11Protocol) connector.getProtocolHandler();

        File keyStore = null;
        File trustStore = null;

        try {
            keyStore = getKeyStoreFile();
        } catch (IOException e) {
            throw new IllegalStateException("Cannot access keyStore: [" + keyStore + "] or " +
                    "trustStore: [" + trustStore + "]", e);
        }

        trustStore = keyStore;

        connector.setPort(env.getRequiredProperty("ssl.port", Integer.class));
        connector.setScheme(env.getRequiredProperty("ssl.scheme"));
        connector.setSecure(env.getRequiredProperty("ssl.secure", Boolean.class));

        protocol.setClientAuth(env.getRequiredProperty("ssl.client-auth"));
        protocol.setSSLEnabled(env.getRequiredProperty("ssl.enabled", Boolean.class));

        protocol.setKeyPass(env.getRequiredProperty("ssl.key-password"));
        protocol.setKeystoreFile(keyStore.getAbsolutePath());
        protocol.setKeystorePass(env.getRequiredProperty("ssl.store-password"));
        protocol.setTruststoreFile(trustStore.getAbsolutePath());
        protocol.setTruststorePass(env.getRequiredProperty("ssl.store-password"));
        protocol.setCiphers(env.getRequiredProperty("ssl.ciphers"));

        return connector;
    }

    // support loading the JKS from the classpath (to get around Tomcat limitation)
    private File getKeyStoreFile() throws IOException {
        ClassPathResource resource = new ClassPathResource(env.getRequiredProperty("ssl.store"));

        // Tomcat won't allow reading File from classpath so read as InputStream into temp File
        File jks = File.createTempFile("server_keystore", ".jks");
        InputStream inputStream = resource.getInputStream();
        try {
            FileUtils.copyInputStreamToFile(inputStream, jks);
        } finally {
            IOUtils.closeQuietly(inputStream);
        }

        return jks;
    }
}
