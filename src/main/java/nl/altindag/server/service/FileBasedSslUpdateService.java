
package nl.altindag.server.service;

import java.io.File;
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.util.SSLFactoryUtils;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

public final class FileBasedSslUpdateService {

    private static final Logger LOGGER = Logger.getLogger(FileBasedSslUpdateService.class);

    private ZonedDateTime lastModifiedTimeIdentityStore = ZonedDateTime.ofInstant(Instant.EPOCH, ZoneOffset.UTC);
    private ZonedDateTime lastModifiedTimeTrustStore    = ZonedDateTime.ofInstant(Instant.EPOCH, ZoneOffset.UTC);

    private final SSLFactory baseSslFactory;

    File certFile    ;
    File certKeyFile ; 
        
    public FileBasedSslUpdateService(SSLFactory baseSslFactory, File crt, File key) {
        this.baseSslFactory = baseSslFactory;
        this.certFile       = crt ;
        this.certKeyFile    = key ;
        LOGGER.info("Started listening for any changes on the keystore and truststore files...");
    }

    public void updateSslMaterial(  X509Certificate cert ) {
        try {
            if ( certFile.exists() && certKeyFile.exists() ) {
                BasicFileAttributes identityAttributes = Files.readAttributes( certFile.toPath(), BasicFileAttributes.class);
                BasicFileAttributes trustStoreAttributes = Files.readAttributes( certKeyFile.toPath(), BasicFileAttributes.class);

                boolean identityUpdated   = lastModifiedTimeIdentityStore.isBefore(ZonedDateTime.ofInstant(identityAttributes.lastModifiedTime().toInstant(), ZoneOffset.UTC));
                boolean trustStoreUpdated = lastModifiedTimeTrustStore.isBefore(ZonedDateTime.ofInstant(trustStoreAttributes.lastModifiedTime().toInstant(), ZoneOffset.UTC));

                if (identityUpdated && trustStoreUpdated) {
                    
                    LOGGER.info("Keystore files have been changed. Trying to read the file content and preparing to update the ssl material");
                    // X509ExtendedTrustManager createCertificateCapturingTrustManager = TrustManagerUtils.createCertificateCapturingTrustManager(List.of(cert) );
                    // X509ExtendedTrustManager createSwappableTrustManager = TrustManagerUtils.createTrustManager( List.of( cert));

                    SSLFactory newUpdatedSslFactory = SSLFactory.builder()
                                                                .withInflatableTrustMaterial()
                                                                .withTrustMaterial( cert)
                                                                .build();
                    
                    SSLFactoryUtils.reload(baseSslFactory, newUpdatedSslFactory, true) ;

                    lastModifiedTimeIdentityStore = ZonedDateTime.ofInstant(identityAttributes.lastModifiedTime().toInstant(), ZoneOffset.UTC  ) ;
                    lastModifiedTimeTrustStore    = ZonedDateTime.ofInstant(trustStoreAttributes.lastModifiedTime().toInstant(), ZoneOffset.UTC) ;

                    LOGGER.info("Updating ssl material finished") ;
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
