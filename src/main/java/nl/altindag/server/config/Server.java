
package nl.altindag.server.config;

import io.quarkus.vertx.http.HttpServerOptionsCustomizer;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.net.PemKeyCertOptions;
import jakarta.enterprise.context.ApplicationScoped;
import java.io.File;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.logging.Level;
import javax.net.ssl.X509ExtendedTrustManager;
import static nl.altindag.server.config.Utils.createAndPersisteCerificate;
import nl.altindag.server.service.FileBasedSslUpdateService;
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.util.TrustManagerUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

@ApplicationScoped
public class Server implements HttpServerOptionsCustomizer {

    public Server() { }

    private static final String CERT_FILE     = "./self-SignedCert.crt" ;
    private static final String CERT_KEY_FILE = "./self-SignedCert.key" ;

    @Override
    public void customizeHttpsServer(HttpServerOptions options) {
        
        Vertx vertx = Vertx.vertx() ;
        Security.addProvider(new BouncyCastleProvider()) ;
      
        try {
          
             Pair<X509Certificate, KeyPair> createCerificate = createAndPersisteCerificate(CERT_FILE, CERT_KEY_FILE);
             X509Certificate certificate = createCerificate.getKey();
             KeyPair         privKey     = createCerificate.getValue();
         
             X509ExtendedTrustManager createCertificateCapturingTrustManager = TrustManagerUtils.createTrustManager(List.of(certificate) );

             X509ExtendedTrustManager createSwappableTrustManager = TrustManagerUtils.createSwappableTrustManager(createCertificateCapturingTrustManager);

             SSLFactory sslFactory = SSLFactory.builder()
                                               .withSwappableTrustMaterial()
                                               .withTrustMaterial(createSwappableTrustManager)
                                               .build();

             var sslUpdateService = new FileBasedSslUpdateService(sslFactory, new File(CERT_FILE), new File(CERT_KEY_FILE));

             // Create Self-SIgned Cert each 10s
             vertx.setPeriodic( 10000, ( Long id) ->  {
                   try {
                           Pair<X509Certificate, KeyPair> certPair = createAndPersisteCerificate(CERT_FILE, CERT_KEY_FILE);
                           sslUpdateService.updateSslMaterial( certPair.getKey() ) ;
                    } catch ( Exception ex) {
                          throw new RuntimeException(ex) ;
                    }
             });
             
             // Config Quarkus Server
            
             PemKeyCertOptions pemKeyCert = new PemKeyCertOptions().setCertValue(Buffer.buffer(Utils.x509CertificateToPem(  certificate ) ))
                                                                   .setKeyValue( Buffer.buffer( Utils.getPrivateKeyAsString( privKey)   ) ); 

             options.setSsl(true)
                    .setUseAlpn(true)
                    .setPort(8443)
                    .setPemKeyCertOptions( pemKeyCert ) ;
             
            System.out.println("Quarkus Started... ") ;
            
         } catch (Exception ex) {
             java.util.logging.Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex) ;
         }
    }
}
