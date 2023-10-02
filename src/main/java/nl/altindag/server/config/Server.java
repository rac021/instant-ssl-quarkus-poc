
package nl.altindag.server.config;

import io.quarkus.vertx.http.HttpServerOptionsCustomizer;
import io.vertx.core.Vertx;
import io.vertx.core.VertxOptions;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.net.KeyCertOptions;
import io.vertx.core.net.TrustOptions;
import jakarta.enterprise.context.ApplicationScoped;
import java.io.File;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import static nl.altindag.server.config.Utils.createAndPersisteCerificate;
import nl.altindag.server.service.FileBasedSslUpdateService;
import nl.altindag.ssl.SSLFactory;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

@ApplicationScoped
public class Server implements HttpServerOptionsCustomizer {

    public Server() { }

    private static final String CERT_FILE     = "./self-SignedCert.crt" ;
    private static final String CERT_KEY_FILE = "./self-SignedCert.key" ;

    @Override
    public void customizeHttpsServer(HttpServerOptions options) {
        VertxOptions vertxOptions = new VertxOptions();
        vertxOptions.setBlockedThreadCheckInterval(1000*60*60);
        Vertx vertx = Vertx.vertx(vertxOptions) ;

        Security.addProvider(new BouncyCastleProvider()) ;
      
        try {
          
             Pair<X509Certificate, KeyPair> createCerificate = createAndPersisteCerificate(CERT_FILE, CERT_KEY_FILE);
             X509Certificate certificate = createCerificate.getKey();
             KeyPair         privKey     = createCerificate.getValue();

            SSLFactory sslFactory = SSLFactory.builder()
                    .withSwappableTrustMaterial()
                    .withIdentityMaterial(privKey.getPrivate(), null, certificate)
                    .withTrustMaterial(certificate)
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

            options.setSsl(true)
                    .setUseAlpn(true)
                    .setPort(8443)
                    .setKeyCertOptions(sslFactory.getKeyManager().map(KeyCertOptions::wrap).orElseThrow())
                    .setTrustOptions(sslFactory.getTrustManager().map(TrustOptions::wrap).orElseThrow());
             
            System.out.println("Quarkus Started... ") ;
            
         } catch (Exception ex) {
             java.util.logging.Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex) ;
         }
    }
}
