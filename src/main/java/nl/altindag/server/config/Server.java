
package nl.altindag.server.config;

import io.quarkus.vertx.http.HttpServerOptionsCustomizer;
import io.vertx.core.Vertx;
import io.vertx.core.VertxOptions;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.net.KeyCertOptions;
import io.vertx.core.net.TrustOptions;
import jakarta.enterprise.context.ApplicationScoped;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import static nl.altindag.server.config.Utils.createAndPersisteCerificate;
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.util.SSLFactoryUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jboss.logging.Logger;

@ApplicationScoped
public class Server implements HttpServerOptionsCustomizer {

    private static final Logger LOGGER = Logger.getLogger(Server.class);

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
          
             Pair<X509Certificate, KeyPair> identity = createAndPersisteCerificate(CERT_FILE, CERT_KEY_FILE);

            SSLFactory sslFactory = SSLFactory.builder()
                    .withSwappableIdentityMaterial()
                    .withIdentityMaterial(identity.getValue().getPrivate(), null, identity.getKey())
                    .withTrustMaterial(identity.getKey())
                    .build();

             // Create Self-SIgned Cert each 30s
             vertx.setPeriodic( 30000, ( Long id) ->  {
                   try {
                       LOGGER.info("Started updating ssl material") ;
                       Pair<X509Certificate, KeyPair> anotherIdentity = createAndPersisteCerificate(CERT_FILE, CERT_KEY_FILE);

                       SSLFactory updatedSslFactory = SSLFactory.builder()
                               .withIdentityMaterial(anotherIdentity.getValue().getPrivate(), null, anotherIdentity.getKey())
                               .build();

                       SSLFactoryUtils.reload(sslFactory, updatedSslFactory);

                       LOGGER.info("Updating ssl material finished") ;
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
