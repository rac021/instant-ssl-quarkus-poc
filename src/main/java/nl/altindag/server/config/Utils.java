
package nl.altindag.server.config ;

import java.util.Base64 ;
import java.io.FileWriter ;
import java.io.IOException ;
import java.io.StringWriter ;
import java.security.KeyPair ;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate ;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter ;

/**
 *
 * @author ryahiaoui
 */

public class Utils {

  public static void writeToFile( String fileName, String content ) {
        
        try( FileWriter writer = new FileWriter( fileName, true   ) ) {
        
            writer.write(content ) ; 
        
        } catch( IOException e   ) {
            throw new RuntimeException( e ) ;
        }
    }
     
  public static String x509CertificateToPem( final X509Certificate cert ) throws IOException  {

    final StringWriter writer    = new StringWriter()       ;
    try ( JcaPEMWriter pemWriter = new JcaPEMWriter(writer) ) {
          pemWriter.writeObject( cert ) ;
          pemWriter.flush()             ;
    }
    return writer.toString()            ;
  }

  public static String getPrivateKeyAsString( final KeyPair keyPair) throws IOException {
      
    return "-----BEGIN PRIVATE KEY-----\n"                                       +
           Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()) + 
           "\n-----END PRIVATE KEY-----\n"                                       ;
  }
  
  public static Pair<X509Certificate, KeyPair> createAndPersisteCerificate( String certFile, String certKeyFile ) throws Exception {
        
        KeyPairGenerator keyPairGenerator1 = KeyPairGenerator.getInstance("RSA")               ;
        KeyPair          keyPair1          = keyPairGenerator1.generateKeyPair()               ;
        X509Certificate selSignedCert1     = SelfSignedCertGenerator.generate( keyPair1        ,
                                                                               "SHA256withRSA" ,
                                                                               "certMe"        ,
                                                                               365           ) ;
        writeToFile(certFile    , Utils.x509CertificateToPem(  selSignedCert1 ) ) ;
        writeToFile(certKeyFile , Utils.getPrivateKeyAsString( keyPair1)        ) ;
        System.out.println("New X509Certificate Generated... ")                   ;
        return Pair.of( selSignedCert1 , keyPair1 )                               ;
    }
}
