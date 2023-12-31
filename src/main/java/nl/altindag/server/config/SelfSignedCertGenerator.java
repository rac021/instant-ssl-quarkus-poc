
package nl.altindag.server.config;

/**
 *
 * @author ryahiaoui
 */

import java.util.Date ;
import java.time.Instant ;
import java.time.Duration ;
import java.math.BigInteger ;
import java.security.KeyPair ;
import java.security.PublicKey ;
import java.security.cert.X509Certificate ;
import org.bouncycastle.asn1.x500.X500Name ;
import org.bouncycastle.asn1.x509.Extension ;
import org.bouncycastle.cert.CertIOException ;
import java.security.cert.CertificateException ;
import org.bouncycastle.operator.ContentSigner ;
import org.bouncycastle.cert.X509ExtensionUtils ;
import org.bouncycastle.operator.DigestCalculator ;
import org.bouncycastle.asn1.x509.BasicConstraints ;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers ;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier ;
import org.bouncycastle.cert.X509v3CertificateBuilder ;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier ;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo ;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier ;
import org.bouncycastle.jce.provider.BouncyCastleProvider ;
import org.bouncycastle.operator.OperatorCreationException ;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider ;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter ;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder ;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder ;

/**
 * Utility class for generating self-signed certificates.
 *
 */

public class SelfSignedCertGenerator {

  private SelfSignedCertGenerator() {}

  /**
   * Generates a self signed certificate using the BouncyCastle lib.
   *
   * @param keyPair used for signing the certificate with PrivateKey
   * @param hashAlgorithm Hash function
   * @param cn Common Name to be used in the subject dn
   * @param days validity period in days of the certificate
   *
   * @return self-signed X509Certificate
     * @throws org.bouncycastle.operator.OperatorCreationException
   * @throws CertificateException on getting certificate from provider
     * @throws org.bouncycastle.cert.CertIOException
   */
  public static X509Certificate generate( final KeyPair keyPair       ,
                                          final String  hashAlgorithm ,
                                          final String  cn            ,
                                          final int     days          )

    throws OperatorCreationException, CertificateException, CertIOException {
      
    final Instant now    = Instant.now()                               ;
    final Date notBefore = Date.from( now )                            ;
    final Date notAfter  = Date.from(now.plus(Duration.ofDays(days)) ) ;

    final ContentSigner contentSigner = new JcaContentSignerBuilder(hashAlgorithm).build(keyPair.getPrivate() ) ;
    final X500Name      x500Name      = new X500Name("CN=" + cn + ", O=Company" )                          ;
    
    final X509v3CertificateBuilder certificateBuilder =

      new JcaX509v3CertificateBuilder( x500Name                               ,
                                       BigInteger.valueOf(now.toEpochMilli()) ,
                                       notBefore                              ,
                                       notAfter                               ,
                                       x500Name                               ,
                                       keyPair.getPublic()).addExtension(Extension.subjectKeyIdentifier  , false , createSubjectKeyId(keyPair.getPublic()))
                                                           .addExtension(Extension.authorityKeyIdentifier, false , createAuthorityKeyId(keyPair.getPublic()))
                                                           .addExtension(Extension.basicConstraints      , true  , new BasicConstraints(true)             ) ;

    return new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(certificateBuilder.build(contentSigner) )               ;
  }

  /**
   * Creates the hash value of the public key.
   *
   * @param publicKey of the certificate
   *
   * @return SubjectKeyIdentifier hash
   *
   * @throws OperatorCreationException
   */
  private static SubjectKeyIdentifier createSubjectKeyId(final PublicKey publicKey) throws OperatorCreationException {
    
    final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()) ;
    
    final DigestCalculator digCalc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1) ) ;

    return new X509ExtensionUtils(digCalc).createSubjectKeyIdentifier( publicKeyInfo ) ;
  }

  /**
   * Creates the hash value of the authority public key.
   *
   * @param publicKey of the authority certificate
   *
   * @return AuthorityKeyIdentifier hash
   *
   * @throws OperatorCreationException
   */
  private static AuthorityKeyIdentifier createAuthorityKeyId( final PublicKey publicKey ) throws OperatorCreationException {
    
    final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded() ) ;
    
    final DigestCalculator digCalc =  new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1) ) ;

    return new X509ExtensionUtils(digCalc).createAuthorityKeyIdentifier( publicKeyInfo ) ;
  }
  
    
}