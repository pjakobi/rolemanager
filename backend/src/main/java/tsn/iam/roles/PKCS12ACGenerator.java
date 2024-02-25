package tsn.iam.roles;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AttCertIssuer;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.asn1.x509.AttributeCertificateInfo;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.Holder;
import org.bouncycastle.asn1.x509.V2AttributeCertificateInfoGenerator;
import org.bouncycastle.asn1.x509.V2Form;
import org.bouncycastle.asn1.x509.X509AttributeIdentifiers;
import org.bouncycastle.cert.AttributeCertificateHolder;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2AttributeCertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaAttributeCertificateIssuer;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

public class PKCS12ACGenerator {
    
    private static Properties conf;

    //private static final String pkcs12File = "/home/arthur/keystores/ca.p12";
    private static String pkcs12File; //= "src/main/resources/static/pki.p12";
    private static String pwd ;//= "nexium";//PKCS12 file password
    private static String alias ;//= "1";//necessary to get the key

    private static final Logger LOGGER = Logger.getLogger( PKCS12ACGenerator.class.getName() );

    private KeyStore keystore;
    private X509AttributeCertificateHolder ACHolder;
    private X500Name holderName;

    private V2AttributeCertificateInfoGenerator   acInfoGen;
    private ExtensionsGenerator extGenerator;

    public PKCS12ACGenerator(){
        Security.addProvider(new BouncyCastleProvider());
        try {
            conf = PKCS12PropertiesLoader.loadProperties();
            pkcs12File  = conf.getProperty("pkcs12.path");
            pwd = conf.getProperty("pkcs12.pwd");
            alias = conf.getProperty("pkcs12.alias");
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        try {
            this.keystore = KeyStore.getInstance("PKCS12");
        } catch (KeyStoreException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
    }

    public PrivateKey getKey(){
        
        try {
            File file = new File(pkcs12File);
            FileInputStream fis = new FileInputStream(file);
            this.keystore.load(fis, pwd.toCharArray());
            PrivateKey key = (PrivateKey)this.keystore.getKey(alias,pwd.toCharArray());

            return key;
        } 
        catch (NoSuchAlgorithmException e) { e.printStackTrace(); }
        catch ( CertificateException e) { e.printStackTrace(); }
        catch ( IOException e) { e.printStackTrace(); }
        catch ( UnrecoverableKeyException e) { e.printStackTrace(); }
        catch ( KeyStoreException e) { e.printStackTrace(); }
        LOGGER.warning("getKey error");
        return null;
        

    }

    /**
     * Create the X509AttributeCertificateHolder
     * @param holder the DN of the holder
     * @param clearance the value of classList in Clearance following RFC3281 (see https://github.com/P1sec/pycrate/blob/master/pycrate_asn1dir/IETF_PKI_RFC3281/PKIXAttributeCertificate.asn)
     * @throws KeyStoreException
     * @throws OperatorCreationException
     * @throws IOException
     */
    public X509AttributeCertificateHolder createAC(String holder, String policyID, int clearance, Date debut, Date fin) throws KeyStoreException, OperatorCreationException, IOException{

        PrivateKey key = getKey();
        X509Certificate caCert = (X509Certificate) this.keystore.getCertificate(alias);
        this.holderName = new X500Name(holder);

        /* X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.C, "AU");
        builder.addRDN(BCStyle.O, "The Legion of the Bouncy Castle");
        builder.addRDN(BCStyle.L, "Melbourne");
        builder.addRDN(BCStyle.ST, "Victoria");
        builder.addRDN(BCStyle.E, "feedback-crypto@bouncycastle.org"); */

        int min = 0;
        int max = 1000000;

        Integer random_int = (int)Math.floor(Math.random()*(max-min+1)+min);

        X509v2AttributeCertificateBuilder acBldr = new X509v2AttributeCertificateBuilder(
            new AttributeCertificateHolder(/*new JcaX509CertificateHolder(clientCert)*/ holderName),
            new JcaAttributeCertificateIssuer(caCert),
            new BigInteger(random_int.toString()),
            debut,         // not before
            fin);        // not after

            //Add clearance attribute
        DERBitString derClassList = new DERBitString(clearance);
        //Attention : la variable suivante ne peut pas commencer par un chiffre supérieur à 2 ou erreur car ASN1ObjectIdentifier ne le considèrera pas comme un OID
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(policyID);//new ASN1ObjectIdentifier("1.3.26.1.3.1"); 
        ASN1EncodableVector envec = new ASN1EncodableVector();
        envec.add(oid);
        envec.add(derClassList);
        DERSequence derSequence = new DERSequence(envec);
        acBldr.addAttribute(X509AttributeIdentifiers.id_at_clearance, derSequence);

         //      finally create the AC
        this.ACHolder = acBldr.build(new JcaContentSignerBuilder("SHA1WithRSA").setProvider("BC").build(key));


        LOGGER.info("AC created");

        return this.ACHolder;

    }

    /**
     * Generates the Attribute Certificate Info to be signed for the creation of an X509AttributeCertificateHolder
     * WARNING : for some reasons, version is 1 due to BouncyCastle V2AttributeCertificateInfoGenerator internal operation whereas in RFC 5755, AC version is defined as v2
     * @param holder the DN of the holder
     * @param policyID
     * @param clearance
     * @param debut
     * @param fin
     * @return
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws IOException
     * @throws CertificateException
     */

    public AttributeCertificateInfo createAttributeCertificateInfoToBeSigned(String holder, String policyID, int clearance, Date debut, Date fin) throws KeyStoreException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, CertificateException{
        
        this.acInfoGen = new V2AttributeCertificateInfoGenerator();
        this.extGenerator = new ExtensionsGenerator();
        this.holderName = new X500Name(holder);
        //PrivateKey key = getSignaKey();
        X509Certificate caCert = (X509Certificate) this.keystore.getCertificate(alias);
        //X509Certificate caCert = getCertifSigna();

        int min = 0;
        int max = 1000000;

        Integer random_int = (int)Math.floor(Math.random()*(max-min+1)+min);


        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256WithRSA");

        this.acInfoGen.setHolder(new Holder(new GeneralNames(new GeneralName(this.holderName))));
        this.acInfoGen.setIssuer(AttCertIssuer.getInstance(new V2Form(new GeneralNames(new GeneralName(X500Name.getInstance(caCert.getIssuerX500Principal().getEncoded()))))));
        this.acInfoGen.setSerialNumber(new ASN1Integer(random_int.longValue()));
        this.acInfoGen.setStartDate(new ASN1GeneralizedTime(debut));
        this.acInfoGen.setEndDate(new ASN1GeneralizedTime(fin));
        this.acInfoGen.setSignature(sigAlgId); 

        DERBitString derClassList = new DERBitString(clearance);
        //Attention : la variable suivante ne peut pas commencer par un chiffre supérieur à 2 ou erreur car ASN1ObjectIdentifier ne le considèrera pas comme un OID
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(policyID);//new ASN1ObjectIdentifier("1.3.26.1.3.1"); 
        ASN1EncodableVector envec = new ASN1EncodableVector();
        envec.add(oid);
        envec.add(derClassList);
        DERSequence derSequence = new DERSequence(envec);

        this.acInfoGen.addAttribute(new Attribute(X509AttributeIdentifiers.id_at_clearance, new DERSet(derSequence)));
        AttributeCertificateInfo acInfo = this.acInfoGen.generateAttributeCertificateInfo();

        return acInfo;
    }


    /**
     * Sign the Attribute Certificate Info
     * @param acInfo
     * @param encapsulate, if true encapsulated signature, if false detached signature
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws IOException
     * @throws KeyStoreException
     * @throws OperatorCreationException
     * @throws CertificateEncodingException
     * @throws CMSException
     */
    public X509AttributeCertificateHolder signACFromACInfo(AttributeCertificateInfo acInfo, boolean encapsulate) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, IOException, KeyStoreException, OperatorCreationException, CertificateEncodingException, CMSException{
        PrivateKey prKey = getKey();
        Signature signature = Signature.getInstance("SHA256WithRSA", "BC");
        signature.initSign(prKey);
        signature.update(acInfo.getEncoded());
        X509Certificate cert = (X509Certificate) this.keystore.getCertificate(alias);
        List certList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray(acInfo.getEncoded());
        certList.add(cert);
        Store certs = new JcaCertStore(certList);
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner sha256Signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(prKey);
        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(sha256Signer, cert));
        gen.addCertificates(certs);
        CMSSignedData sigData = gen.generate(msg, encapsulate);

        //////TEST////
        System.out.println("SIG " + Base64.getEncoder().encodeToString(sigData.getEncoded()));
        //////////////

        /*
         * Dans org.bouncycastle.cert.CertUtils, la classe que BC utilise pour générer les AC
         * il y a la fonction suivante :
         * private static AttributeCertificate generateAttrStructure(AttributeCertificateInfo attrInfo, AlgorithmIdentifier sigAlgId, byte[] signature)
         *  {
         *      ASN1EncodableVector v = new ASN1EncodableVector();
         *
         *      v.add(attrInfo);
         *      v.add(sigAlgId);
         *      v.add(new DERBitString(signature));
         *
         *      return AttributeCertificate.getInstance(new DERSequence(v));
         *  }
         *
         * On reprend ce template pour la construction de notre AC
         */

         ASN1EncodableVector v = new ASN1EncodableVector();
         v.add(acInfo);
         v.add(acInfo.getSignature());
         v.add(new DERBitString(sigData.getEncoded()));
 
 
         X509AttributeCertificateHolder acHolder = new X509AttributeCertificateHolder(AttributeCertificate.getInstance(new DERSequence(v)));
         
        return acHolder;
    }


    /////////////////////////////////////////////////TTTTTTEST//////////////////////////////////////////////////

    public CMSSignedData signToto() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, IOException, KeyStoreException, OperatorCreationException, CertificateEncodingException, CMSException{
        PrivateKey prKey = getKey();
        Signature signature = Signature.getInstance("SHA256WithRSA", "BC");
        signature.initSign(prKey);

        DERBMPString ds = new DERBMPString("toto");
            ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier("1.0.54.76");//new ASN1ObjectIdentifier("1.3.26.1.3.1"); 
            ASN1EncodableVector envec = new ASN1EncodableVector();
            envec.add(oid);
            envec.add(ds);
            DERSequence derSequence = new DERSequence(envec);
            
        signature.update(derSequence.getEncoded());
        X509Certificate cert = (X509Certificate) this.keystore.getCertificate(alias);
        List certList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray(derSequence.getEncoded());
        certList.add(cert);
        Store certs = new JcaCertStore(certList);
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner sha256Signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(prKey);
        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(sha256Signer, cert));
        gen.addCertificates(certs);
        CMSSignedData sigData = gen.generate(msg, false);

        //////TEST////
        System.out.println("SIG " + Base64.getEncoder().encodeToString(sigData.getEncoded()));
        //////////////
         
        return sigData;
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////


    /**
     * Verify the integrity of a X509AttributeCertificateHolder
     * @param acHolder
     * @param encapsulated, to be true if the signature is encapsulated, to be false if it is detached
     * @return
     */
    public static boolean verifyAC(X509AttributeCertificateHolder acHolder, boolean encapsulated){
        //static function, therefore the provider may not have been added in the constructor, in this case this line prevents the errors which will occur
        if(Security.getProvider(new BouncyCastleProvider().getName()) == null) Security.addProvider(new BouncyCastleProvider());
    
        if (encapsulated){
            InputStream is = new ByteArrayInputStream(acHolder.getSignature());
        
            CMSSignedData sigD = null;
            try {
                sigD = new CMSSignedData(is);
            } catch (CMSException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

            Store                   certStore = sigD.getCertificates();
            Store                   attrCertStore = sigD.getAttributeCertificates();
            SignerInformationStore  signers = sigD.getSignerInfos();
            Collection              c = signers.getSigners();
            Iterator                it = c.iterator();
            

            while (it.hasNext())
            {
                SignerInformation   signer = (SignerInformation)it.next();
                Collection          certCollection = certStore.getMatches(signer.getSID());

                Iterator              certIt = certCollection.iterator();
                
                Integer size = certCollection.size();

                LOGGER.info("Number of certificates : " + size.toString());

                while(certIt.hasNext()){
                    X509CertificateHolder certHolder = (X509CertificateHolder)certIt.next();
                    //X509AttributeCertificateHolder acHolder = (X509AttributeCertificateHolder) attrCertIt.next();

                    try {
                        if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certHolder)))
                        {
                            LOGGER.info("Verified");
                            return true;
                        }
                    } catch (OperatorCreationException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                        return false;
                    } catch (CertificateException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                        return false;
                    } catch (CMSException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                        return false;
                    }   
                }
            }
        }

        else{
            InputStream is = new ByteArrayInputStream(acHolder.getSignature());
            V2AttributeCertificateInfoGenerator acInfoGen = new V2AttributeCertificateInfoGenerator();
            X500Name[] issuernames = acHolder.getIssuer().getNames();
            X500Name[] holdernames = acHolder.getHolder().getEntityNames();
            X500Name issuer = issuernames[0];
            X500Name holder = holdernames[0];


            //AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256WithRSA");

            acInfoGen.setHolder(new Holder(new GeneralNames(new GeneralName(holder))));
            acInfoGen.setIssuer(AttCertIssuer.getInstance(new V2Form(new GeneralNames(new GeneralName(issuer)))));
            acInfoGen.setSerialNumber(new ASN1Integer(acHolder.getSerialNumber()));
            acInfoGen.setStartDate(new ASN1GeneralizedTime(acHolder.getNotBefore()));
            acInfoGen.setEndDate(new ASN1GeneralizedTime(acHolder.getNotAfter()));
            acInfoGen.setSignature(acHolder.getSignatureAlgorithm());

            DERBitString derClassList = new DERBitString(ACInfo.getClearance(acHolder));
            //Attention : la variable suivante ne peut pas commencer par un chiffre supérieur à 2 ou erreur car ASN1ObjectIdentifier ne le considèrera pas comme un OID

            ASN1EncodableVector envec = new ASN1EncodableVector();
            envec.add(ACInfo.getPolicyID(acHolder));
            envec.add(derClassList);
            DERSequence derSequence = new DERSequence(envec);

            acInfoGen.addAttribute(new org.bouncycastle.asn1.x509.Attribute(X509AttributeIdentifiers.id_at_clearance, new DERSet(derSequence)));
            AttributeCertificateInfo acInfo = acInfoGen.generateAttributeCertificateInfo();
            
            CMSSignedData sigD = null;
            try {
                sigD = new CMSSignedData(new CMSProcessableByteArray(acInfo.getEncoded()),is);
            } catch (CMSException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }


            Store                   certStore = sigD.getCertificates();
            Store                   attrCertStore = sigD.getAttributeCertificates();
            SignerInformationStore  signers = sigD.getSignerInfos();
            Collection              c = signers.getSigners();
            Iterator                it = c.iterator();
            
            while (it.hasNext())
            {
                SignerInformation   signer = (SignerInformation)it.next();
                Collection          certCollection = certStore.getMatches(signer.getSID());

                Iterator              certIt = certCollection.iterator();
                
                Integer size = certCollection.size();

                LOGGER.info("Number of certificates : " + size.toString());
                
                while(certIt.hasNext()){
                    X509CertificateHolder certHolder = (X509CertificateHolder)certIt.next();

                    try {
                        if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certHolder)))
                        {
                            LOGGER.info("Verified");
                            return true;
                        }
                    } catch (OperatorCreationException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                        return false;
                    } catch (CertificateException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                        return false;
                    } catch (CMSException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                        return false;
                    }   
                }
            }
        }
        
        LOGGER.warning("Unable to verifu the signature and identify the error");
        return false;
    }
    


}
