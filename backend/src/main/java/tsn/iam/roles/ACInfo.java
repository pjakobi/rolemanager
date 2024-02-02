package tsn.iam.roles;

import java.io.IOException;
import java.security.KeyStoreException;
import java.util.Base64;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.cert.AttributeCertificateIssuer;
import org.bouncycastle.cert.X509AttributeCertificateHolder;

public class ACInfo {

    private static final Logger LOGGER = Logger.getLogger( ACInfo.class.getName() );
    //private static final ConsoleHandler consoleHandler = new ConsoleHandler();


    public static X500Principal getIssuer(X509AttributeCertificateHolder ACHolder) throws KeyStoreException, IOException{
        AttributeCertificateIssuer issuer = ACHolder.getIssuer();

        X500Name[] names500issuer = issuer.getNames();//bc
        X500Name name5issuer = names500issuer[0];//bc

        X500Principal bcPrincipal = new X500Principal(name5issuer.getEncoded());
        
        return bcPrincipal;
    }

    public static X500Name getHolder(X509AttributeCertificateHolder ACHolder){
        X500Name[] holders = ACHolder.getHolder().getEntityNames();
        X500Name holderName = holders[0];
        LOGGER.info(holderName.toString());
        //System.out.println(holderName);
        return holderName;
    } 

    /**
     * 
     * @param ACHolder the X509AttributeCertificate to read
     * @return the value as an integer of the ASN1 BITSTRING of the classList attribute of Clearance, -1 if Clearance isn't found
     */
    public static Integer getClearance(X509AttributeCertificateHolder ACHolder){
        Attribute[] attribs = ACHolder.getAttributes();
        LOGGER.info("getClearance : cert has " + attribs.length + " attributes:");
        //System.out.println("cert has " + attribs.length + " attributes:");


        for (int i = 0; i < attribs.length; i++)
        {
            Attribute clearance = attribs[i];
            LOGGER.info("getClearance : OID: " + clearance.getAttrType());
            //System.out.println("OID: " + clearance.getAttrType());
            
            LOGGER.info("getClearance : policyID and classList : " + clearance.getAttrValues().toString());
            //System.out.println( clearance.getAttrValues());
            
            // We check for the presence of a "Clearance" attribute
            ASN1ObjectIdentifier oidclearance = new ASN1ObjectIdentifier("2.5.1.5.55");
            if (clearance.getAttrType().equals(oidclearance)){
                LOGGER.info("getClearance : clearance read from cert");
                //System.out.println("clearance read form cert!");
                String subStringClearance = clearance.getAttrValues().toString().substring(clearance.getAttrValues().toString().lastIndexOf("0"), clearance.getAttrValues().toString().lastIndexOf("]") - 1);
                Integer subBit = Integer.parseInt(subStringClearance,16);
                return subBit;
            }
        }

        return -1;
    
    }


    public static String getPolicyID(X509AttributeCertificateHolder ACHolder){

        Attribute[] attribs = ACHolder.getAttributes();
        LOGGER.info("getPolicyID : cert has " + attribs.length + " attributes");
        //System.out.println("cert has " + attribs.length + " attributes:");


        for (int i = 0; i < attribs.length; i++)
        {
            Attribute clearance = attribs[i];
            LOGGER.info("getPolicyID : OID: " + clearance.getAttrType());
            LOGGER.info("getPolicyID : policyID and classList : " + clearance.getAttrValues().toString());
            
            // We check for the presence of a "Clearance" attribute
            ASN1ObjectIdentifier oidclearance = new ASN1ObjectIdentifier("2.5.1.5.55");
            if (clearance.getAttrType().equals(oidclearance)){
                LOGGER.info("getPolicyID : clearance read from cert");
                String subStringPolicyID = clearance.getAttrValues().toString().substring(clearance.getAttrValues().toString().lastIndexOf("[") + 1, clearance.getAttrValues().toString().lastIndexOf(","));
                
                return subStringPolicyID;
            }
        }

        return "Not found";

    }

    public static String getStartDate(X509AttributeCertificateHolder ACHolder){
        return ACHolder.getNotBefore().toString();
    }

    public static String getEndDate(X509AttributeCertificateHolder ACHolder){
        return ACHolder.getNotAfter().toString();
    }

    /**
     * 
     * @return the ASN1 DER encoded String of the X509AttributeCertificateHolder
     * @throws IOException
     */
    public static String getEncodedAC(X509AttributeCertificateHolder ACHolder) throws IOException{
        return Base64.getEncoder().encodeToString(ACHolder.getEncoded());
    }

    public static byte[] getSignature(X509AttributeCertificateHolder ACHolder) {
        return ACHolder.getSignature();
        
    }
    
}
