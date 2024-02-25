package tsn.iam.roles;

import java.io.IOException;
import java.security.KeyStoreException;
import java.util.Base64;
import java.util.ResourceBundle;
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


	private static RolesLogger rlog=new RolesLogger(ACInfo.class.getName());
	final ResourceBundle bundle = ResourceBundle.getBundle("messages");
	
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
        rlog.doLog(Level.FINE,"ac.holder", new Object[] {holderName.toString()});
        return holderName;
    } 

    /**
     * 
     * @param ACHolder the X509AttributeCertificate to read
     * @return the value as an integer of the ASN1 BITSTRING of the classList attribute of Clearance, -1 if Clearance isn't found
     */
    public static Integer getClearance(X509AttributeCertificateHolder ACHolder){
        Attribute[] attribs = ACHolder.getAttributes();
        rlog.doLog(Level.FINE,"ac.clearance", new Object[] {attribs.length});

        for (Attribute clearance: attribs)
        {
            rlog.doLog(Level.FINE,"ac.clearance.details", new Object[] {clearance.getAttrType(), clearance.getAttrValues().toString()});

            // We check for the presence of a "Clearance" attribute
            ASN1ObjectIdentifier oidclearance = new ASN1ObjectIdentifier("2.5.1.5.55");
            if (clearance.getAttrType().equals(oidclearance)) {
            	rlog.doLog(Level.FINE,"ac.clearance.found", new Object[] {});
                String subStringClearance = clearance.getAttrValues().toString().substring(clearance.getAttrValues().toString().lastIndexOf("0"), clearance.getAttrValues().toString().lastIndexOf("]") - 1);
                Integer subBit = Integer.parseInt(subStringClearance,16);
                return subBit;
            }
        }
        return -1;
    }


    public static ASN1ObjectIdentifier getPolicyID(X509AttributeCertificateHolder ACHolder){

        Attribute[] attribs = ACHolder.getAttributes();
        rlog.doLog(Level.FINE,"ac.clearance", new Object[] {attribs.length});
        
        ASN1ObjectIdentifier oidclearance = new ASN1ObjectIdentifier("2.5.1.5.55");
        for(Attribute clearance : attribs) {
        	rlog.doLog(Level.FINE,"ac.clearance.details", new Object[] {clearance.getAttrType(), clearance.getAttrValues().toString()});
        	if (!clearance.getAttrType().equals(oidclearance)) continue;
        	rlog.doLog(Level.FINER,"ac.policy.found", new Object[] {});
        	return new ASN1ObjectIdentifier(clearance.getAttrValues().toString().substring(clearance.getAttrValues().toString().lastIndexOf("[") + 1, clearance.getAttrValues().toString().lastIndexOf(",")));
        }
        return null;
    } // getPolicyID
    
    public static Integer getPolicyID(X509AttributeCertificateHolder ACHolder, ASN1ObjectIdentifier policyID) {
    	rlog.doLog(Level.FINE,"ac.clearance", new Object[] {policyID.toString()});
    	Attribute[] attribs = ACHolder.getAttributes();
    	for(Attribute clearance : attribs) {
    		if (!clearance.getAttrType().equals(new ASN1ObjectIdentifier("2.5.1.5.55"))) continue; // not a clearance
    		clearance.getAttrValues();
    	} // for clearance
        
        return -1;
    } // getPolicyID
    
    

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
