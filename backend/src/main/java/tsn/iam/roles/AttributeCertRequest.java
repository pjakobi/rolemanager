package tsn.iam.roles;

import java.io.IOException;
import java.util.Date;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.ldap.LdapName;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AttributeCertificateInfo;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public class AttributeCertRequest {
	private static final String className = AttributeCertRequest.class.getName();
    private static final Logger LOGGER = Logger.getLogger( className );
    private final ResourceBundle bundle = ResourceBundle.getBundle("messages"); //default locale
    private final RolesLogger rlog=new RolesLogger(className);
    
	public AttributeCertRequest (
			LdapName entry, 
			LdapName holder, 
			LdapName requestor, 
			int clearance, 
			ASN1ObjectIdentifier policyID, 
			long startMillis, 
			long endMillis, 
			String description) throws IOException, NamingException 
		{

        rlog.doLog(Level.FINE, "ac.add",new Object[] {entry.toString()});

        DERBitString derClassList = new DERBitString(clearance);
        DERGeneralizedTime start = new DERGeneralizedTime(new Date(startMillis));
        DERGeneralizedTime end = new DERGeneralizedTime(new Date(endMillis));
        ASN1EncodableVector envec = new ASN1EncodableVector();
        envec.add(policyID);
        envec.add(derClassList);
        DERSequence derSequence = new DERSequence(envec);

        Attributes attributes = new BasicAttributes();
        Attribute clearanceRequest = new BasicAttribute("objectClass", "clearanceRequest");
        Attribute top = new BasicAttribute("objectClass", "top");
        Attribute clearanceAttribute;
		try { clearanceAttribute = new BasicAttribute("clearance", derSequence.getEncoded()); } 
		catch (IOException e) {
			rlog.doLog(Level.WARNING, "ac.add.error",new Object[] {e.getLocalizedMessage()});
			e.printStackTrace();
			throw new IOException(e.getLocalizedMessage());
		}
        Attribute startAttribute = new BasicAttribute("notBeforeTime", start.getTimeString());
        Attribute endAttribute = new BasicAttribute("notAfterTime", end.getTimeString());
        Attribute reqAttribute = new BasicAttribute("requestor", requestor.toString());
        Attribute holdAttribute = new BasicAttribute("holder", holder);
        Attribute descrAttribute = new BasicAttribute("description",description);
        
        attributes.put(clearanceRequest);    
        attributes.put(clearanceAttribute);
        attributes.put(descrAttribute);
        attributes.put(startAttribute);
        attributes.put(endAttribute);
        attributes.put(reqAttribute);
        attributes.put(holdAttribute);
        
        JndidapAPI.addACRequest(entry, attributes);
	}
}
