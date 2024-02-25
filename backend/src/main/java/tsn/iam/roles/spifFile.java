package tsn.iam.roles;

import java.io.File;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.xmlspif.spif.SPIF;
import org.xmlspif.spif.SecurityClassification;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
public class spifFile {
    private final ResourceBundle bundle = ResourceBundle.getBundle("messages"); //default locale
    private final RolesLogger rlog=new RolesLogger(spifFile.class.getName());
    
	private static Map<BigInteger, String> classifications = new HashMap<BigInteger,String>(); // LACV, label
	private static ASN1ObjectIdentifier policyId;
	private static String policyName;
	private static String fileName;
	
	spifFile(String fileName) throws JAXBException {	
		try {
			// decode XML
	    	Unmarshaller unmarshaller ;
	    	JAXBContext context = JAXBContext.newInstance(SPIF.class);
	    	unmarshaller = context.createUnmarshaller();
    		SPIF spif = (SPIF) unmarshaller.unmarshal(new File(fileName));
    		rlog.doLog(Level.INFO, "spif.start", new Object[] {fileName, spif.getSecurityPolicyId().getId()});
    		
    		// Extract data
    		policyId = new ASN1ObjectIdentifier(spif.getSecurityPolicyId().getId());
    		policyName = spif.getSecurityPolicyId().getName();
    		this.fileName = fileName;
    		rlog.doLog(Level.FINE, "spif.description", new Object[] {policyId.toString(), policyName});
    		
    		spif.getSecurityClassifications().getSecurityClassification().forEach(classif -> {
    			classifications.put(classif.getLacv(), classif.getName());
    			rlog.doLog(Level.FINE, "spif.classif", new Object[] {policyId.toString(),classif.getLacv(),classif.getName()});
    		});
			rlog.doLog(Level.FINE, "spif.decoded", new Object[] {new File(fileName).getName()});
    	} catch (JAXBException e) { 
    		rlog.doLog(Level.WARNING, "spif.decodeErr", new Object[] {fileName,e.getLocalizedMessage()});
    		throw new JAXBException(rlog.toString("spif.decodeErr", new Object[] {fileName,e.getLocalizedMessage()})); 
    	}
	} // spifFile
	
	public ASN1ObjectIdentifier getPolicyId() { return policyId; }
	public String getFileName() { // base name only
		File myFile = new File(fileName);
		return myFile.getName(); 
	}
} // class
