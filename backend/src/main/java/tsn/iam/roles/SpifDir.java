package tsn.iam.roles;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map;
import java.util.Properties;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.logging.Logger;
import java.util.logging.Level;
import org.xmlspif.spif.SPIF;
import org.xmlspif.spif.SecurityCategoryTagSet;
import org.xmlspif.spif.SecurityClassification;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;
import java.io.FileNotFoundException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.MessageFormat;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public class SpifDir {
    private static Properties conf;
        
    private static Map<ASN1ObjectIdentifier,Hashtable<BigInteger,String>> spifMap = new HashMap<ASN1ObjectIdentifier,Hashtable<BigInteger,String>>();
    private static Map<String,String> descriptions = new HashMap<String,String>(); // LACV, label
    private static final String className = SpifDir.class.getName();
    private static final Logger LOGGER = Logger.getLogger( className );
    private final ResourceBundle bundle = ResourceBundle.getBundle("messages"); //default locale
    private final RolesLogger rlog=new RolesLogger(className);
    
    private Set<spifFile> dir = new HashSet<>();
    private Set<ASN1ObjectIdentifier> policies = new HashSet<ASN1ObjectIdentifier>();
    
    // Inspect the SPIF Directory
    public SpifDir(String spifPath) throws JAXBException,InvalidPathException, IOException {
    	rlog.doLog(Level.INFO, "spif.path",new Object[] {spifPath});  	
    	try {
    		Files.list(Paths.get(spifPath)).forEach(file -> { // every file in spifPath 
    			rlog.doLog(Level.INFO, "spif.loaded", new Object[] {file.getFileName()});
    			try {
    				spifFile myFile = new spifFile(spifPath + "/" + file.getFileName());
   					if (!(checkDuplicate(myFile.getPolicyId(), myFile.getFileName()))) dir.add(myFile); 
    				
    		} catch (JAXBException e) { } // logged in spifData - do nothing else
    		}); 
    	} catch (IOException e) {
    		rlog.doLog(Level.FINE,"spif.readDirErr", new Object[] {spifPath, e.getLocalizedMessage()});
    		throw new IOException(rlog.toString("spif.readDirErr",new Object[] {spifPath, e.getLocalizedMessage()}));
    	} 
    } // SpifInfo

  
//    public String getLACV(String policyID, String role){
//        for(int i = 0; i<spifMap.get(policyID).size();i++){
//            String str =  spifMap.get(policyID).get(i).values().toString().substring(1, spifMap.get(policyID).get(i).values().toString().length()-1);
//            LOGGER.info("Role label and policy ID received : " + policyID + " - " + role);
//            if(str.equals(role)){
//                LOGGER.info("LACV returned : " + spifMap.get(policyID).get(i).keySet().toString().substring(1, spifMap.get(policyID).get(i).keySet().toString().length()-1)); 
//                return spifMap.get(policyID).get(i).keySet().toString().substring(1, spifMap.get(policyID).get(i).keySet().toString().length()-1);
//            }
//        }
//        return "null";
//    }

    public Boolean checkDuplicate(ASN1ObjectIdentifier policy, String fileName) {
    	rlog.doLog(Level.FINE,"spif.checkDuplicate", new Object[] {policy,fileName});

    	if (policies.contains(policy)) { // Duplicate
    		rlog.doLog(Level.WARNING,"spif.duplicate", new Object[] {policy, fileName});
    		return true;
    	} else {
    		policies.add(policy);
    		return false;
    	}
    } // checkDuplicate

    public String getName(ASN1ObjectIdentifier policyID, Integer lacv){
    	rlog.doLog(Level.FINE,"spif.getName", new Object[] {policyID,lacv});
    	Hashtable<BigInteger,String> ht = spifMap.get(policyID);
    	if (ht != null) {
    		String clearance = ht.get(lacv.toString());
    		if (clearance != null) {    			
    			rlog.doLog(Level.FINE,"spif.getName.ok", new Object[] {clearance});
    			return clearance;
    		}
    	}
    	rlog.doLog(Level.FINE,"spif.getName.nok", new Object[] {});
    	return null; // policy or Lacv not found
    } // getName


    public Hashtable<BigInteger,String> getClearances(ASN1ObjectIdentifier policyID) { return spifMap.get(policyID); }

}
