package tsn.iam.roles;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map;
import java.util.Properties;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.TreeSet;
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
 
    

    private static final String className = SpifDir.class.getName();
    private static final Logger LOGGER = Logger.getLogger( className );
    private final ResourceBundle bundle = ResourceBundle.getBundle("messages"); //default locale
    private final RolesLogger rlog=new RolesLogger(className);
    private HashMap<ASN1ObjectIdentifier,SpifFile> spifMap = new HashMap<ASN1ObjectIdentifier,SpifFile>();
    
    // Inspect the SPIF Directory
    public SpifDir(String spifPath) throws JAXBException,InvalidPathException, IOException {
    	rlog.doLog(Level.INFO, "spif.path",new Object[] {spifPath});  	
   		
   		for (File file : new File(spifPath).listFiles()) {	 				
 			try { 
 				SpifFile spifFile = new SpifFile(spifPath, file.getName()); 
 				if (spifMap.containsKey(spifFile.getPolicyId())) {
 					rlog.doLog(Level.INFO, "spif.duplicate",new Object[] {spifFile.getPolicyId(), file.getName()}); 
 					continue;
 				}
 				spifMap.put(spifFile.getPolicyId(),spifFile);
 				rlog.doLog(Level.INFO,"spif.loaded", new Object[] {spifFile.getPolicyId(), file.getName()});
 			}  catch (JAXBException e) { continue; } // skip to next file; log elsewhere
    	} // for
   		

   		for (ASN1ObjectIdentifier oid: spifMap.keySet()) {
   			SpifFile spif = spifMap.get(oid);
   			rlog.doLog(Level.FINE,"spif.dirDebug", new Object[] {oid, spifMap.get(oid), spifMap.size()});
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



//    public String getName(ASN1ObjectIdentifier policyID, Integer lacv){
//    	rlog.doLog(Level.FINE,"spif.getName", new Object[] {policyID,lacv});
//    	BigInteger lacv = spifMap.get(policyID);
//    	if (ht != null) {
//    		String clearance = ht.get(lacv.toString());
//    		if (clearance != null) {    			
//    			rlog.doLog(Level.FINE,"spif.getName.ok", new Object[] {clearance});
//    			return clearance;
//    		}
//   	}
//    	rlog.doLog(Level.FINE,"spif.getName.nok", new Object[] {});
//    	return null; // policy or Lacv not found
//    } // getName

    public Set<ASN1ObjectIdentifier> getPolicies() {
    	Set<ASN1ObjectIdentifier> result = new HashSet<ASN1ObjectIdentifier>();
    	for (ASN1ObjectIdentifier oid: spifMap.keySet()) {
    		rlog.doLog(Level.INFO,"spif.getPoliciesDetails", new Object[] {oid.toString(),spifMap.get(oid) });
    		result.add(oid);
    	}
    	return result;
    }
    
    
    
    public Map<BigInteger,String> getClearances(ASN1ObjectIdentifier policyID) { return spifMap.get(policyID).getClassifications(); } // 	getClearances
    	

}
