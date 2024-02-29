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
    private Set<SpifDescriptor> descriptors = new HashSet<SpifDescriptor>();
    private String spifPath;
    
    // Inspect the SPIF Directory
    public SpifDir(String spifPath) throws JAXBException,InvalidPathException, IOException {
    	rlog.doLog(Level.INFO, "spif.path",new Object[] {spifPath});  	
   		this.spifPath = spifPath;
   		
   		for (File file : new File(spifPath).listFiles()) {	 				
 			try { 
 				SpifFile spifFile = new SpifFile(spifPath, file.getName());
 				SpifDescriptor descr = new SpifDescriptor(spifFile.getPolicyId(),spifFile.getPolicyName(),spifFile.getFileName());
 				
 				for (SpifDescriptor index: descriptors) {
 					if (index.equals(spifFile.getPolicyId())) { // duplicate object id
 						rlog.doLog(Level.INFO, "spif.duplicate",new Object[] {spifFile.getPolicyId(), file.getName()});
 						continue;
 					}
 				}
 				
 				new RolesLogger(className, Level.FINE, "spif.noDuplicate", new Object[] { spifFile.getPolicyId(),spifFile.getFileName() }); 
 				descriptors.add(descr);
 				
 				rlog.doLog(Level.INFO,"spif.loaded", new Object[] {spifFile.getPolicyId(), spifFile.getPolicyName(), spifFile.getFileName()});
 			}  catch (JAXBException e) { continue; } // skip to next file; log elsewhere
    	} // for
   			
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

    
    public Map<BigInteger,String> getClearances(ASN1ObjectIdentifier policyID) throws JAXBException, FileNotFoundException { 
    	Map<BigInteger,String> map = new HashMap<BigInteger,String>();
    	SpifFile spifFile = null;
    	for (SpifDescriptor descr: descriptors) {
    		if (!(descr.getOid().equals(policyID))) continue;
    		try { spifFile = new SpifFile(spifPath, descr.getFile()); }
    		catch (JAXBException e) { 
    			String msg = new MessageFormat(bundle.getString("spif.jaxbErr")).format(new Object[] {policyID, e.getLocalizedMessage()});
    			rlog.doLog(Level.WARNING,"spif.jaxbErr", new Object[] { policyID,e.getLocalizedMessage() });
    			throw new JAXBException(msg);
    		}  // catch
    		return spifFile.getClassifications();
    	} // for
    	// Oid not found in descriptors
    	rlog.doLog(Level.WARNING,"spif.getName.nok", new Object[] {policyID});
    	throw new FileNotFoundException(new MessageFormat(bundle.getString("spif.getName.nok")).format(new Object[] {policyID}));
    } // 	getClearances
    
    public Set<SpifDescriptor> getDescriptors() { return this.descriptors; }
}
