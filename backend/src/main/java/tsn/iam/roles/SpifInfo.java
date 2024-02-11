package tsn.iam.roles;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.Properties;
import java.util.ResourceBundle;
import java.util.logging.Logger;
import java.util.logging.Level;
import org.xmlspif.spif.SPIF;
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
public class SpifInfo {
    private static Properties conf;
        
    private static Map<String,ArrayList<Hashtable<String,String>>> spifMap = new HashMap<String,ArrayList<Hashtable<String,String>>>();
    private static final String className = SpifInfo.class.getName();
    private static final Logger LOGGER = Logger.getLogger( className );
    private final ResourceBundle bundle = ResourceBundle.getBundle("messages"); //default locale
    private MessageFormat formatter;
    

    
    // Decode one SPIF file & store it in spifMap
    private void spifData(Unmarshaller jaxbUnmarshaller, String spifName) throws JAXBException {
    	try {
    		//spifLog(Level.INFO, "spif.start", new Object[] {spifName});
    		new RolesLogger(className, Level.INFO, "spif.start", new Object[] {spifName});
    		
    		SPIF mySpif = (SPIF) jaxbUnmarshaller.unmarshal(new File(spifName));
    		Hashtable<String,String> spifTable = new Hashtable<String,String>();
			for (SecurityClassification classif: mySpif.getSecurityClassifications().getSecurityClassification()) 
				spifTable.put(classif.getLacv().toString(), classif.getName());
			ArrayList<Hashtable<String,String>> spifList = new ArrayList<Hashtable<String,String>>();
			spifList.add(spifTable);
			spifMap.put(mySpif.getSecurityPolicyId().getId(), spifList);
			
			new RolesLogger(className, Level.FINE, "spif.decoded", new Object[] {spifName});
    	} catch (JAXBException e) { 
    		new RolesLogger(className, Level.WARNING, "spif.decodeErr", new Object[] {spifName,e.getLocalizedMessage()});
    		throw new JAXBException(spifName + ": " + e.getLocalizedMessage()); 
    	}
    }
    
    // Inspect the SPIF Directory
    public SpifInfo(String spifPath) throws JAXBException,InvalidPathException, IOException {
    	new RolesLogger(className, Level.FINE, "spif.path",new Object[] {spifPath});
    	Unmarshaller jaxbUnmarshaller ;
    	
    	JAXBContext context = JAXBContext.newInstance(SPIF.class);
    	jaxbUnmarshaller = context.createUnmarshaller();
        
    	try {
    		Files.list(Paths.get(spifPath)).forEach(file -> { // every file in spifPath 
    			new RolesLogger(className, Level.FINE, "spif.loaded", new Object[] {file.getFileName()});
    			try { spifData(jaxbUnmarshaller,spifPath + "/" + file.getFileName().toString()); }
    			catch (JAXBException e) { // logged in spifData - do nothing
    				//fmt = new MessageFormat(bundle.getString("spif.decodeErr"));	
    				//LOGGER.warning(fmt.format(new Object[] {file.getFileName(),e.getLocalizedMessage()})); 
            }
        }); 
    	} catch (IOException e) {
    		new RolesLogger(className, Level.FINE,"spif.readDirErr", new Object[] {spifPath, e.getLocalizedMessage()});
    		throw new IOException(formatter.format(new Object[] {spifPath, e.getLocalizedMessage()}));
    	} 
    } // SpifInfo


    public String getLACV(String policyID, String role){
        for(int i = 0; i<spifMap.get(policyID).size();i++){
            String str =  spifMap.get(policyID).get(i).values().toString().substring(1, spifMap.get(policyID).get(i).values().toString().length()-1);
            LOGGER.info("Role label and policy ID received : " + policyID + " - " + role);
            if(str.equals(role)){
                LOGGER.info("LACV returned : " + spifMap.get(policyID).get(i).keySet().toString().substring(1, spifMap.get(policyID).get(i).keySet().toString().length()-1)); 
                return spifMap.get(policyID).get(i).keySet().toString().substring(1, spifMap.get(policyID).get(i).keySet().toString().length()-1);
            }
        }

        return "null";
    }

    public String getName(String policyID, String lacv){

        for(int i = 0; i<spifMap.get(policyID).size();i++){
            String str =  spifMap.get(policyID).get(i).keySet().toString().substring(1, spifMap.get(policyID).get(i).keySet().toString().length()-1);
            LOGGER.info("LACV and policy ID received : " + policyID + " - " + lacv);
            if(str.equals(lacv)){
                LOGGER.info("Role label returned : " + spifMap.get(policyID).get(i).values().toString().substring(1, spifMap.get(policyID).get(i).values().toString().length()-1));
                return spifMap.get(policyID).get(i).values().toString().substring(1, spifMap.get(policyID).get(i).values().toString().length()-1);
            }
        }

        return "Role doesn't exist for this policyID";
        
    }


    public ArrayList<Hashtable<String,String>> getAvailableClearance(String policyID) {
        LOGGER.info(Arrays.toString(spifMap.get(policyID).toArray()));
        return spifMap.get(policyID);
        
    }

}
