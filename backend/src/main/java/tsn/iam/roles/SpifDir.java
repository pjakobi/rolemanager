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
        
    private static Map<String,ArrayList<Hashtable<BigInteger,String>>> spifMap = new HashMap<String,ArrayList<Hashtable<BigInteger,String>>>();
    private static Map<String,String> descriptions = new HashMap<String,String>(); // LACV, label
    private static final String className = SpifDir.class.getName();
    private static final Logger LOGGER = Logger.getLogger( className );
    private final ResourceBundle bundle = ResourceBundle.getBundle("messages"); //default locale
    private MessageFormat formatter;
    private final RolesLogger rlog=new RolesLogger(className);
    
    private Set<spifFile> dir = new HashSet<>();
    
    // Inspect the SPIF Directory
    public SpifDir(String spifPath) throws JAXBException,InvalidPathException, IOException {
    	rlog.doLog(Level.FINE, "spif.path",new Object[] {spifPath});     
    	try {
    		Files.list(Paths.get(spifPath)).forEach(file -> { // every file in spifPath 
    		rlog.doLog(Level.FINE, "spif.loaded", new Object[] {file.getFileName()});
    		try { dir.add(new spifFile(spifPath + "/" + file.getFileName().toString())); }
    		catch (JAXBException e) { } // logged in spifData - do nothing else
        }); 
    	} catch (IOException e) {
    		rlog.doLog(Level.FINE,"spif.readDirErr", new Object[] {spifPath, e.getLocalizedMessage()});
    		throw new IOException(rlog.toString("spif.readDirErr",new Object[] {spifPath, e.getLocalizedMessage()}));
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


    public ArrayList<Hashtable<BigInteger,String>> getClearances(ASN1ObjectIdentifier policyID) {
        return spifMap.get(policyID);       
    }

}
