package tsn.iam.roles;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Logger;

import org.xmlspif.spif.SPIF;
import org.xmlspif.spif.SecurityClassification;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;

public class SpifInfo {
    private static Properties conf;
        
    private static Map<String,ArrayList<Hashtable<String,String>>> spifMap = new HashMap<String,ArrayList<Hashtable<String,String>>>();

    private static final Logger LOGGER = Logger.getLogger( SpifInfo.class.getName() );

    public SpifInfo(String spifPath){
        try {
        File folder = new File(spifPath);
        File[] listOfFiles = folder.listFiles();
        
        for (int i = 0; i < listOfFiles.length; i++) {
            if (listOfFiles[i].isFile()) LOGGER.info("Spif \"" + listOfFiles[i].getName() + "\" loaded");
            else if (listOfFiles[i].isDirectory()) LOGGER.info("Directory in spif directory path named : " + listOfFiles[i].getName());
            
            JAXBContext context = JAXBContext.newInstance(SPIF.class);
            Unmarshaller jaxbUnmarshaller = context.createUnmarshaller();
            SPIF mySpif = (SPIF) jaxbUnmarshaller.unmarshal(listOfFiles[i]);

            ArrayList<Hashtable<String,String>> spifList = new ArrayList<Hashtable<String,String>>();

            for (int x=0; x < mySpif.getSecurityClassifications().getSecurityClassification().size();x++){       
                
                Hashtable<String,String> spifTable = new Hashtable<String,String>();    
                SecurityClassification s = mySpif.getSecurityClassifications().getSecurityClassification().get(x);
                
                spifTable.put(s.getLacv().toString(), s.getName());
                spifList.add(spifTable);
            }

            
            spifMap.put(mySpif.getSecurityPolicyId().getId(), spifList);

        }//first for
        } 
        catch (JAXBException e) { e.printStackTrace(); }
    }


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
