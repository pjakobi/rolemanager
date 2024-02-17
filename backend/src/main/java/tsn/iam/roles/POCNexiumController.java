package tsn.iam.roles;

import java.io.FileNotFoundException;

//import tsn.iam.roles.AttributeCertificate.*;
//import tsn.iam.roles.AttributeCertificate.SPIF.SpifInfo;
//import tsn.iam.roles.LDAP.*;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.file.InvalidPathException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger; // SEVERE, WARNING, INFO, CONFIG, FINE, FINER, FINEST
import java.net.InetAddress;

import javax.naming.InvalidNameException;
import javax.naming.NameAlreadyBoundException;
import javax.naming.NamingException;
import javax.naming.ldap.LdapName;

import org.bouncycastle.asn1.x509.AttributeCertificateInfo;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.xml.bind.JAXBException;


@CrossOrigin (origins = "*", exposedHeaders = "*", allowedHeaders = "*")

@RestController
public class POCNexiumController {
	private InetAddress server=null;
    private final Integer port;
    private LdapName treeroot=null;
    private LdapName login=null;
    private final String password;

    private SpifDir spifi;
    private static final String className = POCNexiumController.class.getName();
    private final RolesLogger rlog=new RolesLogger(className);
    @Autowired Environment env;
    
    POCNexiumController(@Value("${ldap.server}") String server,
                        @Value("${ldap.port}") String port,
                        @Value("${ldap.treeroot}") String treeroot,
                        @Value("${ldap.login}") String login,
                        @Value("${ldap.password}") String password,
                        @Value("${spif.path}") String spifPath,
                        @Value("${ldap.userstree") String spifPeopleSubtree
                        ) throws NamingException, InvalidPathException, JAXBException, IOException
    {
    	

    	// logging
        final ResourceBundle bundle = ResourceBundle.getBundle("messages"); //default locale
        MessageFormat formatter;

        
        // With InetAddress.getByName, we get host name/IP 
        try { this.server = InetAddress.getByName(server); } // host name/IP
        catch (UnknownHostException e1) {
        	rlog.doLog(Level.SEVERE,"ldap.invalidHost", new Object[] {this.server.toString()});
			throw new UnknownHostException(rlog.toString());
		}
        try { this.login = new LdapName(login); } 
        catch (InvalidNameException e) {
        	rlog.doLog(Level.SEVERE,"ldap.invalidName", new Object[] {this.login.toString()});
        	throw new UnknownHostException(rlog.toString());
        }
        this.password = password;
        this.port = Integer.parseInt(port);  
        try { this.treeroot = new LdapName(treeroot); } 
        catch (InvalidNameException e) {
        	rlog.doLog(Level.SEVERE,"ldap.invalidName", new Object[] {this.treeroot.toString()});
        	throw new UnknownHostException(rlog.toString());
        }

        // Bind to Dir.         
        rlog.doLog(Level.SEVERE,"ldap.connect", new Object[] {this.server.toString().split("/")[0], this.port.toString(), this.treeroot.toString()});
       
       JndidapAPI.connect(this.server, this.port, this.login, this.password);
       rlog.doLog(Level.FINE,"ldap.connectOK",new Object[] {}); 

       this.spifi = new SpifDir(spifPath); 
    }


    

    @GetMapping("/users")
    public ResponseEntity<ArrayList<String>> getLDAPUsers() {
    	ArrayList<String> strUsers = new ArrayList();
        try {
        	LdapName searchedTree = new LdapName(env.getProperty("ldap.userstree") + "," + env.getProperty("ldap.treeroot"));
        	rlog.doLog(Level.INFO,"ldap.users", new Object[] {searchedTree.toString()});
            ArrayList<LdapName> users = JndidapAPI.getUsers(searchedTree);
            for (LdapName index : users) strUsers.add(index.toString());
            return new ResponseEntity<ArrayList<String>>(strUsers, HttpStatus.OK);
        } catch (NamingException e) {
        	rlog.doLog(Level.WARNING,"ldap.error.search", new Object[] {e.getLocalizedMessage()});
            e.printStackTrace();
            return new ResponseEntity<ArrayList<String>>(strUsers,HttpStatus.NOT_FOUND);
        } 
    } // getLDAPUsers
    
    
    @GetMapping("/lacv/{policyID}")
    public ResponseEntity<ArrayList<Hashtable<BigInteger,String>>> getAvailableClearance(@PathVariable String policyID){
        return new ResponseEntity<ArrayList<Hashtable<BigInteger,String>>>(this.spifi.getAvailableClearance(policyID), HttpStatus.OK);
    }


    /**
     * Get all the pending Attribute Certificate requests
     */
    @GetMapping("/AC")
    public ResponseEntity<ArrayList<Hashtable<String,String>>> getAllACRequests(){
        ArrayList<String[]> requests = JndidapAPI.getAllACRequests();
       // String[] ACinfoString = new String[6];
       // HttpHeaders headers = new HttpHeaders();
        ArrayList<Hashtable<String,String>> ACList = new ArrayList<Hashtable<String,String>>();
        

        /* for (String[] arr : ACrequests) {
            System.out.println(Arrays.toString(arr));
        } */

        for(int i=0; i<requests.size(); i++){
            Hashtable<String, String> ACTable = new Hashtable<String,String>();      
            
            ACTable.put("SerialNumber", requests.get(i)[0]);
            ACTable.put("Holder", requests.get(i)[1]);
            ACTable.put("Requestor", requests.get(i)[2]);
            ACTable.put("Start", requests.get(i)[5]);
            ACTable.put("End", requests.get(i)[6]);
            ACTable.put("Clearance", this.spifi.getName(requests.get(i)[3], requests.get(i)[4]));
            ACTable.put("PolicyID", requests.get(i)[3]);
            ACTable.put("Description", requests.get(i)[7]);
            

            ACList.add(ACTable);

           
        }

        return new ResponseEntity<ArrayList<Hashtable<String,String>>>(ACList, HttpStatus.OK);

    }

   

    /**
     * Get all the Attribute Certificates of a given user
     * @param entry the LDAP entry of the user 
     */
    @GetMapping("/userAC/{entry}")
    public ResponseEntity<ArrayList<Hashtable<String,String>>> getACOfUser(@PathVariable String entry){//no JSON there otherwise it can't be a GET request
        //String entry = (String) payload.get("entry");
        //LOGGER.info(entry);
        //System.out.println(entry);
        List<String> userACs = JndidapAPI.getACOfUser(entry);
        String[] ACinfoString = new String[6];
        ArrayList<Hashtable<String,String>> userACList = new ArrayList<Hashtable<String,String>>();

        try {
            for(int i =0;i<userACs.size(); i++){
                byte[] ACbyte = Base64.getDecoder().decode(userACs.get(i));
                Hashtable<String, String> userACTable = new Hashtable<String,String>(); 
                
                X509AttributeCertificateHolder ACHolder = new X509AttributeCertificateHolder(ACbyte);
                //LOGGER.info("Certificate number : " + i);
                userACTable.put("Start", ACInfo.getStartDate(ACHolder).toString());
                userACTable.put("End", ACInfo.getEndDate(ACHolder).toString());
                userACTable.put("Clearance", spifi.getName(ACInfo.getPolicyID(ACHolder).toString(), ACInfo.getClearance(ACHolder).toString()));
                userACTable.put("PolicyID", ACInfo.getPolicyID(ACHolder).toString());

                userACList.add(userACTable);
            }   

                    return new ResponseEntity<ArrayList<Hashtable<String,String>>>(userACList, HttpStatus.OK);
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                    ArrayList<Hashtable<String,String>> errorList = new ArrayList<Hashtable<String,String>>();
                    Hashtable<String, String> errorTable = new Hashtable<String,String>(); 
                    errorTable.put("error", e.getMessage());
                    errorList.add(errorTable);
                    return new ResponseEntity<ArrayList<Hashtable<String,String>>>(errorList, HttpStatus.EXPECTATION_FAILED);

                }
            
    }


    /**
     * Get the clearances of the policyID in the query of a given user
     * @param entry the LDAP user entry
     */
    @GetMapping("/roles/{entry}/{policyID}")
    public ResponseEntity<ArrayList<String>> getClearanceOfPolicyID(@PathVariable String entry, @PathVariable String policyIdFromRequest){//no JSON there otherwise it can't be a GET request
        //String entry = (String) payload.get("entry");
        //LOGGER.info(entry);
        //System.out.println(entry);
        List<String> userACs = JndidapAPI.getACOfUser(entry);
        //List<String> clearanceList = new Vector<String>();
        //Hashtable<String,String> clearanceHashtable = new Hashtable<>();
        String clearance;
        String policyID;
        ArrayList<String> clearanceList = new ArrayList<String>();

        if(userACs==null) return new ResponseEntity<ArrayList<String>>(HttpStatus.NOT_FOUND);
        
        else{
            try {
                int failedVerify = 0;
                for(Integer i =0;i<userACs.size(); i++){
                    byte[] ACbyte = Base64.getDecoder().decode(userACs.get(i));
                    
                    X509AttributeCertificateHolder ACHolder = new X509AttributeCertificateHolder(ACbyte);

                    if(PKCS12ACGenerator.verifyAC(ACHolder, false)){

                        clearance =  ACInfo.getClearance(ACHolder).toString();
                        policyID = ACInfo.getPolicyID(ACHolder);
                        //clearanceHashtable.put(policyID, clearance);
                        //System.out.println("Controller : " + clearanceHashtable.values());
                        if(policyID==policyIdFromRequest){
                            clearanceList.add(clearance);
                        }
                    }
                    else rlog.doLog(Level.WARNING,"ac.verifFailures", new Object[] {failedVerify++});
                        
                } 

                    return new ResponseEntity<ArrayList<String>>(clearanceList, HttpStatus.OK);
                    
                    } catch (IOException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    return new ResponseEntity<ArrayList<String>>(HttpStatus.EXPECTATION_FAILED);

                    } 
            }   
    }


    /**
     * Get the clearances and policiesID of a given user
     * @param entry the LDAP user entry
     * @return policyID and clearance in HTTP headers
     */
    @GetMapping("/roles/{entry}")
    public ResponseEntity<Map<String,Object[]>> getRoles(@PathVariable String entry){//no JSON there otherwise it can't be a GET request
        MultiValueMap<String,String> multiMap = new LinkedMultiValueMap<String,String>();
        String clearance;
        String policyID;
        List<String> userACs = JndidapAPI.getACOfUser(entry);
        Map<String,Object[]> map = new HashMap<String, Object[]>();
        

        if(userACs==null) return new ResponseEntity<Map<String, Object[]>>(HttpStatus.NOT_FOUND);

        else{
            try {
                int failedVerify = 0;
                for(Integer i =0;i<userACs.size(); i++){
                    byte[] ACbyte = Base64.getDecoder().decode(userACs.get(i));
                    X509AttributeCertificateHolder ACHolder = new X509AttributeCertificateHolder(ACbyte);

                    if(PKCS12ACGenerator.verifyAC(ACHolder, false)){
                        clearance =  ACInfo.getClearance(ACHolder).toString();
                        policyID = ACInfo.getPolicyID(ACHolder);
                        multiMap.add(policyID,clearance);
                    }
                    else rlog.doLog(Level.WARNING,"ac.verifFailures", new Object[] {failedVerify++});
                }
                Iterator<String> itID = multiMap.keySet().iterator();
                

                while (itID.hasNext()){
                    String pol = itID.next();
                    rlog.doLog(Level.INFO,"ac.policy", new Object[] {pol});
                    //String[] roles = (String[]) multiMap.get(pol).toArray();
                    rlog.doLog(Level.INFO,"arrays", new Object[] {Arrays.toString(multiMap.get(pol).toArray())});
                    map.put(pol, multiMap.get(pol).toArray());
                    //Iterator<String> itClear = multiMap.get(pol).iterator();
                    for (String itClear: multiMap.get(pol)) rlog.doLog(Level.INFO,"ac.policy", new Object[] {itClear});
                    
                }
                rlog.doLog(Level.INFO,"spif.response",new Object[] {});
                //return new ResponseEntity<LinkedMultiValueMap<String,String>>(multiMap, HttpStatus.OK);
                return new ResponseEntity<Map<String,Object[]>>(map, HttpStatus.OK);
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
                return new ResponseEntity<Map<String, Object[]>>(HttpStatus.EXPECTATION_FAILED);
            }            
        }
    }


     /**
     * Add an Attribute Certificate to the request list
     * @param payload the JSON which contains the data
     */
    @PostMapping("/AC")
    public ResponseEntity<String> ACRequest(@RequestBody Map<String,String> payload){

        String holderName =(String) payload.get("holderName");
        String sclear = (String) payload.get("clearance");
        String debut = (String) payload.get("start");//long value to string
        String fin = (String) payload.get("end");//long value to string
        String requestor = (String) payload.get("requestor");
        String policyID = (String) payload.get("policyID");
        rlog.doLog(Level.INFO,"spif.acReq",new Object[] {holderName, sclear, debut, fin, requestor, policyID});
        int clearance = Integer.parseInt(sclear);
        long ldebut = Long.parseLong(debut);
        long lfin = Long.parseLong(fin);
        String descro = (String) payload.get("description");

        
        //Date debutD = new Date(ldebut);
        //Date finD = new Date(lfin);
        
        int min = 0;
        int max = 1000000;

        Integer random_int = (int)Math.floor(Math.random()*(max-min+1)+min);

        String entry = "serialNumber=" + random_int.toString() + ",ou=requests";

        try {

            JndidapAPI.addACRequest(entry, holderName, requestor, clearance, policyID, ldebut, lfin, descro);
            return new ResponseEntity<String>( HttpStatus.CREATED);
            
        } catch (NamingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();

            //ACRequest(payload);//in case the UID already exists, it is randomized again until one which doesn't exist is found
            return new ResponseEntity<String>( HttpStatus.CREATED);

        }

    }




    
    /**
     * Add a new Attribute Certificate to a given user, to do so it will retrieve the data of the request in the LDAP and add it to the user as a new entry
     * @param payload the JSON which contains the user UID and the Attribute Certificate Request UID
     */
    @PostMapping("/userAC")
    public ResponseEntity<String> ACToUser(@RequestBody Map<String,Object> payload){

        PKCS12ACGenerator pkg = new PKCS12ACGenerator();

        String user = (String) payload.get("uid");
        String serialNumber = (String) payload.get("serialNumber");

        String entry = "uid=" + user + ",ou=people";
        //String ACentry = "uid=" + ACuid + ",ou=certificates";

        String requestEntry = "serialNumber=" + serialNumber + ",ou=requests";

        String[] AC = JndidapAPI.getACRequest(requestEntry);

        /* for (int i =0; i<7;i++) {
            System.out.println(AC[i]);
        } */

        try {
            AttributeCertificateInfo acInfo = pkg.createAttributeCertificateInfoToBeSigned(AC[1], AC[3], Integer.parseInt(AC[4]), new Date(Long.parseLong(AC[5])), new Date(Long.parseLong(AC[6])));
            X509AttributeCertificateHolder ACHolder = pkg.signACFromACInfo(acInfo, false);
            //X509AttributeCertificateHolder ACHolder = pkg.createAC(AC[1], AC[3], Integer.parseInt(AC[4]), new Date(Long.parseLong(AC[5])), new Date(Long.parseLong(AC[6])));
            String base64 = Base64.getEncoder().encodeToString(ACHolder.getEncoded());

        
            JndidapAPI.addACToUser(entry, base64);
            JndidapAPI.deleteEntry(requestEntry);
            return new ResponseEntity<String>( HttpStatus.CREATED);
        } catch (NameAlreadyBoundException e1){
            //e1.printStackTrace();
        	rlog.doLog(Level.INFO,"spif.overwrite",new Object[] {});
            JndidapAPI.deleteEntry(entry);
            
            try {
                AttributeCertificateInfo acInfo = pkg.createAttributeCertificateInfoToBeSigned(AC[1], AC[3], Integer.parseInt(AC[4]), new Date(Long.parseLong(AC[5])), new Date(Long.parseLong(AC[6])));
                X509AttributeCertificateHolder ACHolder = pkg.signACFromACInfo(acInfo, false);
                //X509AttributeCertificateHolder ACHolder = pkg.createAC(AC[1], AC[3], Integer.parseInt(AC[4]), new Date(Long.parseLong(AC[5])), new Date(Long.parseLong(AC[6])));
                String base64 = Base64.getEncoder().encodeToString(ACHolder.getEncoded());
                JndidapAPI.addACToUser(entry, base64);

                return new ResponseEntity<String>("Entry overwritten", HttpStatus.CREATED);
            } 
            //catch (NamingException | NumberFormatException | KeyStoreException | OperatorCreationException | IOException | NoSuchAlgorithmException | InvalidKeySpecException | CertificateException | InvalidKeyException | NoSuchProviderException | SignatureException | CMSException e) {
            catch (Exception e) {
                e.printStackTrace();
                return new ResponseEntity<String>( HttpStatus.NOT_ACCEPTABLE);
            }
        
        } catch (NamingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return new ResponseEntity<String>( HttpStatus.NOT_ACCEPTABLE);
        } catch (NumberFormatException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return new ResponseEntity<String>( HttpStatus.NOT_ACCEPTABLE);
        } catch (KeyStoreException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return new ResponseEntity<String>( HttpStatus.NOT_ACCEPTABLE);
        } catch (OperatorCreationException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return new ResponseEntity<String>( HttpStatus.NOT_ACCEPTABLE);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return new ResponseEntity<String>( HttpStatus.NOT_ACCEPTABLE);
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return new ResponseEntity<String>( HttpStatus.NOT_ACCEPTABLE);
        } catch (InvalidKeySpecException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return new ResponseEntity<String>( HttpStatus.NOT_ACCEPTABLE);
        } catch (CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return new ResponseEntity<String>( HttpStatus.NOT_ACCEPTABLE);
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return new ResponseEntity<String>( HttpStatus.NOT_ACCEPTABLE);
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            return new ResponseEntity<String>( HttpStatus.NOT_ACCEPTABLE);
        } catch (SignatureException e) {
            e.printStackTrace();
            return new ResponseEntity<String>( HttpStatus.NOT_ACCEPTABLE);
        } catch (CMSException e) {
            e.printStackTrace();
            return new ResponseEntity<String>( HttpStatus.NOT_ACCEPTABLE);
        }

        


    }

    @DeleteMapping("/AC/{serialNumber}")
    public ResponseEntity<String> deleteACRequest(/*@RequestBody Map<String,Object> payload*/@PathVariable String serialNumber){

        //String entry = "serialNumber=" + (String) payload.get("serialNumber") + ",ou=requests";

        String entry = "serialNumber=" + serialNumber + ",ou=requests";

        JndidapAPI.deleteEntry(entry);

        return new ResponseEntity<String>(HttpStatus.OK);

    }

    @DeleteMapping("/userAC/{uid}/{user}")
    public ResponseEntity<String> deleteUserAC(/* @RequestBody Map<String,Object> payload */@PathVariable String uid, @PathVariable String user){

        //String entry = "uid=" + (String) payload.get("uid") + ",uid=" + (String) payload.get("user") + ",ou=people";
        String entry = "uid=" + uid + ",uid=" + user + ",ou=people";

        JndidapAPI.deleteEntry(entry);

        return new ResponseEntity<String>(HttpStatus.OK);

    }


}
