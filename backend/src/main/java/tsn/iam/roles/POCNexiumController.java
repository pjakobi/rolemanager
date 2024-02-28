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
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;
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
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

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
    private static RolesLogger rlog=new RolesLogger(className);
    @Autowired Environment env;
	//private String ACTable.put;
    
    POCNexiumController(@Value("${ldap.server}") String server,
                        @Value("${ldap.port}") String port,
                        @Value("${ldap.treeroot}") String treeroot,
                        @Value("${ldap.login}") String login,
                        @Value("${ldap.password}") String password,
                        @Value("${spif.path}") String spifPath,
                        @Value("${ldap.userstree") String spifPeopleSubtree
                        ) throws NamingException, InvalidPathException, JAXBException, IOException
    {
    	
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

    // Get user's DNs
    @GetMapping("/users")
    public ResponseEntity<ArrayList<String>> getLDAPUsers() {
    	new RolesLogger(className, Level.INFO, "spif.users", new Object[] {});
    	ArrayList<String> strUsers = new ArrayList<String>();
        try {
        	LdapName searchedTree = new LdapName(env.getProperty("ldap.userstree") + "," + env.getProperty("ldap.treeroot"));
        	rlog.doLog(Level.FINE,"ldap.users", new Object[] {searchedTree.toString()});
            ArrayList<LdapName> users = JndidapAPI.getUsers(searchedTree);
            for (LdapName index : users) strUsers.add(index.toString());
            new RolesLogger(className, Level.FINE, "spif.users.ok", new Object[] {});
            return new ResponseEntity<ArrayList<String>>(strUsers, HttpStatus.OK);
        } catch (NamingException e) {
        	rlog.doLog(Level.WARNING,"ldap.error.search", new Object[] {e.getLocalizedMessage()});
            return new ResponseEntity<ArrayList<String>>(strUsers,HttpStatus.NOT_FOUND);
        } 
    } // getLDAPUsers
    
    // Get all policies object id
    @GetMapping("/policies")
    public ResponseEntity<Set<SpifDescriptor>> getPolicies() { // File name, obj. id, policy name
    	new RolesLogger(className, Level.INFO, "spif.getPolicies", new Object[] {});
    	new RolesLogger(className, Level.INFO, "spif.getPolicies.ok", new Object[] {});
    	return new ResponseEntity<Set<SpifDescriptor>> (spifi.getDescriptors(),HttpStatus.OK);   	
    } // getPolicies
    
    @GetMapping("/lacv/{policyID}")
    public ResponseEntity<Map<BigInteger,String>> getAvailableClearance(@PathVariable String policyID){
    	new RolesLogger(className, Level.INFO, "spif.clearances", new Object[] {policyID.toString()});
    	Map<BigInteger,String> map = spifi.getClearances(new ASN1ObjectIdentifier(policyID));
    	return new ResponseEntity<Map<BigInteger,String>>(map, HttpStatus.OK);
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
        

        for(int i=0; i<requests.size(); i++){
            Hashtable<String, String> ACTable = new Hashtable<String,String>();      
            
            ACTable.put("SerialNumber", requests.get(i)[0]);
            ACTable.put("Holder", requests.get(i)[1]);
            ACTable.put("Requestor", requests.get(i)[2]);
            ACTable.put("Start", requests.get(i)[5]);
            ACTable.put("End", requests.get(i)[6]);
            //ACTable.put("Clearance", this.spifi.getName(new ASN1ObjectIdentifier(requests.get(i)[3]), Integer.valueOf(requests.get(i)[4])));
            ACTable.put("PolicyID", requests.get(i)[3]);
            ACTable.put("Description", requests.get(i)[7]);
            
            ACList.add(ACTable);
        }

        return new ResponseEntity<ArrayList<Hashtable<String,String>>>(ACList, HttpStatus.OK);

    }

   private ArrayList<Hashtable<String,String>> namingException(Level level, LdapName dName, String errorLabel) {
	   new RolesLogger(className,level,"ac.getError", new Object[] {errorLabel,dName.toString()});
       ArrayList<Hashtable<String,String>> errorList = new ArrayList<Hashtable<String,String>>();
       Hashtable<String, String> errorTable = new Hashtable<String,String>(); 
       errorTable.put("error", errorLabel);
       errorList.add(errorTable);
       return errorList;
   }

    /**
     * Get all the Attribute Certificates of a given user
     * @param entry the LDAP entry of the user 
     */
    @GetMapping("/userAC/{entry}")
    public ResponseEntity<ArrayList<Hashtable<String,String>>> getACOfUser(@PathVariable LdapName dName){//no JSON there otherwise it can't be a GET request
    	rlog.doLog(Level.INFO,"ac.get", new Object[] {dName.toString()});
    	List<String> userACs=null;
    	try {  userACs = JndidapAPI.getACOfUser(dName); }
    	catch (NamingException e) {
    		ArrayList<Hashtable<String,String>> errorList = namingException(Level.INFO,dName,e.getLocalizedMessage());
    		return new ResponseEntity<ArrayList<Hashtable<String,String>>>(errorList, HttpStatus.INTERNAL_SERVER_ERROR);
    	}

        ArrayList<Hashtable<String,String>> userACList = new ArrayList<Hashtable<String,String>>();

        try {
            for(int i =0;i<userACs.size(); i++){
                byte[] ACbyte = Base64.getDecoder().decode(userACs.get(i));
                Hashtable<String, String> userACTable = new Hashtable<String,String>(); 
                
                X509AttributeCertificateHolder ACHolder = new X509AttributeCertificateHolder(ACbyte);
                userACTable.put("Start", ACInfo.getStartDate(ACHolder).toString());
                userACTable.put("End", ACInfo.getEndDate(ACHolder).toString());
                //userACTable.put("Clearance", spifi.getName(ACInfo.getPolicyID(ACHolder), ACInfo.getClearance(ACHolder)));
                userACTable.put("PolicyID", ACInfo.getPolicyID(ACHolder).toString());

                userACList.add(userACTable);
            }   

                    return new ResponseEntity<ArrayList<Hashtable<String,String>>>(userACList, HttpStatus.OK);
                } catch (IOException e) {
                    e.printStackTrace();
                    ArrayList<Hashtable<String,String>> errorList = new ArrayList<Hashtable<String,String>>();
                    Hashtable<String, String> errorTable = new Hashtable<String,String>(); 
                    errorTable.put("error", e.getMessage());
                    errorList.add(errorTable);
                    return new ResponseEntity<ArrayList<Hashtable<String,String>>>(errorList, HttpStatus.EXPECTATION_FAILED);

                }
    }


    /**
     * Get the clearance of the policyID in the query of a given user
     * @param entry the LDAP user entry
     * @throws NamingException 
     */
    @GetMapping("/roles/{dName}/{policyID}")
    public ResponseEntity<ArrayList<Hashtable<Integer,String>>> getClearanceOfPolicyID(@PathVariable String dNameStr, @PathVariable String policyIdStr) 
    		throws NamingException { //no JSON there otherwise it can't be a GET request
    	rlog.doLog(Level.INFO,"spif.getClearance", new Object[] {dNameStr, policyIdStr});
    	LdapName dName = new LdapName(dNameStr);
    	ASN1ObjectIdentifier policyID = new ASN1ObjectIdentifier(policyIdStr);
    	ArrayList<Hashtable<Integer,String>> result = new ArrayList<Hashtable<Integer,String>>();
 
        for(String ac : JndidapAPI.getACOfUser(dName)) {
        	int failedVerify = 0;
        	byte[] ACbyte = Base64.getDecoder().decode(ac.toString());
        	X509AttributeCertificateHolder ACHolder;
			try {
				ACHolder = new X509AttributeCertificateHolder(ACbyte);
			} catch (IOException e) {
				rlog.doLog(Level.WARNING,"spif.getClearanceError", new Object[] {dNameStr, policyIdStr});
				continue;
			}
        	if(!(PKCS12ACGenerator.verifyAC(ACHolder, false))) { // incorrect AC
            	rlog.doLog(Level.WARNING,"ac.verifFailures", new Object[] {});
            	continue;
            }
        	if ((ACInfo.getPolicyID(ACHolder).equals(policyID))) { // found
        		Hashtable<Integer,String> ht = new Hashtable<Integer,String>();
        		//ht.put(ACInfo.getClearance(ACHolder), spifi.getName(policyID, ACInfo.getClearance(ACHolder)));
        		result.add(ht);
        		return new ResponseEntity(result, HttpStatus.OK); 
        	}
        }
        rlog.doLog(Level.WARNING,"spif.getClearanceNotFound", new Object[] {dNameStr, policyIdStr}); // not found
        return new ResponseEntity(result,HttpStatus.NOT_FOUND);
        

} // getClearanceOfPolicyID  


    /**
     * Get the clearances and policiesID of a given user
     * @param entry the LDAP user entry
     * @return policyID and clearance in HTTP headers
     * @throws NamingException 
     */
    @GetMapping("/roles/{dNameStr}")
    public ResponseEntity<Map<String,Object[]>> getRoles(@PathVariable String dNameStr) //no JSON there otherwise it can't be a GET request
    		throws NamingException { // NamingException should not be raised
    	LdapName DName;
    	try { DName = new LdapName(dNameStr); }
		catch (InvalidNameException e1) {
			rlog.doLog(Level.WARNING,"ldap.incorrectDN", new Object[] {dNameStr});
			e1.printStackTrace();
			return new ResponseEntity<Map<String, Object[]>>(HttpStatus.NOT_ACCEPTABLE);
		}
    	
        MultiValueMap<String,String> multiMap = new LinkedMultiValueMap<String,String>();
        String clearance;
        ASN1ObjectIdentifier policyID;
        List<String> userACs = JndidapAPI.getACOfUser(DName);
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
                        multiMap.add(policyID.toString(),clearance);
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
    public ResponseEntity<String> ACRequest(@RequestBody Map<String,String> payload) {
    	rlog.doLog(Level.INFO,"spif.acReqStart", new Object[] {});
    	
    	int min = 0;
        int max = 1000000;
        Integer random_int = (int)Math.floor(Math.random()*(max-min+1)+min);
        String strEntry = "serialNumber=" + random_int.toString() + ",ou=requests";
        LdapName entry, holder, requestor;
		try {
			holder = new LdapName((String) payload.get("holderName"));
			requestor = new LdapName((String) payload.get("requestor"));
			entry = new LdapName(strEntry);
		} catch (InvalidNameException e1) {
			rlog.doLog(Level.WARNING,"ac.badldapname",new Object[] {payload.get("holderName"), payload.get("requestor"), e1.getLocalizedMessage()});
			e1.printStackTrace();
			return new ResponseEntity<String>(HttpStatus.NOT_ACCEPTABLE);
		}
        
        int clearance = Integer.parseInt((String) payload.get("clearance"));
        long start = Long.parseLong((String) payload.get("start"));
        long end = Long.parseLong((String) payload.get("end"));
        ASN1ObjectIdentifier policyID = new ASN1ObjectIdentifier((String) payload.get("policyID"));
        rlog.doLog(Level.FINE,"spif.acReq",new Object[] {holder.toString(), requestor.toString(), policyID.toString(), clearance, start, end});
        String description = (String) payload.get("description");

        try {
        	AttributeCertRequest acr = new AttributeCertRequest (
        			entry, 
        			holder, 
        			requestor, 
        			clearance, 
        			policyID, 
        			start, 
        			end, 
        			description);
        	rlog.doLog(Level.FINE,"spif.acReqOK",new Object[] {});
            return new ResponseEntity<String>( HttpStatus.CREATED);
        } catch (IOException e) {
        	rlog.doLog(Level.WARNING,"ac.ioerror",new Object[] {e.getLocalizedMessage()});
			e.printStackTrace();
			return new ResponseEntity<String>( HttpStatus.INTERNAL_SERVER_ERROR);
		} catch (NamingException e) {
			rlog.doLog(Level.WARNING,"ac.namingerror",new Object[] {e.getLocalizedMessage()});
			e.printStackTrace();
			return new ResponseEntity<String>( HttpStatus.BAD_REQUEST);
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

    @GetMapping("/test")
    public ResponseEntity<String> test() {
    	rlog.doLog(Level.INFO,"spif.test",new Object[] {});
    	rlog.doLog(Level.FINE,"spif.test.ok",new Object[] {});
    	
    	return new ResponseEntity<String>(HttpStatus.OK);
    } // test
}
