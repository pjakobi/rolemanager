package tsn.iam.roles;


import java.io.IOException;
import java.net.URL;
import java.net.InetAddress;
import java.text.MessageFormat;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.ResourceBundle;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.ldap.LdapName;
import javax.naming.AuthenticationException;
import javax.naming.AuthenticationNotSupportedException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public class JndidapAPI {

    private static DirContext ctx;
    private static final String UID_STRING = "uid";
    private static final String OBJECTCLASS_STRING = "objectClass";
    private static final String PMIUSER_STRING = "pmiUser";
    private static final String TOP_STRING = "top";
    private static final String ACCOUNT_STRING = "account";
    private static final String HOST_STRING = "host";
    private static final String AC_STRING  = "attributeCertificateAttribute";
    private static final String CLEARANCE_STRING = "clearance";
    private static final String CLEARANCE_REQUEST_STRING = "clearanceRequest";
    private static final String NOT_BEFORE_STRING = "notBeforeTime";
    private static final String NOT_AFTER_STRING = "notAfterTime";
    private static final String REQUESTOR_STRING = "requestor";
    private static final String HOLDER_STRING = "holder";
    private static final String DESCRIPTION_STRING = "description";
    private static final String INET_STRING = "inetOrgPerson";
    private static final Logger LOGGER = Logger.getLogger( JndidapAPI.class.getName() );
    private static ResourceBundle bundle = ResourceBundle.getBundle("messages"); //default locale
    private static MessageFormat formatter;
    private static RolesLogger rlog=new RolesLogger(JndidapAPI.class.getName());
    
    /**
     * Connect to the LDAP
     * @param url the LDAP url
     * @param login the LDAP login
     * @param pwd the LDAP password
     * @throws NamingException 
     */
    public static void connect(InetAddress server, int port, LdapName login, String pwd) 
    throws NamingException {
        Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://" + server.toString().split("/")[0]+ ":" + port);
        env.put(Context.SECURITY_AUTHENTICATION,"simple");
        env.put(Context.SECURITY_PRINCIPAL,login.toString());
        env.put(Context.SECURITY_CREDENTIALS,pwd);
        env.put("java.naming.ldap.attributes.binary",
        "attributeCertificateAttribute clearance");//TRES IMPORTANT : Nécessaire pour récupérer un byte array en lisant attributeCertificateAttribute et clearance, sinon on ne peut 
        //pas le lire en tant qu'objet binaire
        //pour que ca fontionne il faut modifier la syntaxe de attributeCertificateAttribute dans le LDAP en OCTET String : 1.3.6.1.4.1.1466.115.121.1.40
             
        try{
            ctx = new InitialLdapContext(env, null);     
        } catch (NamingException ex) { 
        	rlog.doLog(Level.WARNING, "ldap.incorrectAuthn", new Object[] {ex.getLocalizedMessage(), login.toString()});
        	throw new NamingException(formatter.format(ex.getLocalizedMessage(),login.toString()));
        } 
    }


    public static ArrayList<LdapName> getUsers(LdapName userstree) throws NamingException {

        ArrayList<LdapName> users = new ArrayList<LdapName>();
        NamingEnumeration answer = null;
        try { answer = ctx.search(userstree.toString(),null); }
        catch (NamingException e) {
        	rlog.doLog(Level.FINE,"ldap.error.user", new Object[] {e.getLocalizedMessage()});
        	throw new NamingException();
        }
        while(answer.hasMore()){
                SearchResult sr = (SearchResult) answer.next();
                LdapName user = new LdapName(sr.getNameInNamespace().toString());
                users.add(user);
                rlog.doLog(Level.FINE,"ldap.user", new Object[] {user});
        }
        return users;
        
    }


    /**
     * Add AC to user
     * @param entry the user LDAP entry
     * @param base64String the AC as a Base64 string
     * @throws NamingException
     */
    public static void addACToUser(String entry, String base64String) throws NamingException{

        //System.out.println("Adding new Attribute Certificate to user");
        LOGGER.info("Adding new Attribute Certificate to user");

        Attributes attributes = new BasicAttributes();
        Attribute person = new BasicAttribute(OBJECTCLASS_STRING, INET_STRING);
        byte[] ACbyte = Base64.getDecoder().decode(base64String);
        Attribute AC = new BasicAttribute(AC_STRING, ACbyte);
        attributes.put(person);

        ModificationItem[] item = new ModificationItem[1];
        item[0] = new ModificationItem(DirContext.ADD_ATTRIBUTE, AC);

        ctx.modifyAttributes(entry, item);
    }



    /**
     * Get all the Attribute Certificates of a given user
     * @param entry the LDAP user entry
     * @return ACs as Base64 string
     */
    public static List<String> getACOfUser(String entry){//pour l'isntant basé sur ACCOUNT car uniquement UID comme attriut MUST

        String searchFilter = "(objectClass=pmiUser)";//on ne veut chercher que les objets de ce type de classe, ATTENTION si la classe parent (le user) est un pmiUSER,
        //ca ne fonctionnera pas parce que le programme cherchera dans l'objet du user au lieu de ses enfants.
        String[] requiredAttributes = { AC_STRING };

        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setReturningAttributes(requiredAttributes);

        NamingEnumeration ACData;

        try {
            ACData = ctx.search(entry, searchFilter, controls);//liste tout ce qui est en dessous de entry selon requiredAttributes

            //SearchResult result = null;
            List<String> base64ListOfACasString = new Vector<String>();
            
            

            while(ACData.hasMore()){
                SearchResult result = (SearchResult) ACData.next();
                Attributes attr = result.getAttributes();
                for(NamingEnumeration ae = attr.getAll(); ae.hasMore();){
                    Attribute at = (Attribute) ae.next();
                    System.out.println(at.getID());
                    NamingEnumeration e = at.getAll();
                    while(e.hasMore()){
                        byte[] ACbyte = (byte[]) e.next();
                        base64ListOfACasString.add(Base64.getEncoder().encodeToString(ACbyte));
                    }
                }
                
            }
            LOGGER.info("ACs returned : " + base64ListOfACasString);

            return base64ListOfACasString;

        } catch (NamingException e) {
            System.out.println(e);
            e.printStackTrace();
            // TODO: handle exception
        }

        return null;

    }



     /**
     * Get all the Attribute Certificates pending requests
     * @return the requests info : clearance, holder, requestor, dates, serial number
     */
    public static ArrayList<String[]> getAllACRequests(){
        String searchFilter = "(objectClass=clearanceRequest)";//on ne veut chercher que les objets de ce type de classe
        String[] requiredAttributes = { "clearance", "holder", "requestor", "notBeforeTime", "notAfterTime", "serialNumber", "description" };

        ArrayList<String[]> requestsDataArrayList = new ArrayList<String[]>();
        

        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setReturningAttributes(requiredAttributes);

        NamingEnumeration requests;

        try {
            requests = ctx.search("ou=requests", searchFilter, controls);//liste tout ce qui est en dessous de entry selon requiredAttributes

            SearchResult result = null;
            

            while(requests.hasMore()){
                String[] requestInfo = new String[8]; //obliger de créer ici sinon l'arraylist est constituée de N copies de la dernière valeur d'info (Voir : https://stackoverflow.com/questions/19843506/why-does-my-arraylist-contain-n-copies-of-the-last-item-added-to-the-list)
                result = (SearchResult) requests.next();
                Attributes attr = result.getAttributes();
                byte[] clearanceByte = (byte[]) attr.get(CLEARANCE_STRING).get(0);
                DERGeneralizedTime start = new DERGeneralizedTime((String) attr.get(NOT_BEFORE_STRING).get(0));
                DERGeneralizedTime end = new DERGeneralizedTime((String) attr.get(NOT_AFTER_STRING).get(0));
                String requestor = (String) attr.get(REQUESTOR_STRING).get(0);
                String holder = (String) attr.get(HOLDER_STRING).get(0);
                String serialNumber = (String) attr.get("serialNumber").get(0);
                /* Iterator iter = attr.getAll().asIterator();
                while(iter.hasNext()){
                    LOGGER.info(iter.next().toString());
                } */
                String descro = (String) attr.get(DESCRIPTION_STRING).get(0);


                //Avec  DERSequence.fromByteArray(clearanceByte) on récupère string = [policyID, clearance en hexa], 
                //clearance en hexa -> #(hexa) 03(bitString) 0x(length, si length>127 alors ça devient 1x) xxxx(value)
                //En réalité value sur le dernier xx je ne comprend pas le rôle du premier xx
                String subStringClearance = DERSequence.fromByteArray(clearanceByte).toString().substring(DERSequence.fromByteArray(clearanceByte).toString().lastIndexOf("]")-2, DERSequence.fromByteArray(clearanceByte).toString().lastIndexOf("]"));
                String subStringPolicyID = DERSequence.fromByteArray(clearanceByte).toString().substring(DERSequence.fromByteArray(clearanceByte).toString().lastIndexOf("[")+1, DERSequence.fromByteArray(clearanceByte).toString().lastIndexOf(","));
                Integer subBit = Integer.parseInt(subStringClearance,16);//Juste si seulement le dernier octet est pris, si les deux derniers => mauvaise valeur mais je ne sais pas pourquoi
                //clearance ne peut donc aller que de 0 à 255

                requestInfo[0] = serialNumber;
                requestInfo[1] = holder;
                requestInfo[2] = requestor;
                requestInfo[3] = subStringPolicyID;
                requestInfo[4] = subBit.toString();
                requestInfo[5] = start.getDate().toString();
                requestInfo[6] = end.getDate().toString();
                requestInfo[7] = descro;

                requestsDataArrayList.add(requestInfo);

            }
            return requestsDataArrayList;

        } catch (NamingException e) {
            System.out.println(e);
            e.printStackTrace();
            // TODO: handle exception
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (ParseException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }


    /**
 * Get one specific AC request
 * @param entry the LDAP AC request entry
 * @return the request as a Base64 string
 */
public static String[] getACRequest(String entry){

    try {
        Attributes answer = ctx.getAttributes(entry);
        Attribute AC = answer.get(AC_STRING);
        //System.out.println(AC.get());
        String[] requestInfo = new String[7]; //obliger de créer ici sinon l'arraylist est constituée de N copies de la dernière valeur d'info (Voir : https://stackoverflow.com/questions/19843506/why-does-my-arraylist-contain-n-copies-of-the-last-item-added-to-the-list)
                
        byte[] clearanceByte = (byte[]) answer.get("clearance").get(0);
        DERGeneralizedTime start = new DERGeneralizedTime((String) answer.get("notBeforeTime").get(0));
        DERGeneralizedTime end = new DERGeneralizedTime((String) answer.get("notAfterTime").get(0));
        String requestor = (String) answer.get("requestor").get(0);
        String holder = (String) answer.get("holder").get(0);
        String serialNumber = (String) answer.get("serialNumber").get(0);


        //Avec  DERSequence.fromByteArray(clearanceByte) on récupère string = [policyID, clearance en hexa], 
        //clearance en hexa -> #(hexa) 03(bitString) 0x(length, si length>127 alors ça devient 1x) xxxx(value)
        //En réalité value sur le dernier xx je ne comprend pas le rôle du premier xx
        String subStringClearance = DERSequence.fromByteArray(clearanceByte).toString().substring(DERSequence.fromByteArray(clearanceByte).toString().lastIndexOf("]")-2, DERSequence.fromByteArray(clearanceByte).toString().lastIndexOf("]"));
        String subStringPolicyID = DERSequence.fromByteArray(clearanceByte).toString().substring(DERSequence.fromByteArray(clearanceByte).toString().lastIndexOf("[")+1, DERSequence.fromByteArray(clearanceByte).toString().lastIndexOf(","));
        Integer subBit = Integer.parseInt(subStringClearance,16);//Juste si seulement le dernier octet est pris, si les deux derniers => mauvaise valeur mais je ne sais pas pourquoi
        //clearance ne peut donc aller que de 0 à 255

        Long lstart = start.getDate().getTime();
        Long lend = end.getDate().getTime();
        requestInfo[0] = serialNumber;
        requestInfo[1] = holder;
        requestInfo[2] = requestor;
        requestInfo[3] = subStringPolicyID;
        requestInfo[4] = subBit.toString();
        requestInfo[5] = lstart.toString();
        requestInfo[6] = lend.toString();

        //X509AttributeCertificateHolder att = new X509AttributeCertificateHolder(Base64.getDecoder().decode(AC.get().toString()));
        
        return requestInfo;
        
    } catch (NamingException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
    } catch (ParseException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
    } catch (IOException e) { e.printStackTrace(); }

    return null;
}


    /**
     * Add a request in the AC request tree
     * @param entry the LDAP DN for the entry, ending at OrganizationalUnit level (ou=xxxxx)
     * @param holder the holder of the future Attribute Certificate
     * @param requestor the one responsible who made the request
     * @param clearance the clearance, between 0 and 255
     * @param policyID the policyID
     * @param startMillis the start date of the Attribute Certificate in milliseconds
     * @param endMillis the end date of the Attribute Certificate in milliseconds
     * @param description description of the request
     * @throws NamingException
     */
    public static void addACRequest(String entry, String holder, String requestor, int clearance, String policyID, long startMillis, long endMillis, String description) throws NamingException {

        LOGGER.info("Adding new Attribute Certificate request at " + entry);

        //Holder, demandeur, clearance, début, fin, serialNumber 
        DERBitString derClassList = new DERBitString(clearance);
        DERGeneralizedTime start = new DERGeneralizedTime(new Date(startMillis));
        DERGeneralizedTime end = new DERGeneralizedTime(new Date(endMillis));
        //Attention : la variable suivante ne peut pas commencer par un chiffre supérieur à 2 ou erreur car ASN1ObjectIdentifier ne le considèrera pas comme un OID
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(policyID);//new ASN1ObjectIdentifier("1.3.26.1.3.1"); 
        ASN1EncodableVector envec = new ASN1EncodableVector();
        envec.add(oid);
        envec.add(derClassList);
        DERSequence derSequence = new DERSequence(envec);

        /* System.out.println(start.getTimeString());
        System.out.println("seq :" + derSequence); */


        try {
            Attributes attributes = new BasicAttributes();
            Attribute clearanceRequest = new BasicAttribute(OBJECTCLASS_STRING, CLEARANCE_REQUEST_STRING);
            //Attribute pmiUser = new BasicAttribute(OBJECTCLASS_STRING, PMIUSER_STRING);
            Attribute top = new BasicAttribute(OBJECTCLASS_STRING, TOP_STRING);
            Attribute clearancAttribute = new BasicAttribute(CLEARANCE_STRING, derSequence.getEncoded());
            Attribute startAttribute = new BasicAttribute(NOT_BEFORE_STRING, start.getTimeString());
            Attribute endAttribute = new BasicAttribute(NOT_AFTER_STRING, end.getTimeString());
            Attribute reqAttribute = new BasicAttribute(REQUESTOR_STRING, requestor);
            Attribute holdAttribute = new BasicAttribute(HOLDER_STRING, holder);
            Attribute descrAttribute = new BasicAttribute(DESCRIPTION_STRING,description);
            
            attributes.put(clearanceRequest);    
            attributes.put(clearancAttribute);
            attributes.put(descrAttribute);
            attributes.put(startAttribute);
            attributes.put(endAttribute);
            attributes.put(reqAttribute);
            attributes.put(holdAttribute);
            

        
            ctx.createSubcontext(entry, attributes);

            ModificationItem[] item = new ModificationItem[1];
            item[0] = new ModificationItem(DirContext.ADD_ATTRIBUTE, top);

            ctx.modifyAttributes(entry, item);

        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }








    ////GENERIC LDAP OPERATIONS/////

    /**
     * Add an entry in the current tree of the LDAP. This method cannot create a new branch upstream of the current node, but can do it downstream.
     * @param objectClass the class of the new entry
     * @param newEntry the absolute path of the new entry in LDAP syntax (dc component excluded)
     * @param entryAttributes contains the attributes ID and their values
     */

    public static void addEntry(String objectClass, String newEntry, Hashtable<String,String> entryAttributes){
        System.out.println("Adding new entry");

        Attribute attrID;
        String attrValue;
        String key;

        Attributes attributes = new BasicAttributes();
        Attribute attribute = new BasicAttribute(OBJECTCLASS_STRING);
        attribute.add(objectClass);
        //attribute.add("organizationalUnit");
        attributes.put(attribute);
        //Attribute cn = new BasicAttribute("cn");

        Enumeration<String> en = entryAttributes.keys();

        do {
            key = en.nextElement();
            attrID = new BasicAttribute(key);
            System.out.println(attrID);
            attrValue = entryAttributes.get(key);
            System.out.println(attrValue);
            attrID.add(attrValue);
            attributes.put(attrID);
        } while (en.hasMoreElements());

        try {
            ctx.createSubcontext(newEntry, attributes);
        } catch (NamingException e) {
            System.out.println(e);
            // TODO: handle exception
        }
    }

    /**
     * Delete an entry in the LDAP
     * @param entryToDelete the path of the entry to delete in LDAP syntax (dc component excluded)
     */
    public static void deleteEntry(String entryToDelete){
        LOGGER.info(entryToDelete);
        try {
            ctx.destroySubcontext(entryToDelete);
        } catch (Exception e) {
            System.out.println(e);
            // TODO: handle exception
        }
    }

    /**
     * Modifies the attributes of an entry. Creates the attribute if it doesn't already exist.
     * @param entry the path of the entry to modify, in LDAP syntax (dc component excluded) 
     * @param attributesToModify
     */
    public static void modifyAttributesOfEntry(String entry, Hashtable<String, String> attributesToModify){
        try {
            String key;
            Attribute attribute;
            int i=0;
            ModificationItem[] item = new ModificationItem[attributesToModify.size()];

            Enumeration<String> en = attributesToModify.keys();


            do {
                key = en.nextElement();
                attribute = new BasicAttribute(key,attributesToModify.get(key));
                item[i] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, attribute);
                i++;
            } while (en.hasMoreElements());

            ctx.modifyAttributes(entry, item);

        } catch (NamingException e) {
            e.printStackTrace();
        }
    }
    
}
