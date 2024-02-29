package tsn.iam.roles;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.ResourceBundle;
import java.util.StringTokenizer;
import java.util.logging.Logger;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;

import java.util.logging.Level;

public class LdapConfig {
    final String className = LdapConfig.class.getName();
    final Logger LOGGER = Logger.getLogger( className );
    final ResourceBundle bundle = ResourceBundle.getBundle("messages"); //default locale
    final RolesLogger rlog=new RolesLogger(className);
    
    private String bindUri="";
    private LdapName bindBase;
    private LdapName bindDn;
    private Integer port=389;
    private InetAddress ldapServer;
    private String pwFname;
    
	public LdapConfig(String fname, String pwFname) throws IOException, InvalidNameException {
		this.pwFname = pwFname;
		
		ldapServer = InetAddress.getByName("127.0.0.1");
		BufferedReader reader = new BufferedReader(new FileReader(fname));
		String line = reader.readLine();

		while (line != null) {
			if (!(line.startsWith("#") || (line.length() < 1))) { // skip comments
				StringTokenizer st = new StringTokenizer(line);
				String keyword = "";
				String value = "";
				while (st.hasMoreTokens()) {
					if (keyword.equals("")) keyword = st.nextToken();
					else if (value.equals("")) value = st.nextToken();
				} // while
				rlog.doLog(Level.FINER,"ldap.debug", new Object[] { keyword,value });
				
				if  (keyword.equalsIgnoreCase("BINDDN")) {
					 try { this.bindDn = new LdapName(value); } 
				     catch (InvalidNameException e) {
				        	rlog.doLog(Level.SEVERE,"ldap.invalidName", new Object[] {value});
				        	throw new InvalidNameException(rlog.toString());
				     }
				}
				if  (keyword.equalsIgnoreCase("URI")) decodeUri(value);
				if  (keyword.equalsIgnoreCase("BASE")) 				
					try { this.bindBase = new LdapName(value); } 
		        	catch (InvalidNameException e) {
		        		rlog.doLog(Level.SEVERE,"ldap.invalidName", new Object[] {value});
		        		throw new InvalidNameException(rlog.toString());
		        	}
			} // if
			
			
			line = reader.readLine(); // read next line
		}
		reader.close();
	} // LdapConfig
	
	public LdapName getBindDn() { return bindDn; }
	public Integer getPort() { return port; }
	public InetAddress getHost() { return ldapServer; }
	public LdapName getBindBase() { return bindBase; }
	
	private void decodeUri(String uri) {
		InetAddress server=null;
		try {
			server = InetAddress.getByName(new URI(uri).getHost());
			Integer myPort = new URI(uri).getPort();
			port = (myPort == -1)?389:myPort; // -1 : no port in string
		} 
		catch (URISyntaxException e1) { rlog.doLog(Level.SEVERE,"ldap.invalidUri", new Object[] {uri}); return; }
		catch (UnknownHostException e2) { rlog.doLog(Level.SEVERE,"ldap.invalidUri", new Object[] {uri}); return; }
		ldapServer = server; // everything ok
	} // decodeUri
	
	public String getPasswd() throws FileNotFoundException, IOException {
		try {
			BufferedReader reader = new BufferedReader(new FileReader(pwFname));
			String line = reader.readLine();
			while (line != null) {
				if (!(line.startsWith("#") || (line.length() < 1))) { // skip comments
					reader.close();
					return line;
				}
				line = reader.readLine(); // read next line
			}
			reader.close(); // at EOF
		} catch (FileNotFoundException e1) {
			rlog.doLog(Level.SEVERE,"ldap.invalidFile", new Object[] {e1.getLocalizedMessage()}); 
			throw (new FileNotFoundException(rlog.toString())); 
		} catch (IOException e2) { 
			rlog.doLog(Level.SEVERE,"ac.ioerror", new Object[] {pwFname, e2.getLocalizedMessage()}); 
			throw (new FileNotFoundException(rlog.toString()));		
		}
		return "";
	}
} // class LdapConfig
