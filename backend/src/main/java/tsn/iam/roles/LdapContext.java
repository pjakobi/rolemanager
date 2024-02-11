package tsn.iam.roles;

import java.text.MessageFormat;
import java.util.Hashtable;
import java.util.ResourceBundle;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;
import org.springframework.core.env.Environment;
import org.springframework.javapoet.ClassName;


import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;



public class LdapContext {
	private InitialDirContext value=null;
	private String DirectoryUrl;
	private String DirectoryBase;
	private String DirectoryUser;
	
	private final Logger logger = LoggerFactory.getLogger(this.getClass());
	ResourceBundle bundle = ResourceBundle.getBundle("messages"); //default locale
	   //
	   // Connect to Directory based on params found in application.properties
	   //

	
	
		private void createCtxt(Environment env, LdapName searchBase) throws IllegalStateException, NamingException {
			
			DirectoryUrl = env.getRequiredProperty("ldap.url");
			DirectoryUser = env.getRequiredProperty("ldap.user");
			DirectoryBase = searchBase.toString();
			new MyLog(this.getClass(), Level.DEBUG, "ldap.setup", DirectoryUrl, DirectoryUser, DirectoryBase);
			Hashtable ldapEnv = new Hashtable();
			ldapEnv.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
			ldapEnv.put(Context.PROVIDER_URL, env.getRequiredProperty("ldap.url"));

			ldapEnv.put(Context.SECURITY_AUTHENTICATION, "simple");
			ldapEnv.put(Context.SECURITY_PRINCIPAL, env.getRequiredProperty("ldap.user"));
			ldapEnv.put(Context.SECURITY_CREDENTIALS, env.getRequiredProperty("ldap.password"));
			try { value = new InitialDirContext(ldapEnv); }
			   catch (NamingException e) { // invalid bind DN - misconfiguration
				   throw new NamingException(env.getRequiredProperty("ldap.user"));
			   }
			
		} // createCtxt
	
	   LdapContext(Environment env) throws IllegalStateException, NamingException { createCtxt(env, new LdapName(env.getRequiredProperty("ldap.base"))); } // ldapContext 
	   LdapContext(Environment env, LdapName searchBase) throws IllegalStateException, NamingException { createCtxt(env, searchBase); } // ldapContext     
		   
	   
	   InitialDirContext get() { return value; }
	   
	  
	   
//	   public NamingEnumeration searchScope(LdapServiceFilter filter, int scope) throws NamingException { // Search all attributes for a given DN
//		   SearchControls sc = new SearchControls();
//		   new MyLog(this.getClass(), Level.DEBUG, "ldap.query", filter.toString());
//		   sc.setSearchScope(scope);  
//		   try { 
//			   NamingEnumeration searchResults = value.search(DirectoryBase, filter.toString(), sc); 
//			   new MyLog(this.getClass(), Level.TRACE, "ldap.query.end");
//			   return searchResults;
//		   } 
//		   catch (NamingException e) { // should not happpen (invalid DNs trapped before) - bug
//			   new MyLog(this.getClass(), Level.WARN, "ldap.incorrectAuthn", e.getLocalizedMessage(), DirectoryUser);
//			   throw new NamingException(e.getLocalizedMessage());
//		   }
//		} // search
		   
		   
//	   public NamingEnumeration search(LdapServiceFilter filter) throws NamingException {
//		   return this.searchScope(filter, SearchControls.SUBTREE_SCOPE);
//	   }
	   
	   void close() { 
		   new MyLog(this.getClass(), Level.INFO, "ldap.close",DirectoryUrl);
		   try { value.close(); }
		   catch (NamingException e) { // invalid bind DN - should not happen (bug)
			   new MyLog(this.getClass(), Level.WARN, "ldap.close.error",DirectoryUrl,e.getLocalizedMessage());
		   } // catch
	   } // close
} // class ldapContext
