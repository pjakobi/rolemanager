package tsn.iam.roles;

import java.text.MessageFormat;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RolesLogger {
	private static ResourceBundle bundle;
	private static Logger LOGGER;
	public RolesLogger(String className) {
		LOGGER = Logger.getLogger( className );
		bundle = ResourceBundle.getBundle("messages"); //default locale
    } // RolesLogger
	
	public  RolesLogger(String className, Level level, String fmtKey, Object[] params) {
		LOGGER = Logger.getLogger( className );
		bundle = ResourceBundle.getBundle("messages"); //default locale
		MessageFormat formatter = new MessageFormat(bundle.getString(fmtKey));
		LOGGER.log(level, formatter.format(params));
	}
	
	public void doLog(Level level, String fmtKey, Object[] params) {
		MessageFormat formatter = new MessageFormat(bundle.getString(fmtKey));
		LOGGER.log(level, formatter.format(params));
	}
	public String toString(String fmtKey, Object[] params) {
		MessageFormat formatter = new MessageFormat(bundle.getString(fmtKey));
		return formatter.format(params); 
	} 
} // class
