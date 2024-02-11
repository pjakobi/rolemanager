package tsn.iam.roles;

import java.text.MessageFormat;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RolesLogger {
	String msg;
	public RolesLogger(String className, Level level, String fmtKey, Object[] params) {
		Logger LOGGER = Logger.getLogger( className );
		ResourceBundle bundle = ResourceBundle.getBundle("messages"); //default locale
		MessageFormat formatter = new MessageFormat(bundle.getString(fmtKey));
		this.msg = formatter.format(params);
		LOGGER.log(level, msg);
    } // RolesLogger
	public String toString() { return msg; } 
} // class
