package tsn.iam.roles;

import java.net.Inet4Address;
import java.text.MessageFormat;
import java.util.ResourceBundle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;


//import java.util.logging.Level;
public class MyLog {
	private Object[] params;
	private ResourceBundle bundle = ResourceBundle.getBundle("messages"); //default locale
	String Label;
	MessageFormat formatter;
	
	String getLabelString() { return formatter.format(params); }
	
	MessageFormat makeFormatter(String label) { // shorthand
		this.Label = label;
		return new MessageFormat(bundle.getString(label));
	} // makeFormatter
	
	MyLog(Class className, Level level, String label) {
		formatter = makeFormatter(label);
		params = new Object[] { };
		doLog(className,level,formatter,params);
	   } // MyLog
	   
	MyLog(Class className, Level level, String label, String param ) {
		formatter = makeFormatter(label);
		params = new Object[] { param };
		doLog(className,level,formatter,params);
	   } // MyLog
	
	MyLog(Class className, Level level, String label, int param ) {
		formatter = makeFormatter(label);
		params = new Object[] { param };
		doLog(className,level,formatter,params);
	   } // MyLog	
	
	MyLog(Class className, Level level, String label, String param1, int param2 ) {
		formatter = makeFormatter(label);
		params = new Object[] { param1,param2 };
		doLog(className,level,formatter,params);
	} // MyLog
	
	MyLog(Class className, Level level, String label, String param1, String param2) {
		formatter = makeFormatter(label);
		params = new Object[] { param1,param2 };
		doLog(className,level,formatter,params);
	} // MyLog
	
	MyLog(Class className, Level level, String label, String param1, String param2, int param3) {
		formatter = makeFormatter(label);
		params = new Object[] { param1,param2,param3 };
		doLog(className,level,formatter,params);
	} // MyLog   
	
	MyLog(Class className, Level level, String label, String param1, String param2, String param3) {
		formatter = makeFormatter(label);
		params = new Object[] { param1,param2,param3 };
		doLog(className,level,formatter,params);
	} // MyLog
	MyLog(Class className, Level level, String label, String param1, String param2, String param3, String param4) {
		formatter = makeFormatter(label);
		params = new Object[] { param1,param2,param3, param4 };
		doLog(className,level,formatter,params);
	} // MyLog
	MyLog(Class className, Level level, String label, Inet4Address eMail) {
		formatter = makeFormatter(label);
		params = new Object[] { eMail.toString() };
		doLog(className,level,formatter,params);
	} // MyLog
	   
	   
	   
	public void doLog(Class className, Level level, MessageFormat formatter, Object[] params) {
		   Logger logger = LoggerFactory.getLogger(className);
		   if (logger.isDebugEnabled() && (level == Level.DEBUG)) logger.debug(formatter.format(params));
		   if (logger.isErrorEnabled() && (level == Level.ERROR)) logger.error(formatter.format(params));
		   if (logger.isWarnEnabled() && (level == Level.WARN)) logger.warn(formatter.format(params));
		   if (logger.isInfoEnabled() && (level == Level.INFO)) logger.info(formatter.format(params));
		   if (logger.isTraceEnabled() && (level == Level.TRACE)) logger.trace(formatter.format(params));
	   } // doLog
} // class MyLog
