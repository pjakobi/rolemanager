package tsn.iam.roles;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class PKCS12PropertiesLoader {
    public static Properties loadProperties() throws IOException {
        Properties configuration = new Properties();
        /* InputStream inputStream = PKCS12PropertiesLoader.class
          .getClassLoader()
          .getResourceAsStream("pkcs12.properties");//if named application.properties it doesn't work */
        File initialFile = new File("/etc/nexium/pkcs12.properties");
        InputStream targetStream = new FileInputStream(initialFile);
        configuration.load(targetStream);
        targetStream.close();
        return configuration;
    }
}
