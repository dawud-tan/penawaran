package org.bouncycastle.util;

import java.security.AccessControlException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;
import java.util.Map;

/**
 * Utility method for accessing system properties.
 */
public class Properties {
    private Properties() {
    }

    private static final ThreadLocal threadProperties = new ThreadLocal();

    /**
     * Return whether a particular override has been set to true.
     *
     * @param propertyName the property name for the override.
     * @return true if the property is set to "true", false otherwise.
     */
    public static boolean isOverrideSet(String propertyName) {
        try {
            String p = getPropertyValue(propertyName);

            return "true".equalsIgnoreCase(p);
        } catch (AccessControlException e) {
            return false;
        }
    }

    public static String getPropertyValue(final String propertyName) {
        String val = (String) AccessController.doPrivileged((PrivilegedAction) () -> Security.getProperty(propertyName));
        if (val != null) {
            return val;
        }

        Map localProps = (Map) threadProperties.get();
        if (localProps != null) {
            String p = (String) localProps.get(propertyName);
            if (p != null) {
                return p;
            }
        }

        return (String) AccessController.doPrivileged((PrivilegedAction) () -> System.getProperty(propertyName));
    }
}
