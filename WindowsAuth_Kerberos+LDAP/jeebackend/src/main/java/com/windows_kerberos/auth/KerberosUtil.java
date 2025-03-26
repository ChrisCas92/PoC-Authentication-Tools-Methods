package com.windows_kerberos.auth;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class KerberosUtil {
  private static final Logger LOGGER = Logger.getLogger(KerberosUtil.class.getName());

  /**
   * Configures the JVM system properties for Kerberos authentication.
   * This should be called during application startup.
   */
  public void configureKerberos() {
    try {
      LOGGER.info("Configuring Kerberos properties");

      // Set system properties for Kerberos
      System.setProperty("java.security.krb5.conf", "/path/to/krb5.conf");
      System.setProperty("java.security.auth.login.config", "/path/to/jaas.conf");
      System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");

      // Log the configuration
      LOGGER.info("Kerberos configuration complete");
    } catch (Exception e) {
      LOGGER.log(Level.SEVERE, "Error configuring Kerberos", e);
    }
  }

  /**
   * Validates if the current JVM environment is properly configured for Kerberos.
   * 
   * @return true if the environment is properly configured, false otherwise
   */
  public boolean isKerberosConfigured() {
    boolean configured = true;

    // Check for required system properties
    if (System.getProperty("java.security.krb5.conf") == null) {
      LOGGER.warning("java.security.krb5.conf is not set");
      configured = false;
    }

    if (System.getProperty("java.security.auth.login.config") == null) {
      LOGGER.warning("java.security.auth.login.config is not set");
      configured = false;
    }

    return configured;
  }
}
