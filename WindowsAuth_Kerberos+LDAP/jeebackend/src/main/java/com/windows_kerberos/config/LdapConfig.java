package com.windows_kerberos.config;

import java.util.Hashtable;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.eclipse.microprofile.config.inject.ConfigProperty;

@ApplicationScoped
public class LdapConfig {
  private static final Logger LOGGER = Logger.getLogger(LdapConfig.class.getName());

  @Inject
  @ConfigProperty(name = "ldap.url")
  private String ldapUrl;

  @Inject
  @ConfigProperty(name = "ldap.base")
  private String ldapBase;

  @Inject
  @ConfigProperty(name = "ldap.bind.dn")
  private String ldapBindDn;

  @Inject
  @ConfigProperty(name = "ldap.password")
  private String ldapPassword;

  @Inject
  @ConfigProperty(name = "ldap.pool.enabled", defaultValue = "true")
  private boolean poolEnabled;

  @Inject
  @ConfigProperty(name = "ldap.pool.timeout", defaultValue = "10000")
  private String poolTimeout;

  @Inject
  @ConfigProperty(name = "ldap.pool.maxsize", defaultValue = "20")
  private String poolMaxSize;

  @Inject
  @ConfigProperty(name = "ldap.connect.timeout", defaultValue = "5000")
  private String connectTimeout;

  @Inject
  @ConfigProperty(name = "ldap.retry.max", defaultValue = "3")
  private int maxRetries;

  @Inject
  @ConfigProperty(name = "ldap.retry.delay", defaultValue = "1000")
  private long retryDelay;

  @Inject
  @ConfigProperty(name = "ldap.secure", defaultValue = "false")
  private boolean secure;

  @Inject
  @ConfigProperty(name = "ldap.truststore.path", defaultValue = "")
  private String truststorePath;

  @Inject
  @ConfigProperty(name = "ldap.truststore.password", defaultValue = "")
  private String truststorePassword;

  /**
   * Creates and returns an LDAP directory context with the configured parameters.
   * Includes retry logic for resilience.
   * 
   * @return The LDAP directory context
   * @throws NamingException If there's an error establishing the context
   */
  public DirContext getLdapContext() throws NamingException {
    LOGGER.info("Creating new LDAP context");
    Hashtable<String, String> env = createEnvironment();
    return createContextWithRetry(env);
  }

  /**
   * Creates the environment hashtable for LDAP connection.
   * Configures secure connections and connection pooling if enabled.
   */
  private Hashtable<String, String> createEnvironment() {
    Hashtable<String, String> env = new Hashtable<>();

    // If secure LDAP is enabled, adjust URL and add SSL properties
    if (secure) {
      // Make sure URL starts with ldaps://
      if (!ldapUrl.startsWith("ldaps://")) {
        ldapUrl = ldapUrl.replace("ldap://", "ldaps://");
        // Default LDAPS port is 636 if not specified
        if (!ldapUrl.contains(":")) {
          ldapUrl += ":636";
        }
      }

      env.put(Context.SECURITY_PROTOCOL, "ssl");

      // Configure truststore if provided
      if (truststorePath != null && !truststorePath.isEmpty()) {
        System.setProperty("javax.net.ssl.trustStore", truststorePath);
        System.setProperty("javax.net.ssl.trustStorePassword", truststorePassword);
      }
    }

    // Rest of your environment setup
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
    env.put(Context.PROVIDER_URL, ldapUrl);
    env.put(Context.SECURITY_AUTHENTICATION, "simple");
    env.put(Context.SECURITY_PRINCIPAL, ldapBindDn);
    env.put(Context.SECURITY_CREDENTIALS, ldapPassword);

    // Connection timeout
    env.put("com.sun.jndi.ldap.connect.timeout", connectTimeout);

    // Connection pooling configuration
    if (poolEnabled) {
      env.put("com.sun.jndi.ldap.connect.pool", "true");
      env.put("com.sun.jndi.ldap.connect.pool.timeout", poolTimeout);
      env.put("com.sun.jndi.ldap.connect.pool.maxsize", poolMaxSize);
    }

    return env;
  }

  /**
   * Accessor method for the LDAP base DN used in searches.
   */
  public String getLdapBase() {
    return ldapBase;
  }

  /**
   * Creates an LDAP context with retry logic for resilience.
   * Will attempt to create a connection multiple times based on configuration.
   */
  private DirContext createContextWithRetry(Hashtable<String, String> env) throws NamingException {
    int retryCount = 0;

    while (true) {
      try {
        return new InitialDirContext(env);
      } catch (NamingException e) {
        retryCount++;
        LOGGER.log(Level.WARNING, "LDAP connection attempt {0} failed: {1}",
            new Object[] { retryCount, e.getMessage() });

        if (retryCount >= maxRetries) {
          LOGGER.log(Level.SEVERE, "Failed to connect to LDAP after {0} attempts", maxRetries);
          throw e;
        }

        try {
          LOGGER.log(Level.INFO, "Waiting {0}ms before retry...", retryDelay);
          Thread.sleep(retryDelay);
        } catch (InterruptedException ie) {
          Thread.currentThread().interrupt();
          throw new NamingException("LDAP connection retry interrupted: " + ie.getMessage());
        }
      }
    }
  }
}