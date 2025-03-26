package com.windows_kerberos.health;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;

import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Readiness;

import com.windows_kerberos.config.LdapConfig;

@Readiness
@ApplicationScoped
public class LdapHealthCheck implements HealthCheck {
  private static final Logger LOGGER = Logger.getLogger(LdapHealthCheck.class.getName());

  @Inject
  private LdapConfig ldapConfig;

  @Override
  public HealthCheckResponse call() {
    DirContext context = null;
    try {
      context = ldapConfig.getLdapContext();

      // Try to perform a simple search to verify connection
      SearchControls controls = new SearchControls();
      controls.setSearchScope(SearchControls.OBJECT_SCOPE);
      controls.setTimeLimit(5000); // 5 seconds timeout
      controls.setCountLimit(1); // Limit to 1 result

      // Just search for the base entry to verify connection
      context.search(ldapConfig.getLdapBase(), "(objectClass=*)", controls);

      return HealthCheckResponse.up("LDAP connection");
    } catch (NamingException e) {
      LOGGER.log(Level.SEVERE, "LDAP health check failed", e);
      return HealthCheckResponse.down("LDAP connection: " + e.getMessage());
    } finally {
      if (context != null) {
        try {
          context.close();
        } catch (NamingException e) {
          LOGGER.log(Level.WARNING, "Error closing LDAP context during health check", e);
        }
      }
    }
  }
}