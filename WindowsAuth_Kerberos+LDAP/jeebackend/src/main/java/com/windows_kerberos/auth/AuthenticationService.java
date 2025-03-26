package com.windows_kerberos.auth;

import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.ejb.Stateless;
import javax.inject.Inject;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import com.windows_kerberos.cache.UserCacheService;
import com.windows_kerberos.config.LdapConfig;
import com.windows_kerberos.model.UserDetails;

@Stateless
public class AuthenticationService {
  private static final Logger LOGGER = Logger.getLogger(AuthenticationService.class.getName());

  @Inject
  private LdapConfig ldapConfig;

  @Inject
  private UserCacheService cacheService;

  /**
   * Retrieves user details from LDAP based on the Windows username that was
   * authenticated through Kerberos.
   * 
   * @param username The username from Kerberos authentication
   * @return UserDetails containing the user's information from LDAP
   * @throws NamingException If there's an error querying LDAP
   */
  private UserDetails getUserDetailsFromLdap(String username) throws NamingException {
    DirContext context = null;
    try {
      // Get a connection to the LDAP directory
      context = ldapConfig.getLdapContext();

      // Configure search parameters
      SearchControls controls = new SearchControls();
      controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
      controls.setReturningAttributes(new String[] { "sAMAccountName", "displayName", "mail", "memberOf" });

      // Create search filter to find the user in Active Directory
      // sAMAccountName in Active Directory matches the Windows username
      String filter = "(sAMAccountName=" + escapeLdapSearchFilter(username) + ")";

      LOGGER.log(Level.INFO, "Searching LDAP with filter: {0}", filter);

      // Execute the search against the directory
      NamingEnumeration<SearchResult> results = context.search(
          ldapConfig.getLdapBase(), filter, controls);

      if (results.hasMore()) {
        // User found in LDAP
        SearchResult result = results.next();
        Attributes attributes = result.getAttributes();

        // Create and populate user details object
        UserDetails user = new UserDetails();
        user.setUsername(username);

        // Get display name if available
        if (attributes.get("displayName") != null) {
          user.setDisplayName((String) attributes.get("displayName").get());
        }

        // Get email if available
        if (attributes.get("mail") != null) {
          user.setEmail((String) attributes.get("mail").get());
        }

        // Extract group memberships
        user.setGroups(extractGroupsFromMemberOf(attributes));

        LOGGER.log(Level.INFO, "Retrieved user details: {0}", user);
        return user;
      }

      LOGGER.log(Level.WARNING, "User not found in LDAP: {0}", username);
      throw new RuntimeException("User not found in LDAP");
    } finally {
      // Always close the LDAP connection
      closeContextSafely(context);
    }
  }

  /**
   * Extracts the user's group memberships from the memberOf attribute in Active
   * Directory.
   * 
   * @param attributes The LDAP attributes returned for the user
   * @return A set of group names the user belongs to
   */
  private Set<String> extractGroupsFromMemberOf(Attributes attributes) throws NamingException {
    Set<String> groups = new HashSet<>();

    // Add a default role for all authenticated users
    groups.add("authenticated-user");

    // If the memberOf attribute exists, extract all group names
    if (attributes.get("memberOf") != null) {
      NamingEnumeration<?> memberOf = attributes.get("memberOf").getAll();
      while (memberOf.hasMore()) {
        String dnString = (String) memberOf.next();

        // Extract the CN (Common Name) from the Distinguished Name
        // Example: "CN=GroupName,OU=Groups,DC=example,DC=com" becomes "GroupName"
        if (dnString.startsWith("CN=")) {
          String groupName = dnString.substring(3, dnString.indexOf(','));
          groups.add(groupName);
        }
      }
    }

    return groups;
  }

  /**
   * Safely closes an LDAP context to prevent resource leaks.
   */
  private void closeContextSafely(DirContext context) {
    if (context != null) {
      try {
        context.close();
      } catch (NamingException e) {
        LOGGER.log(Level.WARNING, "Error closing LDAP context", e);
      }
    }
  }

  /**
   * Escapes special characters in LDAP search filters to prevent injection
   * attacks.
   * This follows the rules defined in RFC 2254.
   */
  private String escapeLdapSearchFilter(String filter) {
    if (filter == null) {
      return null;
    }

    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < filter.length(); i++) {
      char c = filter.charAt(i);
      switch (c) {
        case '\\':
          sb.append("\\5c");
          break;
        case '*':
          sb.append("\\2a");
          break;
        case '(':
          sb.append("\\28");
          break;
        case ')':
          sb.append("\\29");
          break;
        case '\u0000':
          sb.append("\\00");
          break;
        default:
          sb.append(c);
      }
    }

    return sb.toString();
  }
}