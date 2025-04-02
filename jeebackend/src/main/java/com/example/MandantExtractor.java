package com.example;

import java.util.HashMap;
import java.util.Map;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;
import org.wildfly.security.http.oidc.OidcSecurityContext;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

/**
 * Extrahiert die Mandanten-ID aus dem UPN-Claim des ID-Tokens.
 * Speziell für die WildFly/JBoss Elytron OIDC-Implementation.
 */
@ApplicationScoped
public class MandantExtractor {

  @Inject
  private Logger log;

  // Domain zu Mandanten-ID Mapping
  private static final Map<String, String> DOMAIN_TO_MANDANT = new HashMap<>();

  static {
    DOMAIN_TO_MANDANT.put("rhl.drv", "13");
    DOMAIN_TO_MANDANT.put("bsh.drv", "14");
    DOMAIN_TO_MANDANT.put("now-it.drv", "15");
  }

  /**
   * Extrahiert die Mandanten-ID aus dem OidcSecurityContext.
   *
   * @param securityContext Der OIDC-Sicherheitskontext
   * @return Die Mandanten-ID oder null, wenn nicht ermittelbar
   */
  public String extractMandantFromContext(OidcSecurityContext securityContext) {
    if (securityContext == null) {
      log.debug("Kein OidcSecurityContext vorhanden");
      return null;
    }

    try {
      // Token als String verarbeiten
      String tokenString = securityContext.getTokenString();
      JwtConsumer jwtConsumer = new JwtConsumerBuilder()
          .setSkipSignatureVerification()
          .setSkipAllValidators()
          .build();

      JwtClaims claims = jwtConsumer.processToClaims(tokenString);
      String upn = claims.getStringClaimValue("upn");

      log.info("Extrahierter UPN: " + upn);
      return extractMandantFromUpn(upn);
    } catch (Exception e) {
      log.error("Fehler beim Parsen des Tokens", e);
      return null;
    }
  }

  /**
   * Extrahiert die Mandanten-ID direkt aus einem UPN-String.
   *
   * @param upn Der UPN im Format "username@domain"
   * @return Die Mandanten-ID oder null, wenn nicht ermittelbar
   */
  public String extractMandantFromUpn(String upn) {
    if (upn == null || !upn.contains("@")) {
      log.debug("UPN ist null oder enthält kein @-Zeichen: " + upn);
      return null;
    }

    String domain = upn.split("@")[1];
    log.debug("Extrahierte Domain: " + domain);

    String mandantId = DOMAIN_TO_MANDANT.get(domain);
    log.debug("Ermittelte Mandanten-ID: " + mandantId);

    return mandantId;
  }

  /**
   * Producer für den Logger.
   */
  @jakarta.enterprise.inject.Produces
  public Logger produceLogger() {
    return Logger.getLogger(MandantExtractor.class);
  }
}
