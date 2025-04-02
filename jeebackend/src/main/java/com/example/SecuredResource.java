package com.example;

import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;
import jakarta.annotation.security.RolesAllowed;
import jakarta.ws.rs.core.Context;

import org.jboss.logging.Logger;
import org.wildfly.security.http.oidc.OidcPrincipal;
import org.wildfly.security.http.oidc.OidcSecurityContext;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

@Path("/api")
@RequestScoped
public class SecuredResource {

  @Inject
  private Logger log;

  @Inject
  private MandantExtractor mandantExtractor;

  @Context
  private SecurityContext securityContext;

  @GET
  @Path("/public")
  @Produces(MediaType.APPLICATION_JSON)
  public Response publicEndpoint() {
    log.info("Zugriff auf öffentlichen Endpunkt");
    return Response.ok("{\"message\": \"Dies ist ein öffentlicher Endpunkt\"}").build();
  }

  @GET
  @Path("/secured")
  @Produces(MediaType.APPLICATION_JSON)
  @RolesAllowed({ "user", "admin" })
  public Response securedEndpoint() {
    OidcSecurityContext oidcContext = extractOidcContext();
    if (oidcContext == null) {
      return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
          .entity("{\"error\": \"Keine OIDC-Authentifizierung vorhanden\"}").build();
    }

    try {
      JwtConsumer jwtConsumer = new JwtConsumerBuilder()
          .setSkipSignatureVerification()
          .setSkipAllValidators()
          .build();

      JwtClaims claims = jwtConsumer.processToClaims(oidcContext.getTokenString());
      String winaccountname = claims.getStringClaimValue("winaccountname");
      String upn = claims.getStringClaimValue("upn");

      String mandantId = mandantExtractor.extractMandantFromContext(oidcContext);

      String jsonResponse = String.format(
          "{\"message\": \"Dies ist ein gesicherter Endpunkt\", \"winaccountname\": \"%s\", \"upn\": \"%s\", \"mandantId\": \"%s\"}",
          winaccountname != null ? winaccountname : "nicht verfügbar",
          upn != null ? upn : "nicht verfügbar",
          mandantId != null ? mandantId : "unbekannt");

      return Response.ok(jsonResponse).build();
    } catch (Exception e) {
      log.error("Fehler beim Parsen des Tokens", e);
      return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
          .entity("{\"error\": \"Fehler beim Parsen des Tokens\"}").build();
    }
  }

  @GET
  @Path("/admin")
  @Produces(MediaType.APPLICATION_JSON)
  @RolesAllowed("admin")
  public Response adminEndpoint() {
    OidcSecurityContext oidcContext = extractOidcContext();
    if (oidcContext == null) {
      return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
          .entity("{\"error\": \"Keine OIDC-Authentifizierung vorhanden\"}").build();
    }

    try {
      JwtConsumer jwtConsumer = new JwtConsumerBuilder()
          .setSkipSignatureVerification()
          .setSkipAllValidators()
          .build();

      JwtClaims claims = jwtConsumer.processToClaims(oidcContext.getTokenString());
      String winaccountname = claims.getStringClaimValue("winaccountname");
      String upn = claims.getStringClaimValue("upn");

      String mandantId = mandantExtractor.extractMandantFromContext(oidcContext);

      String jsonResponse = String.format(
          "{\"message\": \"Dies ist ein Admin-Endpunkt\", \"winaccountname\": \"%s\", \"upn\": \"%s\", \"mandantId\": \"%s\"}",
          winaccountname != null ? winaccountname : "nicht verfügbar",
          upn != null ? upn : "nicht verfügbar",
          mandantId != null ? mandantId : "unbekannt");

      return Response.ok(jsonResponse).build();
    } catch (Exception e) {
      log.error("Fehler beim Parsen des Tokens", e);
      return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
          .entity("{\"error\": \"Fehler beim Parsen des Tokens\"}").build();
    }
  }

  private OidcSecurityContext extractOidcContext() {
    if (securityContext == null || securityContext.getUserPrincipal() == null) {
      log.warn("SecurityContext oder UserPrincipal ist null");
      return null;
    }

    if (securityContext.getUserPrincipal() instanceof OidcPrincipal) {
      return ((OidcPrincipal) securityContext.getUserPrincipal()).getOidcSecurityContext();
    }

    log.warn("UserPrincipal ist kein OidcPrincipal: " + securityContext.getUserPrincipal().getClass().getName());
    return null;
  }
}
