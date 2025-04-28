# **Dokumentation: Proof of Concept für Authentifizierungs- und Autorisierungskonzepte**

## **1\. Einleitung**

## **Einleitung und Motivation**

In der zunehmend digitalisierten Unternehmenslandschaft stellt die Sicherheit von Webanwendungen einen kritischen Erfolgsfaktor dar. Moderne Unternehmensanwendungen müssen nicht nur höchsten Sicherheitsanforderungen genügen, sondern gleichzeitig Benutzerfreundlichkeit, Performance und Skalierbarkeit gewährleisten.

### **1.1 Ausgangssituation**

Die Anwendung besteht aus:

* **Frontend**: Angular-basierte Single-Page-Application  
* **Backend**: Java EE-basierter Applikationsserver  
* **Künftige Anforderungen**: Neben der reinen Datenanzeige soll das Frontend später auch zur Fehlerkorrektur und \-behebung genutzt werden können

### **1.2 Methodischer Ansatz**

Zur umfassenden Evaluation wurden zwei alternative Sicherheitskonzepte entwickelt und systematisch untersucht. Die gesamte Testumgebung wurde mittels Docker containerisiert, um:

* **Reproduzierbarkeit** zu gewährleisten  
* **Vergleichbare** Testzenarien zu schaffen  
* Infrastruktur und Anwendungskomponenten **vollständig zu isolieren**

### **1.3 Untersuchte Konzepte**

1. **OAuth2 mit OpenID Connect (OIDC)**  
   PoC Implementierung mit Keycloak als Identitätsprovider, evtl. in Produktion Migration zu ADFS   sofern von notwendig  
2. **Windows-Authentifizierung mit LDAP und Kerberos**  
   Direkte Integration mit dem Active Directory über Java-LDAP-Schnittstellen und Kerberos für Single Sign-On

## **Rahmenbedingungen**

### **Technische Rahmenbedingungen**

* Komplexität der Anwendungsarchitektur  
* Anforderungen an Datenschutz und Compliance  
* Integration bestehender Systemlandschaften  
* Skalierbarkeit und Performanceanforderungen

### **Vergleichsdimensionen der Sicherheitskonzepte**

* Authentifizierungsmechanismen  
* Autorisierungsstrategien  
* Identitätsmanagement  
* Sicherheitsniveau  
* Implementierungsaufwand  
* Wartbarkeit und Erweiterbarkeit

## **Erwartete Ergebnisse**

Der Proof of Concept soll fundierte Antworten auf folgende Kernfragen liefern:

* Welches Sicherheitskonzept bietet den höchsten Schutz vor Sicherheitsrisiken?  
* Wie lässt sich die Benutzererfahrung ohne Kompromisse bei der Sicherheit optimieren?  
* Welche Implementierungsstrategie ermöglicht maximale Flexibilität und Zukunftsfähigkeit?

Die nachfolgenden Abschnitte dokumentieren die detaillierte Methodik, Durchführung und Erkenntnisse dieser vergleichenden Untersuchung.

## **2\. Technische Implementierungsdetails**

### **2.1 OAuth2 mit OpenID Connect**

#### **2.1.1 Keycloak-Implementierung für das PoC** 

Die Implementierung nutzt Keycloak als Identity-Provider und angular-oauth2-oidc als Client-Bibliothek für die nahtlose Integration mit Angular.

**Hauptkomponenten der Implementierung:**

**1\. Authentifizierungskonfiguration (auth.config.ts):**

```typescript
import { AuthConfig } from 'angular-oauth2-oidc';

export const authConfig: AuthConfig = {
  // Use localhost because the browser accesses Keycloak directly
  issuer: 'http://localhost:8080/realms/PoCRealm-Oauth2OpenIdConnect',
  redirectUri: window.location.origin,
  clientId: 'angular-client',
  responseType: 'code',
  scope: 'openid profile email',
  showDebugInformation: true,
  requireHttps: false,
  disableAtHashCheck: true,
  useIdTokenHintForSilentRefresh: true,
  // Client Secret für confidential clients
  dummyClientSecret: '9Ie6TbfCfkurKsUkq6Yx0zMtUE3J4Flv'
};

// Konfiguration für zukünftige ADFS-Migration
// export const adfsAuthConfig: AuthConfig = {
//  // ADFS-spezifische Konfiguration
//  issuer: 'https://adfs.example.com/adfs',
//  redirectUri: window.location.origin,
//  clientId: 'angular-client',
//  responseType: 'code',
//  scope: 'openid profile email',
//  showDebugInformation: false,
//  requireHttps: true,
//  disableAtHashCheck: true,
//  // ADFS hat möglicherweise eine andere Token-Struktur
//  customTokenParameters: ['resource']
// };

// Konfiguration für zukünftige PKCE-Implementierung
// export const pkceAuthConfig: AuthConfig = {
//  // Basis-Konfiguration bleibt gleich wie in authConfig
//  issuer: 'http://localhost:8080/realms/PoCRealm-Oauth2OpenIdConnect',
//  redirectUri: window.location.origin,
//  clientId: 'angular-client',
//  // PKCE-spezifische Einstellungen
//  responseType: 'code',
//  scope: 'openid profile email',
//  useSilentRefresh: true,
//  codeChallengeMethod: 'S256',
//  showDebugInformation: true,
//  requireHttps: false
// };

// Interface für die erwarteten Claims im Token
export interface UserClaims {
  // Standardmäßige OIDC-Claims + winaccountname und upn
  sub: string; // Eindeutige ID des Benutzers
  winaccountname?: string; // Windows-Kontoname des Benutzers falls verfügbar
  upn?: string; // User Principal Name (UPN) des Benutzers
  email?: string;
  name?: string;
  preferred_username?: string;
}

// Mapping von Domains zu Mandanten-IDs
export const domainToMandantMapping: Record<string, string> = {
  'rhl.drv': '13',
  'bsh.drv': '14',
  'now-it.drv': '15',
};

// Funktion zur Extraktion der Mandanten-ID aus dem UPN
export function extractMandantFromUpn(upn: string | undefined): string | null {
  if (!upn) {
    console.warn('Kein UPN vorhanden');
    return null;
  }

  // Wenn UPN bereits ein @ enthält, normale Extraktion verwenden
  if (upn.includes('@')) {
    const domain = upn.split('@')[1];
    return domainToMandantMapping[domain] || null;
  }

  // Spezielle Mapping-Logik für einfache Benutzernamen ohne Domain
  if (upn.startsWith('now')) {
    // NOW-IT-Benutzer gehören zu Mandant 15
    return '15';
  } else if (upn.startsWith('rhl')) {
    // RHL-Benutzer gehören zu Mandant 13
    return '13';
  } else if (upn.startsWith('bsh')) {
    // BSH-Benutzer gehören zu Mandant 14
    return '14';
  }

  console.warn('Konnte Mandanten-ID nicht aus UPN/Username ermitteln:', upn);
  return null;
}
```

Die Konfiguration definiert die wichtigsten Parameter für die Integration mit Keycloak:

* Der Issuer verweist auf den Keycloak-Realm "PoCRealm-Oauth2OpenIdConnect"  
* Die Client-ID "angular-client" entspricht dem in Keycloak konfigurierten Client  
* Die Anwendung verwendet den Authorization Code Flow (responseType: 'code')  
* Der angefragte Scope umfasst "openid profile email"  
* Es werden benutzerdefinierte Claims für die Windows-Benutzerkennung (winaccountname) und den User Principal Name (upn) definiert  
* Eine Funktion zur Extraktion der Mandanten-ID aus dem UPN wird bereitgestellt

**Sicherheitshinweis für den Produktionsbetrieb:**

Für den Produktionsbetrieb sollte die Implementierung um PKCE (Proof Key for Code Exchange) erweitert werden, um das Client-Secret besser zu schützen. Dies ließe sich durch folgende Ergänzungen in der Konfiguration erreichen:

```typescript
// Empfohlene Ergänzungen für den Produktionsbetrieb
export const authConfigProduction: AuthConfig = {
  // Basis-Konfiguration wie oben
  // ...

  // PKCE für zusätzliche Sicherheit
  useSilentRefresh: true,
  useHttpBasicAuth: true,
  
  // Code Challenge Method für PKCE
  codeChallengeMethod: 'S256'
};
```

PKCE bietet durch die Verwendung eines dynamisch generierten Code-Verifiers und einer daraus abgeleiteten Code-Challenge einen zusätzlichen Schutz gegen CSRF- und Authorization Code Interception-Angriffe, besonders wichtig für öffentliche Clients und Anwendungen mit höheren Sicherheitsanforderungen.

**3\. HTTP-Interceptor für Token-Hinzufügung (auth.interceptor.ts):**

```typescript
import { HttpInterceptorFn, HttpRequest, HttpHandlerFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { AuthService } from './auth.service';

export const authInterceptor: HttpInterceptorFn = (
  req: HttpRequest<unknown>,
  next: HttpHandlerFn
) => {
  const authService = inject(AuthService);

  // Aktuell: Benutze ID-Token statt Access-Token (entsprechend den Anforderungen)
  // Bei ADFS-Migration: Token-Typ könnte sich ändern, abhängig von der ADFS-Konfiguration
  // Bei PKCE-Implementierung: Access-Token würde statt ID-Token verwendet werden

  const idToken = authService.getIdToken();
  
  if (idToken && shouldAddToken(req.url)) {
    // Authorization Header mit Bearer Token hinzufügen
    // Bleibt bei PKCE und ADFS-Migration gleich, nur Token-Quelle ändert sich
    const authReq = req.clone({
      setHeaders: { Authorization: `Bearer ${idToken}` }
    });
    
    return next(authReq);
  }
  
  return next(req);
};

// Hilfsfunktion, um festzulegen, für welche URLs der Token verwendet werden soll
// Bleibt unverändert bei PKCE und ADFS-Migration
function shouldAddToken(url: string): boolean {
  // Token nur für Backend-API-Aufrufe hinzufügen
  return url.includes('/api/');
}
```

Der Interceptor:

* Fügt automatisch das ID-Token zu allen API-Requests hinzu  
* Verwendet eine Hilfsfunktion, um zu entscheiden, für welche URLs der Token erforderlich ist  
* Stellt den Token im Authorization-Header im Bearer-Format bereit

**4\. Backend-Implementierung für Mandantenverarbeitung:** 

- **MandantExtractor.java \- Extraktion der Mandanteninformation aus dem Token:**

```java
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
```

- **SecuredResource.java \- REST-Endpunkte mit Mandantenverarbeitung:**

```java
package com.example;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.core.Context;
import org.jboss.logging.Logger;
import org.wildfly.security.http.oidc.OidcPrincipal;
import org.wildfly.security.http.oidc.OidcSecurityContext;

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
        return Response.ok("{\"message\": \"This is a public endpoint\"}")
            .header("Access-Control-Allow-Origin", "*")
            .build();
    }

    @GET
    @Path("/secured")
    @Produces(MediaType.APPLICATION_JSON)
    public Response securedEndpoint() {
        OidcSecurityContext oidcContext = extractOidcContext();
        if (oidcContext == null) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity("{\"error\": \"Keine OIDC-Authentifizierung vorhanden\"}")
                .build();
        }

        String username = securityContext.getUserPrincipal().getName();
        String mandantId = mandantExtractor.extractMandantFromContext(oidcContext);
        return Response.ok(String.format(
                "{\"message\": \"This is a secured endpoint\", \"user\": \"%s\", \"mandantId\": \"%s\"}",
                username, mandantId != null ? mandantId : "unbekannt"))
            .header("Access-Control-Allow-Origin", "*")
            .build();
    }

    @GET
    @Path("/admin")
    @Produces(MediaType.APPLICATION_JSON)
    public Response adminEndpoint() {
        OidcSecurityContext oidcContext = extractOidcContext();
        if (oidcContext == null) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity("{\"error\": \"Keine OIDC-Authentifizierung vorhanden\"}")
                .build();
        }

        String username = securityContext.getUserPrincipal().getName();
        String mandantId = mandantExtractor.extractMandantFromContext(oidcContext);
        return Response.ok(String.format(
                "{\"message\": \"This is an admin endpoint\", \"user\": \"%s\", \"mandantId\": \"%s\"}",
                username, mandantId != null ? mandantId : "unbekannt"))
            .header("Access-Control-Allow-Origin", "*")
            .build();
    }

    /**
     * Extrahiert den OIDC-Kontext aus dem SecurityContext.
     */
    private OidcSecurityContext extractOidcContext() {
        if (securityContext == null || securityContext.getUserPrincipal() == null) {
            log.warn("SecurityContext oder UserPrincipal ist null");
            return null;
        }

        if (securityContext.getUserPrincipal() instanceof OidcPrincipal) {
            return ((OidcPrincipal) securityContext.getUserPrincipal()).getOidcSecurityContext();
        }

        log.warn("UserPrincipal ist kein OidcPrincipal: " + 
                 securityContext.getUserPrincipal().getClass().getName());
        return null;
    }
}
```

- **JaxRsApplication.java \- JAX-RS Anwendungskonfiguration: (evtl. notwendig)**

```java
package com.example;

import javax.enterprise.context.ApplicationScoped;
import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

@ApplicationPath("/")
@ApplicationScoped
public class JaxRsApplication extends Application {
    // Die Ressourcen werden automatisch erkannt
}
```

- **CORSFilter.java \- Cross-Origin Resource Sharing Filter:**

```java
package com.example;

import java.io.IOException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;
import javax.ws.rs.ext.Provider;

@Provider
public class CORSFilter implements ContainerResponseFilter {
    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext)
            throws IOException {
        responseContext.getHeaders().add("Access-Control-Allow-Origin", "*");
        responseContext.getHeaders().add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD");
        responseContext.getHeaders().add("Access-Control-Allow-Headers", "origin, content-type, accept, authorization");
        responseContext.getHeaders().add("Access-Control-Allow-Credentials", "true");
    }
}
```

Diese Backend-Implementierung:

● Extrahiert Mandanteninformationen aus dem Token anhand der UPN-Domain

● Bietet drei REST-Endpunkte mit unterschiedlichen Sicherheitsstufen

● Stellt die relevanten Benutzer- und Mandanteninformationen in der Antwort bereit

● Ermöglicht Cross-Origin Requests über den CORS-Filter

**8\. Backend-Konfiguration:**

```xml
<!-- standalone.xml -->
<subsystem xmlns="urn:wildfly:elytron-oidc-client:1.0">
  <provider name="keycloak">
    <provider-url>http://keycloak:8080/realms/PoCRealm-Oauth2OpenIdConnect</provider-url>
    <ssl-required>external</ssl-required>
  </provider>
  
  <secure-deployment name="jee-backend-1.0">
    <provider>keycloak</provider>
    <client-id>angular-client</client-id>
    <credential name="secret" secret="${env.OIDC_CLIENT_SECRET:your-client-secret}"/>
    <principal-claim>winaccountname</principal-claim>
    <token-type>id_token</token-type>
  </secure-deployment>
</subsystem>
```

**Sicherheitsempfehlung für den Produktionsbetrieb:**

Im Produktionsbetrieb sollte das Client-Secret nicht als Klartext in der Konfiguration oder als Umgebungsvariable gespeichert werden. Stattdessen empfiehlt sich die Verwendung des Elytron Credential Store:

```xml
<!-- Credential Store Konfiguration für Produktionsumgebungen -->
<subsystem xmlns="urn:wildfly:elytron:15.1">
  <!-- ... andere Elytron-Konfigurationen ... -->
  
  <!-- Credential Store für sichere Geheimnisspeicherung -->
  <credential-stores>
    <credential-store name="oidcCredentialStore" relative-to="jboss.server.config.dir" path="credential-store.jceks">
      <credential-reference clear-text="password123"/>
      <implementation-properties>
        <property name="keyStoreType" value="JCEKS"/>
      </implementation-properties>
    </credential-store>
  </credential-stores>
  
  <!-- ... -->
</subsystem>

<!-- OIDC-Konfiguration mit Credential Store für Client Secret -->
<subsystem xmlns="urn:wildfly:elytron-oidc-client:1.0">
  <provider name="keycloak">
    <provider-url>http://keycloak:8080/realms/PoCRealm-Oauth2OpenIdConnect</provider-url>
    <ssl-required>external</ssl-required>
  </provider>
  
  <secure-deployment name="jee-backend-1.0">
    <provider>keycloak</provider>
    <client-id>angular-client</client-id>
    <credential name="secret" secret="${CREDENTIAL_STORE:oidcCredentialStore:client-secret}"/>
    <principal-claim>winaccountname</principal-claim>
    <token-type>id_token</token-type>
  </secure-deployment>
</subsystem>
```

Mit dem Elytron Credential Store wird das Client-Secret sicher verschlüsselt gespeichert und ist nicht mehr im Klartext in der Konfiguration oder als Umgebungsvariable sichtbar, was die Sicherheit deutlich erhöht.

### **2.2 Windows-Authentifizierung mit LDAP und Kerberos**

Diese Implementierung kombiniert LDAP für den Zugriff auf Verzeichnisdienste mit Kerberos für den sicheren Authentifizierungsprozess. Diese Integration bietet eine nahtlose "Single Sign-On"-Erfahrung in Windows-Umgebungen.

#### **2.2.1 Kernkomponenten der Implementierung**

**LDAP-Authentifizierungsservice:**

```java
public class LdapAuthenticationService {
    public boolean authenticate(String username, String password) {
        // Verbindung zum LDAP-Server herstellen
        // Benutzer suchen und mit Passwort authentifizieren
        // ...
        return false; // Platzhalter für tatsächliche Implementierung
    }

    public String[] getUserGroups(String username) {
        // Gruppenmitgliedschaften des Benutzers abfragen
        // ...
        return new String[0]; // Platzhalter für tatsächliche Implementierung
    }
}
```

**Kerberos-Authentifizierung:**

Kerberos ist ein netzwerkbasiertes Authentifizierungsprotokoll, das auf dem "Ticket"-Konzept basiert. Es ermöglicht Benutzern, sich einmal bei einem zentralen Authentifizierungsdienst (Key Distribution Center, KDC) anzumelden und dann auf verschiedene Dienste zuzugreifen, ohne erneut Anmeldedaten einzugeben.

```java
package com.meinefirma.security;

import org.ietf.jgss.*;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.security.PrivilegedAction;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.util.Base64;

@Provider
public class KerberosAuthenticationFilter implements ContainerRequestFilter {
    private static final String NEGOTIATE = "Negotiate";
    private static final String AUTHORIZATION = "Authorization";
    private static final String WWW_AUTHENTICATE = "WWW-Authenticate";

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        String authHeader = requestContext.getHeaderString(AUTHORIZATION);
        
        // Prüfen, ob ein Authorization-Header vorhanden ist und mit "Negotiate" beginnt
        if (authHeader == null || !authHeader.startsWith(NEGOTIATE + " ")) {
            // Kein oder falscher Auth-Header: Challenge senden
            requestContext.abortWith(
                Response.status(Response.Status.UNAUTHORIZED)
                    .header(WWW_AUTHENTICATE, NEGOTIATE)
                    .build());
            return;
        }

        // Kerberos-Token aus dem Header extrahieren
        String kerberosToken = authHeader.substring(NEGOTIATE.length() + 1);
        byte[] token = Base64.getDecoder().decode(kerberosToken);

        try {
            // Kerberos-Authentifizierung durchführen
            Subject serviceSubject = loginAsService();

            // Als Service-Prinzipal ausführen
            KerberosValidationResult result = Subject.doAs(serviceSubject,
                (PrivilegedAction<KerberosValidationResult>) () -> {
                    try {
                        // GSSContext initialisieren
                        GSSManager manager = GSSManager.getInstance();
                        GSSCredential credential = manager.createCredential(null,
                            GSSCredential.INDEFINITE_LIFETIME,
                            new Oid("1.3.6.1.5.5.2"), // SPNEGO
                            GSSCredential.ACCEPT_ONLY);

                        GSSContext context = manager.createContext(credential);

                        // Token validieren und den Client-Principal extrahieren
                        byte[] outputToken = context.acceptSecContext(token, 0, token.length);
                        String clientPrincipal = context.getSrcName().toString();

                        // Benutzerinformationen extrahieren (typischerweise user@REALM.COM)
                        String username = extractUsername(clientPrincipal);

                        return new KerberosValidationResult(true, username, outputToken);
                    } catch (GSSException e) {
                        return new KerberosValidationResult(false, null, null);
                    }
                });

            if (result.isAuthenticated()) {
                // Extraktion des Benutzernamens und der Rollen aus Active Directory
                String username = result.getUsername();

                // LDAP verwendet, um zusätzliche Benutzerinformationen und Gruppen zu holen
                LdapAuthenticationService ldapService = new LdapAuthenticationService();
                String[] groups = ldapService.getUserGroups(username);

                // Benutzerinformationen im Request-Kontext speichern
                requestContext.setProperty("username", username);
                requestContext.setProperty("roles", groups);

                // Optional: Antwort-Token für komplette SPNEGO-Handshake
                if (result.getResponseToken() != null) {
                    requestContext.getHeaders().add(WWW_AUTHENTICATE,
                        NEGOTIATE + " " + Base64.getEncoder().encodeToString(result.getResponseToken()));
                }
            } else {
                // Authentifizierung fehlgeschlagen
                requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
            }
        } catch (Exception e) {
            // Fehler bei der Authentifizierung
            requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
        }
    }

    // Service-Principal anmelden (verwendet JAAS-Konfiguration)
    private Subject loginAsService() throws LoginException {
        LoginContext loginContext = new LoginContext("com.sun.security.jgss.accept");
        loginContext.login();
        return loginContext.getSubject();
    }

    // Benutzername aus dem Kerberos-Principal extrahieren
    private String extractUsername(String principal) {
        // Typisches Format: username@REALM.COM
        return principal.split("@")[0];
    }

    // Hilfsklasse für das Ergebnis der Kerberos-Validierung
    private static class KerberosValidationResult {
        private final boolean authenticated;
        private final String username;
        private final byte[] responseToken;

        public KerberosValidationResult(boolean authenticated, String username, byte[] responseToken) {
            this.authenticated = authenticated;
            this.username = username;
            this.responseToken = responseToken;
        }

        public boolean isAuthenticated() {
            return authenticated;
        }

        public String getUsername() {
            return username;
        }

        public byte[] getResponseToken() {
            return responseToken;
        }
    }
}
```

**JAAS-Konfiguration für Kerberos:**

Die Java Authentication and Authorization Service (JAAS) Konfigurationsdatei definiert, wie die JVM mit Kerberos interagiert:

```properties
com.sun.security.jgss.accept {
  com.sun.security.auth.module.Krb5LoginModule required
  useKeyTab=true
  keyTab="/etc/krb5.keytab"
  principal="HTTP/service.meinefirma.de@MEINEFIRMA.DE"
  storeKey=true
  doNotPrompt=true
};
```

**Kerberos-Konfiguration (krb5.conf):**

```ini
[libdefaults]
default_realm = MEINEFIRMA.DE
dns_lookup_realm = false
dns_lookup_kdc = false
ticket_lifetime = 24h
renew_lifetime = 7d
forwardable = true

[realms]
MEINEFIRMA.DE = {
  kdc = kdc1.meinefirma.de
  kdc = kdc2.meinefirma.de
  admin_server = kdc1.meinefirma.de
}

[domain_realm]
.meinefirma.de = MEINEFIRMA.DE
meinefirma.de = MEINEFIRMA.DE
```

#### **2.2.2 Integration in Angular-Frontend**

Für die Integration von Kerberos im Angular-Frontend müssen bestimmte Anpassungen vorgenommen werden, um die integrierte Windows-Authentifizierung zu ermöglichen:

```typescript
// kerberos-auth.service.ts
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { BehaviorSubject, Observable, of } from 'rxjs';
import { tap, catchError, map } from 'rxjs/operators';

@Injectable({
  providedIn: 'root'
})
export class KerberosAuthService {
  private currentUserSubject = new BehaviorSubject<any>(null);
  public currentUser$ = this.currentUserSubject.asObservable();
  
  private apiUrl = 'http://localhost:8080/api';

  constructor(private http: HttpClient) {
    // Prüfen des Authentifizierungsstatus beim Start
    this.checkAuthStatus().subscribe();
  }

  // Authentifizierungsstatus prüfen
  checkAuthStatus(): Observable<boolean> {
    // Wichtig: withCredentials=true, damit Kerberos-Tickets gesendet werden
    return this.http.get<any>(`${this.apiUrl}/auth/kerberosInfo`, { withCredentials: true })
      .pipe(
        map(userInfo => {
          if (userInfo && userInfo.username) {
            this.currentUserSubject.next(userInfo);
            return true;
          }
          return false;
        }),
        catchError(error => {
          if (error.status === 401) {
            // Initiierung des Kerberos-Authentifizierungsprozesses
            return this.initiateKerberosAuth();
          }
          return of(false);
        })
      );
  }

  // Initiieren des Kerberos-Authentifizierungsprozesses
  private initiateKerberosAuth(): Observable<boolean> {
    return this.http.get<any>(`${this.apiUrl}/auth/kerberos`, {
      withCredentials: true,
      observe: 'response'
    }).pipe(
      map(response => {
        // Prüfen der WWW-Authenticate Header
        const negotiateHeader = response.headers.get('WWW-Authenticate');
        if (negotiateHeader && negotiateHeader.startsWith('Negotiate ')) {
          // Erfolgreiche Authentifizierung, Benutzerinformationen abrufen
          return this.checkAuthStatus().toPromise();
        }
        return false;
      }),
      catchError(() => of(false))
    );
  }
}
```

**Wichtige Browsereinstellungen:**

Für die Kerberos-Authentifizierung im Browser muss dieser richtig konfiguriert sein, um die integrierte Windows-Authentifizierung zu unterstützen:

1. **Internet Explorer / Edge:**  
   * Die Website zur "Lokalen Intranet-Zone" hinzufügen  
   * "Integrierte Windows-Authentifizierung" aktivieren  
2. **Chrome:**  
   * Startparameter \--auth-server-whitelist="\*.meinefirma.de" hinzufügen  
   * Gruppenrichtlinien für die automatische NTLM/Kerberos-Authentifizierung konfigurieren  
3. **Firefox:**  
   * In about  
      den Parameter network.negotiate-auth.trusted-uris auf \*.meinefirma.de setzen

#### **2.2.3 Vorteile der Kombination von Kerberos und LDAP**

Die Kombination von Kerberos für die Authentifizierung und LDAP für die Autorisierung bietet mehrere wesentliche Vorteile:

1. **Echte Single Sign-On-Erfahrung**: Benutzer müssen sich nur einmal bei ihrem Windows-System anmelden und können dann auf alle Anwendungen zugreifen, ohne erneut Anmeldedaten eingeben zu müssen.  
2. **Hohe Sicherheit**: Kerberos ist ein ausgereiftes, sicheres Protokoll, das Passwörter niemals im Klartext über das Netzwerk überträgt.  
3. **Delegierte Authentifizierung**: Ermöglicht Services, sich im Namen des Benutzers bei anderen Services zu authentifizieren (Service-zu-Service-Authentifizierung).  
4. **Zentrale Verwaltung**: Benutzerkonten und Berechtigungen werden zentral im Active Directory verwaltet, was den Administrationsaufwand reduziert.  
5. **Nahtlose Integration in Windows-Umgebungen**: Perfekte Passung für Unternehmen, die bereits eine Microsoft-Infrastruktur nutzen.

## **3\. Vergleichsanalyse**

### **3.1 OAuth2 mit OpenID Connect**

**Stärken:**

* Moderne, standardisierte Sicherheitsprotokolle  
* Hohe Sicherheit durch token-basierte Authentifizierung  
* Klare Trennung von Authentifizierung und Autorisierung  
* Unterstützung für Single Sign-On (SSO) über mehrere Anwendungen hinweg  
* Hervorragende Skalierbarkeit für verteilte Systeme und Microservices  
* Flexible Integration verschiedener Clienttypen (Web, Mobile, Desktop)  
* Unterstützung für Refresh-Tokens für längere Sessions ohne erneute Anmeldung  
* Breite Unterstützung in modernen Client-Bibliotheken wie angular-oauth2-oidc

**Schwächen:**

* Höhere initiale Komplexität bei der Implementierung  
* Zusätzliche Infrastrukturkomponente (Identity Provider) erforderlich  
* Potenziell höherer Verwaltungsaufwand  
* Komplexere Setup- und Konfigurationsschritte

**Migrationsaufwand zu ADFS:** Der Migrationsaufwand von Keycloak zu ADFS ist moderat. Die Hauptänderungen betreffen die Endpunkte und das Mapping der Benutzerrollen, da ADFS eine andere Claim-Struktur verwendet. Die Gesamtarchitektur bleibt jedoch unverändert.

### **3.2 Windows-Authentifizierung mit LDAP und Kerberos**

**Stärken:**

* Direkte Integration mit dem vorhandenen Active Directory  
* Kein zusätzlicher Identity Provider erforderlich  
* Nahtlose "Single Sign-On"-Erfahrung in Windows-Umgebungen ohne zusätzliche Anmeldungen  
* Hohe Sicherheit durch ausgereiftes, kryptografisch starkes Authentifizierungsprotokoll  
* Keine Übertragung von Passwörtern im Netzwerk (nur Kerberos-Tickets)  
* Möglichkeit zur delegierten Authentifizierung für mehrstufige Anwendungsarchitekturen  
* Hervorragende Integration in bestehende Windows-Domänenumgebungen  
* Reduzierter Verwaltungsaufwand durch zentrale Benutzer- und Gruppenverwaltung im Active Directory  
* Gut geeignet für Intranet-Anwendungen  
* Vertraute Lösung für IT-Abteilungen in Windows-Umgebungen

**Schwächen:**

* Komplexe Konfiguration der Kerberos-Infrastruktur (Service Principal Names, Keytabs)  
* Funktioniert am besten in homogenen Windows-Umgebungen, weniger gut mit nicht-Windows-Clients  
* Stark abhängig von korrekter DNS-Konfiguration und Zeitsynchronisation  
* Kann Probleme bei der Verwendung über Internet-Verbindungen oder mit mobilen Geräten verursachen  
* Erfordert spezielle Browsereinstellungen für die Aktivierung der integrierten Authentifizierung  
* Eingeschränkte Unterstützung für moderne Authentifizierungsszenarien  
* Weniger flexibel für verteilte Systeme und Microservices  
* Schwieriger für Single Sign-On über verschiedene Plattformen hinweg (nicht-Windows)

## **4\. Bewertung anhand von Kriterien**

| Kriterium | OAuth2/OIDC | Windows/LDAP/Kerberos |
| :---- | :---- | ----- |
| Sicherheit | ★★★★★ | ★★★★★ |
| Zukunftsfähigkeit | ★★★★★ | ★★★☆☆ |
| Implementierungsaufwand | ★★★☆☆ | ★★☆☆☆ |
| Wartbarkeit | ★★★★☆ | ★★★☆☆ |
| Skalierbarkeit | ★★★★★ | ★★☆☆☆ |
| Integrations Optionen | ★★★★★ | ★★★☆☆ |
| Single Sign-On Möglichkeiten | ★★★★★ | ★★★★★ |
| Unterstützung für Microservices | ★★★★★ | ★★☆☆☆ |
| Integration in Windows-Umgebungen | ★★★☆☆ | ★★★★★ |

## **5\. Empfehlung**

Nach eingehender Analyse der beiden Sicherheitskonzepte empfehlen wir die Implementierung von **OAuth2 mit OpenID Connect (OIDC)** aus folgenden Gründen:

1. **Zukunftssicherheit**: OAuth2/OIDC ist der moderne Industriestandard für Authentifizierung und Autorisierung und wird kontinuierlich weiterentwickelt.  
2. **Flexibilität**: Die token-basierte Authentifizierung ermöglicht eine höhere Flexibilität bei der Integration verschiedener Client Typen und unterstützt moderne Architekturansätze.  
3. **Skalierbarkeit**: Falls die Anwendung künftig in Richtung Microservices oder verteilte Systeme entwickelt wird, bietet OAuth2/OIDC die beste Unterstützung.  
4. **Sicherheit**: Die klare Trennung von Authentifizierung und Autorisierung sowie die token-basierte Architektur bieten ein hohes Sicherheitsniveau.  
5. **Single Sign-On**: Die native Unterstützung für SSO ermöglicht eine nahtlose Integration mit anderen Unternehmensanwendungen.

Die initiale Implementierung kann mit Keycloak erfolgen, was eine schnelle Entwicklung und Testung ermöglicht. Bei Bedarf kann später eine Migration zu ADFS mit überschaubarem Aufwand durchgeführt werden, wie in unserem PoC demonstriert.

Obwohl die Windows-Authentifizierung mit LDAP und Kerberos eine attraktive Alternative für Umgebungen mit starker Windows-Integration darstellt, wurde diese Option letztendlich nicht empfohlen. Die Implementierung Komplexität war im Vergleich zum OAuth2/OIDC-Ansatz deutlich höher und erforderte tiefere Kenntnisse in Kerberos-Sicherheit und Systemadministration. Für das PoC waren die Hürden bei der Kerberos-Einrichtung (Service Principal Names, Keytabs, spezielle DNS-Konfigurationen) sowie die notwendigen Browsereinstellungen zu komplex und fehleranfällig. Der Ansatz wäre zwar für eine reine Intranet-Anwendung in einer homogenen Windows-Umgebung geeignet, bietet aber weniger Zukunftssicherheit und Flexibilität für moderne Anwendungsszenarien, insbesondere im Hinblick auf plattformübergreifende Nutzung und Microservices-Architekturen.

## **6\. Implementierungsplan / \-variante**

### **Phase 1: Setup und Grundlagenimplementierung**

1. Einrichtung einer Keycloak-Instanz in Docker  
2. Konfiguration des Realms, Clients und Benutzer in Keycloak  
3. Integration des Angular-Frontends mit angular-oauth2-oidc  
4. Integration des JEE-Backends mit Keycloak-Adapter

### **Phase 2: Feinabstimmung und Erweiterung**

1. Implementierung detaillierter Rollenhierarchien  
2. Konfiguration von Token-Lifetimes und Session-Management  
3. Implementierung von Refresh-Token-Logik  
4. Hinzufügen von benutzerspezifischen Claims und Attributen  
5. Für den Produktionsbetrieb: Integration von PKCE (Proof Key for Code Exchange) für erhöhte Sicherheit  
6. Für den Produktionsbetrieb: Einrichtung des Elytron Credential Store für sichere Client-Secret-Speicherung

### **Phase 3: Testphase und Validierung**

1. Umfassende Tests der Authentifizierungs- und Autorisierungslogik  
2. Sicherheitsaudits und Penetrationstests  
3. Performance-Tests unter Last  
4. Validierung gegen Compliance-Anforderungen

### **Phase 4 (Optional): Migration zu ADFS**

1. Einrichtung und Konfiguration von ADFS  
2. Anpassung der Frontend- und Backend-Konfigurationen  
3. Parallelbetrieb und schrittweise Migration  
4. Vollständige Umstellung und Abschaltung von Keycloak

## **6.1 Implementierung ohne Docker**

Für Umgebungen, in denen keine Docker-Containerisierung verwendet werden kann oder soll, sind folgende Anpassungen in der Implementierung notwendig. Diese Änderungen betreffen nur den Code und die Konfigurationseinstellungen, nicht die Installation der Komponenten selbst.

### **1\. Frontend-Konfiguration (Angular)**

#### **1.1 OAuth2/OIDC Konfiguration anpassen**

In `auth.config.ts` müssen die Endpunkte angepasst werden, um die direkte Kommunikation mit dem Keycloak-Server ohne Docker-Netzwerk zu ermöglichen:

```typescript
// auth.config.ts - Anpassung für Nicht-Docker-Umgebung
export const authConfig: AuthConfig = {
  // Direkte URL zum Keycloak-Server (passen Sie die URL an Ihre Umgebung an)
  issuer: 'http://localhost:8080/realms/PoCRealm-Oauth2OpenIdConnect',
  redirectUri: window.location.origin,
  clientId: 'angular-client',
  responseType: 'code',
  scope: 'openid profile email',
  
  // Weitere Konfiguration bleibt unverändert
  showDebugInformation: true,
  requireHttps: false,
  // In Produktionsumgebungen auf true setzen
  disableAtHashCheck: true,
  dummyClientSecret: '9Ie6TbfCfkurKsUkq6Yx0zMtUE3J4Flv'
};
```

#### **1.2 API-Endpunkte anpassen**

In den Service-Klassen, die HTTP-Requests ausführen, müssen die Backend-URLs angepasst werden:

```typescript
// Beispiel-Anpassung in einem Service
@Injectable({
  providedIn: 'root'
})
export class ApiService {
  // Backend-Basis-URL (passen Sie diese an Ihre Umgebung an)
  private baseUrl = 'http://localhost:8081/jee-backend-1.0/api';  

  constructor(private http: HttpClient) {}

  getResource(): Observable<any> {
    return this.http.get(`${this.baseUrl}/secured`);
  }

  // Weitere Methoden
}
```

#### **1.3 Proxy-Konfiguration ohne Nginx**

Anstelle der Nginx-Konfiguration kann die Angular Dev Server Proxy-Konfiguration in `proxy.conf.json` verwendet werden:

```json
{
  "/api": {
    "target": "http://localhost:8081/jee-backend-1.0",
    "secure": false,
    "changeOrigin": true,
    "pathRewrite": {
      "^/api": "/api"
    }
  },
  "/realms": {
    "target": "http://localhost:8080",
    "secure": false,
    "changeOrigin": true
  }
}
```

Und in `angular.json` die entsprechende Konfiguration anpassen:

```json
"serve": {
  "builder": "@angular-devkit/build-angular:dev-server",
  "options": {
    "browserTarget": "oauth2-openIDConnect-angularFrontend-jeeBackend:build",
    "proxyConfig": "proxy.conf.json"
  }
  // Weitere Konfiguration
}
```

#### **1.4 Produktionsbuild-Anpassungen**

Für den Produktionsbuild müssen die URLs in der Umgebungskonfiguration angepasst werden:

```typescript
// environments/environment.prod.ts
export const environment = {
  production: true,
  apiBaseUrl: 'http://server-hostname:8081/jee-backend-1.0/api',
  keycloakUrl: 'http://keycloak-hostname:8080/realms/PoCRealm-Oauth2OpenIdConnect'
};
```

### **2\. Backend-Konfiguration (JBoss/WildFly)**

#### **2.1 OIDC-Client Konfiguration**

In der `standalone.xml` von JBoss/WildFly muss die Keycloak-URL angepasst werden:

```xml
<subsystem xmlns="urn:wildfly:elytron-oidc-client:1.0">
  <provider name="keycloak">
    <!-- Angepasste URL für lokale Keycloak-Instanz -->
    <provider-url>http://localhost:8080/realms/PoCRealm-Oauth2OpenIdConnect</provider-url>
    <ssl-required>external</ssl-required>
  </provider>
  <secure-deployment name="jee-backend-1.0">
    <provider>keycloak</provider>
    <client-id>angular-client</client-id>
    <credential name="secret" secret="${env.OIDC_CLIENT_SECRET:9Ie6TbfCfkurKsUkq6Yx0zMtUE3J4Flv}"/>
    <principal-claim>winaccountname</principal-claim>
    <token-type>id_token</token-type>
  </secure-deployment>
</subsystem>
```

#### **2.2 MicroProfile Config Properties**

Alternativ können die Konfigurationsparameter in `microprofile-config.properties` definiert werden:

```properties
# Keycloak OIDC Konfiguration für Nicht-Docker-Umgebung
mp.jwt.verify.publickey.location=http://localhost:8080/realms/PoCRealm-Oauth2OpenIdConnect/protocol/openid-connect/certs
mp.jwt.verify.issuer=http://localhost:8080/realms/PoCRealm-Oauth2OpenIdConnect
mp.jwt.verify.audiences=angular-client

# JWT Validierungskonfiguration
mp.jwt.token.header=Authorization
mp.jwt.token.cookie=Bearer
mp.jwt.verify.requireiss=true

# ID-Token und Claims-Konfiguration
mp.jwt.verify.publickey.algorithm=RS256

# Claims für die Authentifizierung
mp.jwt.principal.claim=winaccountname
mp.jwt.groups.claim=realm_access/roles

# Zusätzliche Claims für Mandanten-Information (UPN-Claim)
mp.jwt.mandant.claim=upn

# -------------------------------------------------------------------------
# Zukünftige ADFS-Konfiguration (auskommentiert)
# -------------------------------------------------------------------------
# mp.jwt.verify.publickey.location=https://adfs.example.com/adfs/discovery/keys
# mp.jwt.verify.issuer=https://adfs.example.com/adfs
# mp.jwt.verify.audiences=angular-client
#  
# # ADFS verwendet möglicherweise andere Claim-Namen
# mp.jwt.principal.claim=winaccountname
# mp.jwt.groups.claim=roles
# mp.jwt.mandant.claim=upn
```

#### **2.3 CORS-Konfiguration anpassen**

Die CORS-Filter-Einstellungen müssen für die direkten Ursprünge angepasst werden:

```java
// CORSFilter.java
@Provider
public class CORSFilter implements ContainerResponseFilter {
    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext)
            throws IOException {
        // Spezifische Origin für Nicht-Docker-Umgebung
        responseContext.getHeaders().add("Access-Control-Allow-Origin", "http://localhost:4200");
        
        // Alternativ für mehrere Ursprünge
        // String origin = requestContext.getHeaderString("Origin");
        // if (origin != null && (origin.equals("http://localhost:4200") || origin.equals("http://another-origin"))) {
        //   responseContext.getHeaders().add("Access-Control-Allow-Origin", origin);
        // }
        
        responseContext.getHeaders().add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD");
        responseContext.getHeaders().add("Access-Control-Allow-Headers", "origin, content-type, accept, authorization");
        responseContext.getHeaders().add("Access-Control-Allow-Credentials", "true");
    }
}
```

### **3\. Keycloak-Konfiguration**

Für eine lokale Keycloak-Instanz müssen einige Einstellungen angepasst werden:

#### **3.1 Client-Einstellungen**

Im Keycloak Admin-Panel:

1. Passen Sie die Redirect URIs für den Angular-Client an:

| http://localhost:4200/\* |
| :---- |

2. Stellen Sie sicher, dass die Valid Post Logout URIs konfiguriert sind:

| http://localhost:4200 |
| :---- |

     3\. Passen Sie die Web Origins fuer CORS an:

| http://localhost:4200/\* |
| :---- |

#### 

#### **3.2 Erzeugen einer Realm-Konfigurationsdatei**

Für eine einfache Wiederherstellung der Konfiguration kann ein Realm-Export erstellt werden:

| \# Mit der Keycloak Kommandozeilebin/kc.sh export \--dir /path/to/export \--realm PoCRealm-Oauth2OpenIdConnect \--users realm\_file |
| :---- |

Diese JSON-Datei kann dann für den Import in eine neue Keycloak-Instanz verwendet werden.

### **4\. Sicherheitsempfehlungen für Nicht-Docker-Umgebungen**

#### **4.1 PKCE für Produktionsumgebungen**

In der Angular-Konfiguration für Produktionsumgebungen:
```typescript
// auth.config.prod.ts
export const authConfig: AuthConfig = {  
  // Basis-Konfiguration
  issuer: 'https://keycloak-server/realms/PoCRealm-Oauth2OpenIdConnect', 
  redirectUri: window.location.origin,  
  clientId: 'angular-client',  
  responseType: 'code',  
  scope: 'openid profile email',    
  
  // PKCE für erhöhte Sicherheit
  useSilentRefresh: true,  
  useHttpBasicAuth: false,  
  
  // Auf false setzen, wenn PKCE verwendet wird
  disableAtHashCheck: false,  
  codeChallengeMethod: 'S256',
  
  // Produktionseinstellungen
  requireHttps: true,  
  showDebugInformation: false
}; 
```
#### **4.2 Elytron Credential Store für JBoss/WildFly**

Die Einrichtung erfolgt durch CLI-Befehle:

```bash
# Credential Store erstellen (auf dem Server ausführen)
$JBOSS_HOME/bin/elytron-tool.sh credential-store --create \
  --location=/path/to/credential-store.cs \
  --password StorePassword

# OIDC-Client-Secret im Store speichern
$JBOSS_HOME/bin/elytron-tool.sh credential-store \
  --location=/path/to/credential-store.cs \
  --password StorePassword \
  --add oidc-client-secret \
  --secret AktuellesClientSecret
```

Konfiguration in `standalone.xml`:

```xml
<subsystem xmlns="urn:wildfly:elytron:15.1">
  <!-- Credential Store Konfiguration -->
  <credential-stores>
    <credential-store name="oidcCredentialStore" path="/path/to/credential-store.cs">
      <credential-reference clear-text="StorePassword"/>
    </credential-store>
  </credential-stores>
</subsystem>

<!-- OIDC-Konfiguration mit Credential Store Referenz -->
<subsystem xmlns="urn:wildfly:elytron-oidc-client:1.0">
  <!-- ... -->
  <secure-deployment name="jee-backend-1.0">
    <!-- ... -->
    <credential name="secret" secret="${CREDENTIAL_STORE:oidcCredentialStore:oidc-client-secret}"/>
  </secure-deployment>
</subsystem>
```

### **5\. Zusammenfassung der Änderungen für Nicht-Docker-Umgebungen**

Die Hauptanpassungen für eine Implementierung ohne Docker konzentrieren sich auf:

1. **URL-Anpassungen**: Alle Verweise zwischen den Komponenten müssen explizit auf die tatsächlichen Hostnamen/Ports angepasst werden.  
2. **CORS-Konfiguration**: Die CORS-Einstellungen müssen für die direkten Ursprünge konfiguriert werden.  
3. **Proxy-Konfiguration**: In der Entwicklungsumgebung muss der Angular-Entwicklungsserver als Proxy konfiguriert werden, in der Produktionsumgebung sollte ein dedizierter Webserver (z.B. Apache oder Nginx) genutzt werden.  
4. **Sicherheitseinstellungen**: Besonders in Nicht-Container-Umgebungen ist die sichere Speicherung von Secrets wichtig, daher empfiehlt sich der Elytron Credential Store für JBoss/WildFly.

## **7\. Fazit**

Das vorliegende Proof of Concept hat gezeigt, dass beide untersuchten Sicherheitskonzepte technisch umsetzbar sind und jeweils spezifische Vor- und Nachteile bieten. Die Entscheidung für OAuth2 mit OpenID Connect basiert auf einer ganzheitlichen Betrachtung unter Berücksichtigung aktueller Anforderungen und zukünftiger Entwicklungsmöglichkeiten.

Die bereits umgesetzte Implementierung mit Keycloak und angular-oauth2-oidc demonstriert einen funktionierenden Authentifizierungs- und Autorisierungsfluss mit getrennten API-Zugriffsebenen (öffentlich, authentifiziert, rollenbasiert). Diese Implementierung kann als solide Grundlage für die weitere Entwicklung und den Ausbau des Sicherheitskonzepts dienen.

Die Windows-Authentifizierung mit LDAP und Kerberos stellt eine starke Alternative dar, besonders für Unternehmen mit einer etablierten Windows-Infrastruktur und primär internen Anwendungen. Die Möglichkeit zur nahtlosen Authentifizierung mit den bestehenden Windows-Anmeldedaten ohne zusätzliche Login-Dialoge bietet einen erheblichen Komfortvorteil für die Benutzer und reduziert den Support-Aufwand. Allerdings zeigte sich im Verlauf des PoCs, dass die Implementierung deutlich komplexer ist als ursprünglich angenommen. Insbesondere die Konfiguration der Kerberos-Umgebung, die Erstellung und Verwaltung von Service Principal Names (SPNs) und die notwendigen Anpassungen an den Browsern der Endbenutzer stellten erhebliche Herausforderungen dar, die den Implementierungsaufwand signifikant erhöhten.

Die finale Entscheidung sollte unter Berücksichtigung der spezifischen organisatorischen Rahmenbedingungen, des verfügbaren Know-hows und der langfristigen Strategie getroffen werden. Dabei spielen auch Faktoren wie die bestehende IT-Infrastruktur, geplante Modernisierungen und die strategische Ausrichtung der Anwendungsentwicklung eine wichtige Rolle.

Es empfiehlt sich, das gewählte Konzept zunächst in einer kontrollierten Testumgebung zu implementieren und umfassend zu validieren, bevor es in der Produktivumgebung eingesetzt wird. Dadurch können potenzielle Probleme frühzeitig erkannt und behoben werden, was die Gesamtkosten der Implementierung reduziert und die Akzeptanz bei den Endbenutzern erhöht.

Abschließend lässt sich festhalten, dass die OAuth2/OIDC-Lösung den besten Kompromiss zwischen Implementierungsaufwand, Zukunftssicherheit und Flexibilität bietet. Die erfolgreiche Implementierung im Rahmen des PoCs hat gezeigt, dass dieser Ansatz die gestellten Anforderungen erfüllen kann und gleichzeitig eine solide Basis für zukünftige Erweiterungen und Anpassungen bildet. Die modernen, standardisierten Protokolle gewährleisten zudem eine langfristige Unterstützung und Weiterentwicklung durch die Industrie, was die Investitionssicherheit erhöht.

Für den Produktionsbetrieb empfehlen wir folgende zusätzliche Sicherheitsmaßnahmen:

1. **Implementierung von PKCE**: Nutzen Sie den Proof Key for Code Exchange Flow, um das Client-Secret besser zu schützen und Angriffe auf den Authorization Code abzuwehren.

2. **Verwendung des Elytron Credential Store**: Speichern Sie sensitive Informationen wie Client Secrets in einem verschlüsselten Credential Store anstatt in Klartext in Konfigurationsdateien oder Umgebungsvariablen.

3. **HTTPS für alle Kommunikation**: Sichern Sie alle Kommunikationswege zwischen den Komponenten (Frontend, Backend, Identity Provider) mit TLS/SSL.

4. **Token-Validierung**: Implementieren Sie eine strenge Validierung aller Tokens auf Serverseite, inklusive Signatur-, Aussteller- und Zielgruppenprüfung.

5. **Regelmäßige Rotation von Geheimnissen**: Etablieren Sie einen Prozess zur regelmäßigen Erneuerung aller Geheimnisse wie Client Secrets und Signaturschlüssel.

Die weitere Entwicklung sollte sich auf die Verfeinerung der Rollen- und Berechtigungsmodelle, die Optimierung der Token-Lebensdauer und \-Handhabung sowie auf die Integration weiterer sicherheitsrelevanter Features wie Multi-Faktor-Authentifizierung und erweiterte Auditing-Funktionen konzentrieren. Mit dieser soliden Grundlage ist die Anwendung für die aktuellen und zukünftigen Sicherheitsanforderungen gut gerüstet.

## **8\. Wertvolle Quellen**

**Migrationsleitfaden**

# Migrations-Leitfaden: Keycloak zu ADFS und PKCE-Implementierung

Dieser Leitfaden beschreibt die notwendigen Schritte für:
1. Migration von Keycloak zu ADFS
2. Implementierung des PKCE-Flows für erhöhte Sicherheit

## 1. Unterschiede zwischen Keycloak und ADFS bei der Tokenvalidierung

### 1.1 Token-Struktur

Keycloak und ADFS unterscheiden sich in folgenden Aspekten:

| Aspekt | Keycloak | ADFS |
|--------|----------|------|
| Issuer-URL | `http://keycloak:8080/realms/{realm-name}` | `https://adfs.example.com/adfs` |
| Claim-Namen | Standard OIDC-Claims (sub, email, etc.) | Kann abweichen, oft mit Microsoft-spezifischen Claims |
| Gruppen-Mapping | `realm_access.roles` | Oft `roles` oder `group` |
| JWKS-Endpunkt | `/protocol/openid-connect/certs` | `/discovery/keys` |

### 1.2 Konfigurationsanpassungen für ADFS

1. **Frontend (Angular)**:
   - Issuer-URL anpassen
   - Möglicherweise zusätzliche Parameter für ADFS hinzufügen
   - ADFS hat andere Anforderungen an Redirect-URIs

2. **Backend (JBoss/WildFly)**:
   - Issuer-URL und JWKS-Endpunkt anpassen
   - Claim-Mapping überprüfen und anpassen
   - Beachten Sie, dass ADFS andere Standardwerte für Token-Lebensdauer hat

### 1.3 Claim-Mapping

| Claim | Keycloak | ADFS | Anmerkungen |
|-------|----------|------|-------------|
| Benutzer-ID | `preferred_username` oder benutzerdefiniert | `unique_name` | In unserem Fall `winaccountname` |
| E-Mail | `email` | `email` oder `upn` | |
| Gruppen | `realm_access.roles` | `roles` oder benutzerdefiniert | |
| UPN | Benutzerdefiniert (`upn`) | `upn` | Standard bei ADFS |

## 2. Umstellung auf PKCE-Flow

PKCE (Proof Key for Code Exchange) bietet zusätzliche Sicherheit für den Authorization Code Flow.

### 2.1 Vorteile von PKCE

- Schutz vor Authorization Code Interception-Angriffen
- Besonders wichtig für öffentliche Clients
- Zusätzliche Sicherheit auch für vertrauliche Clients

### 2.2 Anpassungen im Frontend

1. **Auth-Konfiguration anpassen**:
   ```typescript
   export const authConfig: AuthConfig = {
     // Bisherige Konfiguration...
     
     // PKCE-Einstellungen
     useSilentRefresh: true,
     codeChallengeMethod: 'S256'
   };
   ```

2. **Token-Handling ändern**:
   - Bei PKCE wird typischerweise das Access-Token statt des ID-Tokens für 
     API-Anfragen verwendet
   - HTTP-Interceptor entsprechend anpassen

### 2.3 Server-Konfiguration

- Keycloak unterstützt PKCE ohne zusätzliche Konfiguration
- ADFS unterstützt PKCE ab Windows Server 2016 mit bestimmten Updates

## 3. Migrationsstrategie

Für eine reibungslose Migration empfehlen wir:

1. Parallelbetrieb vorbereiten:
   - Implementieren Sie zunächst die ADFS-Konfiguration parallel zur 
     Keycloak-Konfiguration
   - Fügen Sie eine Umschaltmöglichkeit in der Anwendung ein

2. Schrittweise Umstellung:
   - Zuerst auf ADFS umstellen (mit bestehendem Flow)
   - Nach erfolgreicher ADFS-Migration die PKCE-Implementierung aktivieren

3. Validierungsstrategie:
   - Überprüfen Sie die Token-Struktur und Claims nach jedem 
     Migrationsschritt
   - Testen Sie alle Berechtigungsszenarien gründlich
   - Besondere Aufmerksamkeit auf Fehlerbehandlung legen

## 4. ADFS-Konfigurationshinweise

1. Relying Party Trust einrichten:
   - Identifier: angular-client (identisch zur Keycloak-Client-ID)
   - Redirect URL: Identisch zur Anwendungs-URL
   - Zugriffssteuerungsrichtlinie: Alle Benutzer erlauben

2. Claim Rules konfigurieren:
   - Regel für winaccountname einrichten
   - Regel für UPN einrichten
   - Regel für Gruppen/Rollen einrichten

3. OAuth2-Endpoint aktivieren:
   - Client konfigurieren mit gleicher Client-ID
   - Entsprechendes Client-Secret generieren
   - Erlaubte Scopes definieren (openid, profile, email)

	  
# Sicherheitsrelevante Aspekte - Referenzen und Richtlinien

## 1. PKCE (Proof Key for Code Exchange) und OAuth2-Sicherheit

### Offizielle Sicherheitsempfehlungen
* **Bundesamt für Sicherheit in der Informationstechnik (BSI)**: 
  - [IT-Grundschutz-Kompendium - Edition 2023](https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/IT-Grundschutz/IT-Grundschutz-Kompendium/it-grundschutz-kompendium_node.html)
  - [BSI-Orientierungshilfe zu OAuth 2.0 (2022)](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03107/TR-03107-1_Anforderungen.pdf?__blob=publicationFile&v=4)

### Kernempfehlungen für PKCE
- Implementierung eines sicheren Code-Verifikationsverfahrens
- Schutz vor Authorization Code Interception-Angriffen
- Zusätzliche Sicherheitsebene für öffentliche und vertrauliche Clients

## 2. Sichere Speicherung von Credentials

### Rechtliche und technische Grundlagen
* **BSI-Publikationen**:
  - [TR-02102-1: Kryptographische Verfahren](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR02102/BSI-TR-02102.pdf)

* **TeleTrusT – Bundesverband IT-Sicherheit e.V.**:
  - [Handreichung zum Stand der Technik](https://www.teletrust.de/publikationen/broschueren/stand-der-technik/)

### Empfohlene Sicherheitsmaßnahmen
- Verwendung verschlüsselter Credential Stores
- Vermeidung von Klartext-Speicherung
- Regelmäßige Rotation von Zugangsdaten

## 3. TLS/HTTPS-Anforderungen

### Technische Richtlinien
* **BSI TR-02102-2**: [Kryptographische Verfahren: TLS](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR02102/BSI-TR-02102-2.pdf)

### Sicherheitsempfehlungen
- Mindestens TLS 1.2 oder höher
- Verwendung sicherer Cipher-Suites
- Zertifikatsvalidierung
- HSTS (HTTP Strict Transport Security)

## 4. Content Security Policy und Web-Sicherheit

### Aktuelle Studien und Empfehlungen
* **BSI-Studie "Die Lage der IT-Sicherheit in Deutschland 2024"**:
  [BSI Lagebericht](https://www.bsi.bund.de/DE/Service-Navi/Publikationen/Lagebericht/lagebericht_node.html)

### Implementierungshinweise
- Strikte CSP-Konfiguration
- Vermeidung von Inline-Scripts
- Whitelisting von Ressourcen-Quellen

## 5. Übergreifende Sicherheitsstandards

### Grundlegende Methodik
* **BSI-Standard 200-2: IT-Grundschutz-Methodik**:
  [BSI-Standards](https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/IT-Grundschutz/BSI-Standards/bsi-standards_node.html)

### Single Sign-On (SSO) Sicherheit
* **BSI SSO-Baustein**:
  [SSO-Sicherheitsempfehlungen](https://www.bsi.bund.de/DE/Themen/Verbraucherinnen-und-Verbraucher/Informationen-und-Empfehlungen/Cyber-Sicherheitsempfehlungen/Accountschutz/Single-Sign-On/single-sign-on_node.html)

## Zusammenfassende Handlungsempfehlungen

1. **Implementierung von PKCE**
2. **Sichere Credential-Speicherung**
3. **Durchgängige TLS-Verschlüsselung**
4. **Strikte Content Security Policy**
5. **Regelmäßige Sicherheitsüberprüfungen**

**Hinweis**: Die Referenzen und Empfehlungen basieren auf aktuellen Veröffentlichungen deutscher Sicherheitsbehörden und sollten kontinuierlich aktualisiert werden.


