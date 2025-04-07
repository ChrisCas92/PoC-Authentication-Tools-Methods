# OAuth2 + OpenID Connect PoC mit Keycloak und JBoss/WildFly

Dieses Proof of Concept demonstriert die Integration von OAuth2 und OpenID Connect (OIDC) für die Authentifizierung in einer Angular-Frontend + JBoss/WildFly-Backend Architektur mit Keycloak als Identity Provider.

## Besonderheiten dieses PoC

- Verwendung von ID-Token (statt Access-Token) für Backend-Authentifizierung
- Extraktion der Windows-Benutzerkennung über den `winaccountname`-Claim
- Extraktion der Mandanteninformation aus dem UPN-Claim (z.B. `user@rhl.drv` → Mandant "13")
- Vorbereitung für AD-FS ohne proprietäre AD-FS-Funktionen
- JBoss/WildFly-Backend mit Elytron OIDC-Integration

## Voraussetzungen

- Docker und Docker Compose
- Node.js und NPM (für lokale Entwicklung)
- Java 17 und Maven (für lokale Backend-Entwicklung)
- JBoss/WildFly 26+ (lokale Installation optional)

## Schnellstart

### Entwicklungsumgebung starten

```bash
# Mit Hot-Reload für das Frontend
docker-compose --profile dev up

# Oder nur die Produktionsversion
docker-compose up
```

### Frontend und Backend separat bauen

```bash
# Frontend bauen
npm install
npm run build

# Backend bauen
cd jeebackend
mvn clean package

# Optional: Direktes Deployment auf einen lokalen WildFly-Server
mvn wildfly:deploy
```

## Komponenten

### Frontend (Angular)

- OAuth2/OIDC-Integration mit `angular-oauth2-oidc`
- Extraktion und Verwendung von Custom Claims aus dem ID-Token
- Mandanten-Extraktion aus dem UPN

### Backend (JBoss/WildFly mit Elytron OIDC)

- WildFly Elytron OIDC für Token-Validierung
- Extraktion von Claims aus dem ID-Token
- Mandanten-Extraktion aus dem UPN-Claim
- Beispiel-Endpoints mit verschiedenen Berechtigungsstufen

## JBoss/WildFly OIDC-Konfiguration

Die OIDC-Integration in JBoss/WildFly erfolgt über das Elytron-Subsystem:

### 1. Konfiguration in standalone.xml

```xml
<subsystem xmlns="urn:wildfly:elytron:15.0">
    <!-- ... -->
    <http>
        <!-- OIDC/OAuth2 Identity Provider Konfiguration -->
        <oidc-client name="keycloak-client"
                  provider-url="http://keycloak:8080/realms/PoCRealm%20Oauth2OpenIdConnect"
                  client-id="angular-client"
                  client-secret="${env.OIDC_CLIENT_SECRET:your-client-secret}"
                  principal-claim="winaccountname"
                  token-type="id_token">
            <!-- ... -->
        </oidc-client>
        <!-- ... -->
    </http>
    <!-- ... -->
</subsystem>
```

### 2. Anwendungssicherheit konfigurieren

```xml
<subsystem xmlns="urn:jboss:domain:undertow:12.0">
    <!-- ... -->
    <application-security-domains>
        <application-security-domain name="jee-backend" http-authentication-factory="oidc-http-authentication"/>
    </application-security-domains>
    <!-- ... -->
</subsystem>
```

### 3. Web.xml für die Anwendung

```xml
<web-app>
    <!-- ... -->
    <security-constraint>
        <web-resource-collection>
            <web-resource-name>Secured API</web-resource-name>
            <url-pattern>/api/secured/*</url-pattern>
            <url-pattern>/api/admin/*</url-pattern>
        </web-resource-collection>
        <auth-constraint>
            <role-name>user</role-name>
            <role-name>admin</role-name>
        </auth-constraint>
    </security-constraint>
    <!-- ... -->
</web-app>
```

## Keycloak-Konfiguration

Die detaillierte Anleitung zur Keycloak-Konfiguration finden Sie in der [Keycloak-Konfigurationsanleitung](docs/keycloak-config-guide.md).

Hier die wichtigsten Schritte:

1. Öffnen Sie die Keycloak-Admin-Konsole: http://localhost:8080/admin/ (admin/admin)
2. Erstellen Sie einen Realm: "PoCRealm Oauth2OpenIdConnect"
3. Erstellen Sie einen Client: "angular-client"
4. Konfigurieren Sie folgende Mapper für den Client:
   - winaccountname (User Attribute → winaccountname)
   - upn (User Property → username oder email)
5. Erstellen Sie Testbenutzer mit passenden Attributen

## Projektstruktur

```
/
├── src/                           # Angular-Frontend
│   ├── app/                       # Angular-Komponenten
│   ├── auth/                      # Auth-Service und Konfiguration
│   │   ├── auth.config.ts         # OAuth-Konfiguration
│   │   ├── auth.service.ts        # Auth-Service für Claims
│   │   └── auth.interceptor.ts    # HTTP-Interceptor für Token
│   └── ...
├── jeebackend/                    # JBoss/WildFly-Backend
│   ├── src/                       # Backend-Quellcode
│   │   ├── main/java/com/example/ # Java-Klassen
│   │   │   ├── MandantExtractor.java  # UPN/Mandanten-Verarbeitung
│   │   │   └── SecuredResource.java   # REST-Endpunkte
│   │   └── main/webapp/           # Web-Ressourcen
│   │       └── WEB-INF/           # Webdeskriptoren
│   │           └── web.xml        # Security-Konfiguration
│   └── pom.xml                    # Maven-Konfiguration
├── docker-compose.yml             # Docker-Compose für Produktion
├── Dockerfile.frontend            # Frontend-Dockerfile
├── jeebackend/Dockerfile.backend  # Backend-Dockerfile
└── ...
```

## AD-FS Integration

Dieses PoC ist so konzipiert, dass es später mit AD-FS (Active Directory Federation Services) als Identity Provider verwendet werden kann. Dafür müssen folgende Anpassungen vorgenommen werden:

### 1. Angular-Konfiguration anpassen

```typescript
// src/auth/auth.config.ts
export const authConfig: AuthConfig = {
  issuer: "https://adfs.example.com/adfs",
  redirectUri: window.location.origin,
  clientId: "angular-client",
  // Weitere Konfiguration...
};
```

### 2. JBoss/WildFly-Konfiguration anpassen

```xml
<oidc-client name="adfs-client"
           provider-url="https://adfs.example.com/adfs"
           client-id="angular-client"
           client-secret="${env.OIDC_CLIENT_SECRET}"
           principal-claim="winaccountname"
           token-type="id_token">
    <!-- ... -->
</oidc-client>
```

### 3. AD-FS Konfiguration

- Erstellen Sie eine Relying Party Trust für die Anwendung
- Konfigurieren Sie die erforderlichen Claims (winaccountname, upn)
- Stellen Sie sicher, dass der UPN das Format username@domain.drv hat
- Konfigurieren Sie die OAuth2/OIDC-Endpunkte

## Fehlerbehebung: Häufige Probleme

### Frontend-Aktualisierungen werden nicht übernommen

Siehe [Frontend-Aktualisierung in Docker-Umgebungen](docs/frontend-aktualisierung.md) für detaillierte Anleitungen.

Kurze Lösung:

```bash
# Stoppe Container
docker-compose down

# Bereinige Cache
docker system prune -a

# Baue Images neu
docker-compose build --no-cache

# Starte Container neu
docker-compose up -d
```

### JBoss/WildFly OIDC-Probleme

1. **Logs prüfen**:

   ```bash
   docker logs jboss-backend
   ```

2. **Token-Validierungsprobleme**:

   - Stellen Sie sicher, dass der JWKS-Endpunkt erreichbar ist
   - Überprüfen Sie die Claims im Token
   - Prüfen Sie die Issuer-URL

3. **Rollen-Mapping-Probleme**:
   - Überprüfen Sie die Rollenzuweisungen in Keycloak
   - Prüfen Sie die realm_access/roles-Struktur im Token

## Unterstützte Mandanten

Folgende Domänen werden im aktuellen Mapping unterstützt:

| Domain     | Mandanten-ID |
| ---------- | ------------ |
| rhl.drv    | 13           |
| bsh.drv    | 14           |
| now-it.drv | 15           |

Zum Hinzufügen weiterer Mandanten bearbeiten Sie die `DOMAIN_TO_MANDANT`-Map in `MandantExtractor.java`.

## Autoren

- [Ihr Team/Name]

## Lizenz

[Ihre Lizenzinformationen]

## To-Do

- [ ] Vollständige Dokumentation der Keycloak-Konfiguration
- [ ] Vollständige Dokumentation der JBoss/WildFly-Konfiguration
- [ ] Vollständige Dokumentation der Frontend-Integration
- Implentierung das man nicht direkt eingeloggt ist ( es ist immer eine neue Anmeldung nötig ), zumindest wenn der Container neu gestartet wird.
- Test Secured Endpoint muss noch gefixxt werden
- Test Admin Endpoint muss noch gefixxt werden
