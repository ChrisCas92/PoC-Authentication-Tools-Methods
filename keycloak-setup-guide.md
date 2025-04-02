# Keycloak-Einrichtung für OAuth2/OpenID Connect PoC

Diese Anleitung führt Sie durch die vollständige Konfiguration von Keycloak für Ihr OAuth2/OpenID Connect PoC mit besonderem Fokus auf der Bereitstellung der `winaccountname` und `upn` Claims im ID-Token.

## 1. Keycloak starten

Keycloak sollte bereits über Docker-Compose gestartet werden können. Wenn nicht, führen Sie folgenden Befehl aus:

```bash
docker-compose up -d keycloak
```

Warten Sie, bis Keycloak vollständig hochgefahren ist (normalerweise 30-60 Sekunden).

## 2. Auf die Admin-Konsole zugreifen

1. Öffnen Sie die Keycloak Admin-Konsole im Browser: http://localhost:8080/admin/
2. Melden Sie sich mit den in der docker-compose.yml festgelegten Admin-Zugangsdaten an:
   - Username: `admin`
   - Password: `admin`

## 3. Realm erstellen

1. Klicken Sie im Dropdown-Menü links oben auf "Create Realm"
2. Geben Sie folgende Informationen ein:
   - Realm name: `PoCRealm Oauth2OpenIdConnect`
   - Stellen Sie sicher, dass "Enabled" aktiviert ist
3. Klicken Sie auf "Create"

## 4. Client für die Angular-Anwendung erstellen

1. Navigieren Sie im linken Menü zu "Clients"
2. Klicken Sie auf "Create client"
3. Geben Sie im General Settings Tab folgende Informationen ein:
   - Client type: `OpenID Connect`
   - Client ID: `angular-client`
   - Name: `Angular Frontend`
4. Klicken Sie auf "Next"
5. Im "Capability config"-Tab:
   - Client authentication: `ON` (Um einen confidential client zu erstellen)
   - Authentication flow:
     - Standard flow: `ON` (für Authorization Code Flow)
     - Direct access grants: `ON`
     - Implicit flow: `OFF`
     - Service accounts roles: `OFF`
   - Klicken Sie auf "Next"
6. Im "Login settings"-Tab:
   - Valid redirect URIs: `http://localhost:4200/*` (für lokale Entwicklung)
   - Web origins: `*` (oder `http://localhost:4200` für mehr Sicherheit)
   - Klicken Sie auf "Save"

## 5. Client-Secret notieren

1. Navigieren Sie zum Tab "Credentials" des erstellten Clients
2. Notieren Sie sich das Client Secret (Sie benötigen es später für Ihre Anwendungskonfiguration)
3. aktuell RDPuvVZwEW0grzhx36F4pDrxMx5yDc32

## 6. Client-Scopes konfigurieren

1. Klicken Sie im linken Menü auf "Client scopes"
2. Prüfen Sie, ob ein Scope "openid" existiert. Falls nicht:

   - Klicken Sie auf "Create client scope"
   - Name: `openid`
   - Description: `OpenID Connect scope`
   - Type: `Default`
   - Protocol: `openid-connect`
   - Klicken Sie auf "Save"

3. Navigieren Sie zu "Clients" → "angular-client" → "Client scopes"
4. Prüfen Sie im Tab "Assigned default client scopes", ob der Scope "openid" zugewiesen ist
   Falls nicht, klicken Sie auf "Add client scope" und wählen Sie "openid" aus der Liste und setzen Sie ihn als "Default"

5. Navigieren Sie zum Tab "Mappers"
6. Stellen Sie sicher, dass die Standard-Claims (wie `sub`, `email`, usw.) vorhanden sind

- Die `Standard-Claims`, die in einem OpenID Connect ID-Token typischerweise enthalten sind, umfassen:

  - `iss` (Issuer): Der Aussteller des Tokens, in diesem Fall die URL des Keycloak-Servers.
  - `sub` (Subject): Ein eindeutiger Identifier für den Benutzer.
  - `aud` (Audience): Für wen der Token bestimmt ist (normalerweise die Client-ID).
  - `exp` (Expiration Time): Wann der Token abläuft.
  - `iat` (Issued At): Wann der Token ausgestellt wurde.
  - `auth_time`: Wann die Authentifizierung stattfand.
  - `name`: Der vollständige Name des Benutzers.
  - `given_name`: Der Vorname des Benutzers.
  - `family_name`: Der Nachname des Benutzers.
  - `preferred_username`: Der bevorzugte Benutzername.
  - `email`: Die E-Mail-Adresse des Benutzers.
  - `email_verified`: Ob die E-Mail-Adresse verifiziert wurde.

- In Keycloak werden diese `Standard-Claims` normalerweise automatisch dem "openid" Client Scope hinzugefügt. Wenn Sie im Tab "Mappers" des "openid" Client Scopes nachsehen, sollten Sie Mapper für diese Claims sehen.

- Für Ihr PoC sind die wichtigsten dieser `Standard-Claims` wahrscheinlich:

  - `sub`: Als Basis-Identifikator
  - `preferred_username`: Kann als Fallback-Option verwendet werden, falls andere Claims fehlen
  - `email`: Kann auch als Basis für den UPN verwendet werden

Diese Standard-Claims werden ergänzt durch Ihre benutzerdefinierten Claims winaccountname und upn, die Sie speziell für Ihre Anwendung hinzufügen.

## 7. Benutzer-Attribut für winaccountname einrichten

Wir erstellen ein benutzerdefiniertes Attribut für die Windows-Benutzerkennung:

1. Navigieren Sie zu "Realm settings" → "User profile"
2. Klicken Sie auf "Attributes" → "Add attribute"
3. Füllen Sie das Formular aus:
   - Name: `winaccountname`
   - Display name: `Windows Account Name`
   - Enabled: `ON`
   - Required: `OFF`
   - Group: `user-metadata` = `default`
   - Validator: `username-prohibited-characters`
   - Error message key: `Die Windows-Benutzerkennung darf nur alphanumerische Zeichen, Bindestriche und Unterstriche enthalten.`
4. Klicken Sie auf "Add"

## 8. Claims-Mapper für winaccountname und upn erstellen

Wir müssen Mapper erstellen, um die benötigten Claims in das ID-Token aufzunehmen:

### 8.1 winaccountname-Mapper

1. Navigieren Sie zu "Clients" → "angular-client"
2. Wählen Sie den Tab "Client scopes"
3. Klicken Sie auf den "angular-client-dedicated" Scope
4. Gehen Sie zum Tab "Mappers"
5. Klicken Sie auf "Configure a new mapper" → "User Attribute"
6. Füllen Sie das Formular aus:
   - Name: `winaccountname`
   - User Attribute: `winaccountname`
   - Token Claim Name: `winaccountname`
   - Claim JSON Type: `String`
   - Add to ID token: `ON`
   - Add to access token: `ON`
   - Add to userinfo: `ON`
   - Multivalued: `OFF`
   - Aggregate attribute values: `OFF`
7. Klicken Sie auf "Save"

### 8.2 UPN-Mapper (aus username)

1. Navigieren Sie zu "Clients" → "angular-client"
2. Wählen Sie den Tab "Client scopes"
3. Klicken Sie auf den "angular-client-dedicated" Scope
4. Gehen Sie zum Tab "Mappers"
5. Klicken Sie auf "Configure a new mapper" → "User Property"
6. Füllen Sie das Formular aus:
   - Name: `upn-mapper`
   - User Property: `username`
   - Token Claim Name: `upn`
   - Claim JSON Type: `String`
   - Add to ID token: `ON`
   - Add to access token: `ON`
   - Add to userinfo: `ON`
7. Klicken Sie auf "Save"

## 9. Domain-Suffix für UPN (Optional)

Um sicherzustellen, dass der UPN das Format username@domain.drv hat:

Erstellen Sie ein zusätzliches Benutzerattribut für den vollständigen UPN:

- Navigieren Sie zu "Realm settings" → "User profile"
- Klicken Sie auf "Attributes" → "Add attribute"
  - Name: `fullUpn`
  - Display name: `Full UPN`
  - Enabled: `ON`
  - Required: `OFF`
  - Group: `user-metadata`

Wählen Sie "User Attribute" aus der Liste der Mapper
Konfigurieren Sie den Mapper wie folgt:

- Name: `upn-with-domain`
- User Attribute: `fullUpn`
- Token Claim Name: `upn`
- Claim JSON Type: `String`
- Add to ID token: `ON`
- Add to access token: `ON`
- Add to userinfo: `ON`

## 10. Testbenutzer erstellen

Erstellen Sie mindestens einen Testbenutzer zum Testen der Anwendung:

1. Navigieren Sie im linken Menü zu "Users"
2. Klicken Sie auf "Add user"
3. Geben Sie folgende Informationen ein:
   - Username: `rh000042` (oder ein anderer passender Name)
   - Email: `rh000042@rhl.drv` (falls Sie den UPN-Domain-Suffix-Mapper nicht verwenden)
   - Email verified: `ON`
   - First name: `Test`
   - Last name: `User`
   - Enabled: `ON`
4. Klicken Sie auf "Create"
5. Nachdem der Benutzer erstellt wurde, navigieren Sie zum Tab "Attributes"
6. Fügen Sie die Attribute hinzu:

   - Key: `winaccountname`
   - Value: `rh000042`
   - Klicken Sie auf "Add"
   - Key: `fullUpn`
   - Value: `rh000042@rhl.drv`
   - Klicken Sie auf "Add"

7. Klicken Sie auf "Save", um die Attribute zu speichern
8. Navigieren Sie zum Tab "Credentials"
9. Klicken Sie auf "Set password"
10. Geben Sie ein Passwort ein und bestätigen Sie es
11. Temporary: `OFF` (damit der Benutzer das Passwort nicht ändern muss)
12. Klicken Sie auf "Save"

Wiederholen Sie diesen Prozess für jeden zusätzlichen Testbenutzer, den Sie erstellen möchten, und ändern Sie jeweils die Domain im UPN, um verschiedene Mandanten zu testen:

- Für `Mandant 13`: `rh000042@rhl.drv`
- Für `Mandant 14`: `bh000123@bsh.drv`
- Für `Mandant 15:` `now000987@now-it.drv`

## 11. Rollen zuweisen (Optional)

1. Navigieren Sie zu "Realm roles"
2. Klicken Sie auf "Create role"
3. Erstellen Sie die Rollen "user" und "admin"
4. Navigieren Sie zurück zu "Users" → Ihrem Testbenutzer
5. Gehen Sie zum Tab "Role mapping"
6. Klicken Sie auf "Assign role"
7. Weisen Sie die Rollen "user" und "admin" zu

## 12. Konfiguration der ID-Token-Einstellungen

Um sicherzustellen, dass das ID-Token die gewünschten Claims enthält:

1. Navigieren Sie zu "Realm Settings" → "Tokens"
2. Stellen Sie den Access Token Lifespan auf einen angemessenen Wert ein (z.B. 5 Minuten)
3. ID Token Signature Algorithm: `RS256`

## 13. Anwendungskonfiguration anpassen

Stellen Sie sicher, dass Ihre Angular-Anwendung und JBoss/WildFly korrekt konfiguriert sind:

1. In Ihrer Angular-Anwendung (auth.config.ts):

   ```typescript
   export const authConfig: AuthConfig = {
     issuer: "http://localhost:8080/realms/PoCRealm%20Oauth2OpenIdConnect",
     redirectUri: window.location.origin,
     clientId: "angular-client",
     // ...
   };
   ```

2. In Ihrer JBoss/WildFly-Konfiguration (standalone.xml):
   ```xml
   <oidc-client name="keycloak-client"
              provider-url="http://keycloak:8080/realms/PoCRealm%20Oauth2OpenIdConnect"
              client-id="angular-client"
              client-secret="YOUR_CLIENT_SECRET"
              principal-claim="winaccountname"
              token-type="id_token">
   ```

## 14. Weitere Testbenutzer mit unterschiedlichen Domains

Um verschiedene Mandanten zu testen, erstellen Sie weitere Benutzer:

1. Erstellen Sie einen zweiten Benutzer:

   - Username: `bh000123`
   - Email: `bh000123@bsh.drv`
   - winaccountname: `bh000123`

2. Erstellen Sie einen dritten Benutzer:
   - Username: `now000987`
   - Email: `now000987@now-it.drv`
   - winaccountname: `now000987`

## 15. Troubleshooting

### Token-Inhalte überprüfen

Bei Problemen können Sie den Token-Inhalt mit Online-Tools wie [jwt.io](https://jwt.io/) prüfen:

1. Extrahieren Sie das ID-Token aus der Anwendung (z.B. über Browser-Netzwerkinspektor)
2. Fügen Sie es in jwt.io ein
3. Überprüfen Sie, ob die Claims vorhanden sind

### Fehlende Claims

Wenn Claims fehlen:

1. Überprüfen Sie die Mapper-Konfiguration
2. Stellen Sie sicher, dass "Add to ID token" aktiviert ist
3. Prüfen Sie, ob der Scope "openid" in der Anfrage enthalten ist
4. Prüfen Sie, ob die Benutzerattribute korrekt gesetzt sind

### CORS-Probleme

Bei CORS-Problemen:

1. Überprüfen Sie die Web Origins-Einstellung im Client
2. Stellen Sie sicher, dass Ihre Anwendung die korrekten Ports verwendet

## standalone.xml

```<?xml version="1.0" ?>
<!-- Dieses ist ein Ausschnitt aus der standalone.xml Konfigurationsdatei -->
<!-- Bitte integrieren Sie dies in Ihre vorhandene Konfigurationsdatei -->

<server xmlns="urn:jboss:domain:17.0">
  <subsystem xmlns="urn:wildfly:elytron:1.0">
    <http>
      <http-authentication-factory name="oidc-http-authentication" http-server-mechanism-factory="global" security-domain="ApplicationDomain">
        <mechanism-configuration>
          <mechanism mechanism-name="BEARER_TOKEN" credential-security-factory="oidc-security-factory"/>
        </mechanism-configuration>
      </http-authentication-factory>

      <oidc-client name="keycloak-client" provider-url="http://keycloak:8080/realms/PoCRealm%20Oauth2OpenIdConnect" client-id="angular-client" client-secret="${env.OIDC_CLIENT_SECRET:your-client-secret}" principal-claim="winaccountname" token-type="id_token">
        <provider-metadata>
          <issuer>http://keycloak:8080/realms/PoCRealm%20Oauth2OpenIdConnect</issuer>
          <jwks-uri>http://keycloak:8080/realms/PoCRealm%20Oauth2OpenIdConnect/protocol/openid-connect/certs</jwks-uri>
        </provider-metadata>
      </oidc-client>

      <security-domain name="oidc-security-domain" default-realm="oidc-realm">
        <realm name="oidc-realm" principal-transformer="oidc-principal-transformer">
          <token-realm name="oidc-token-realm" principal-claim="winaccountname" jwt-security-realm="oidc-jwt-realm"/>
        </realm>
      </security-domain>

      <principal-transformer name="oidc-principal-transformer" />

      <jwt-security-realm name="oidc-jwt-realm">
        <oidc-realm truststore="application-truststore" client="keycloak-client"/>
      </jwt-security-realm>

      <credential-security-factory name="oidc-security-factory" />
    </http>
  </subsystem>

</server>
```
