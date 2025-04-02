# Keycloak-Konfiguration für winaccountname und upn Claims

Diese Anleitung beschreibt, wie Sie Keycloak für die Bereitstellung der benötigten Claims (`winaccountname` und `upn`) konfigurieren, um das System mit AD-FS-kompatiblen Standards zu verwenden.

## 1. Realm erstellen

1. Navigieren Sie zur Keycloak Admin-Konsole (http://localhost:8080/admin)
2. Melden Sie sich mit den Admin-Credentials an (Standard: admin/admin)
3. Erstellen Sie einen neuen Realm namens "PoCRealm Oauth2OpenIdConnect" (oder verwenden Sie Ihren bestehenden)

## 2. Client-Konfiguration

1. Navigieren Sie zu "Clients" und wählen Sie Ihren "angular-client"
2. Stellen Sie sicher, dass folgende Einstellungen konfiguriert sind:
   - Access Type: `confidential`
   - Standard Flow aktiviert: `ON`
   - Valid Redirect URIs: `http://localhost:4200/*` (für Entwicklung)
   - Web Origins: `*` (für Entwicklung, in Produktion einschränken)

## 3. Claim-Mapper für winaccountname

1. Navigieren Sie zum Tab "Mappers" im Client "angular-client"
2. Klicken Sie auf "Create"
3. Konfigurieren Sie den Mapper wie folgt:
   - Name: `winaccountname`
   - Mapper Type: `User Attribute`
   - User Attribute: `winaccountname`
   - Token Claim Name: `winaccountname`
   - Claim JSON Type: `String`
   - Add to ID token: `ON`
   - Add to access token: `ON`
   - Add to userinfo: `ON`
   - Multivalued: `OFF`
   - Aggregate attribute values: `OFF`

## 4. UPN-Claim-Konfiguration

1. Erstellen Sie einen weiteren Mapper:
   - Name: `upn`
   - Mapper Type: `User Property`
   - Property: `username` (oder `email`, je nach Verfügbarkeit)
   - Token Claim Name: `upn`
   - Claim JSON Type: `String`
   - Add to ID token: `ON`
   - Add to access token: `ON`
   - Add to userinfo: `ON`

## 5. Domain-suffix für UPN

Um sicherzustellen, dass der UPN das Format `username@domain.drv` hat:

1. Sie können entweder:
   - Benutzer mit E-Mail-Adressen im Domain-Format erstellen
   - Oder einen Script-Mapper hinzufügen, der die Domain anhängt:
     - Name: `domain-suffix-mapper`
     - Mapper Type: `Script Mapper`
     - Script: 
       ```javascript
       user.username = user.username + '@rhl.drv';
       ```
     - Add to ID token: `ON`
     - Add to access token: `ON`
     - Target Claim Name: `upn`

## 6. Testbenutzer erstellen

1. Navigieren Sie zu "Users" und klicken Sie auf "Add User"
2. Erstellen Sie einen Benutzer mit:
   - Username: `rh000042` (oder ein anderer passender Name)
   - Email: `rh000042@rhl.drv` (damit der UPN-Claim korrekt ist)
3. Unter "Attributes" fügen Sie hinzu:
   - Key: `winaccountname`
   - Value: `rh000042`
4. Setzen Sie ein Passwort im "Credentials"-Tab
5. Weisen Sie dem Benutzer Rollen zu (optional)

## 7. Überprüfung der Claims

Um zu überprüfen, ob die Claims korrekt konfiguriert sind:

1. Melden Sie sich mit dem Testbenutzer in Ihrer Anwendung an
2. Prüfen Sie die Browser-Konsole für die Ausgabe der Claims
3. Verwenden Sie ein JWT-Debugging-Tool wie [jwt.io](https://jwt.io/), um den Inhalt des ID-Tokens zu inspizieren

## 8. Vorbereitung für AD-FS-Migration

Wenn Sie später zu AD-FS wechseln möchten, beachten Sie:

1. Stellen Sie sicher, dass die Claim-Namen (`winaccountname` und `upn`) konsistent sind
2. Passen Sie die authConfig.ts an, um auf den AD-FS-Endpunkt zu verweisen
3. Konfigurieren Sie AD-FS so, dass es die gleichen Claims im gleichen Format bereitstellt

## Fehlersuche

Wenn die Claims nicht wie erwartet erscheinen:

1. Überprüfen Sie die Mapper-Konfiguration im Client
2. Stellen Sie sicher, dass die Benutzerattribute korrekt gesetzt sind
3. Überprüfen Sie, ob die Benutzer-E-Mail dem erwarteten UPN-Format entspricht
4. Prüfen Sie in der Keycloak-Konfiguration, ob die Claims für ID-Token aktiviert sind
