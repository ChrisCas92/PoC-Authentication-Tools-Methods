# WildFly/JBoss EAP OIDC-Client-Secret Konfigurationsanleitung

Diese Anleitung beschreibt die Konfiguration des OIDC-Client-Secrets für zwei JBoss EAP Versionen:
1. Für die **aktuelle PoC-Version** (WildFly/JBoss EAP früherer Version)
2. Für **JBoss EAP 8.0.5.1 mit OIDC-Client 2.0** (zukünftige Version)

Für jede Version werden beide Ansätze erklärt:
- Die sichere Methode mit dem Elytron Credential Store
- Die einfachere Methode über eine Properties-Datei

## Teil 1: Konfiguration für aktuelle PoC-Version

### Methode 1A: Elytron Credential Store (sicher)

#### Voraussetzungen
- WildFly/JBoss EAP
- Administrativer Zugriff auf den Server
- JDK 8 oder höher

#### Schritt 1: Credential Store erstellen

```bash
# Wechseln Sie in das bin-Verzeichnis von JBoss
cd $JBOSS_HOME/bin

# Erstellen des Credential Store
./elytron-tool.sh credential-store --create \
  --location=/pfad/zu/credential-store.cs \
  --password MeinCredentialStorePasswort
```

#### Schritt 2: OIDC-Client-Secret im Credential Store speichern

```bash
./elytron-tool.sh credential-store \
  --location=/pfad/zu/credential-store.cs \
  --password MeinCredentialStorePasswort \
  --add oidc-client-secret \
  --secret MeinOIDCClientSecret
```

#### Schritt 3: Credential Store in JBoss konfigurieren

Starten Sie die JBoss CLI:

```bash
./jboss-cli.sh --connect
```

Führen Sie folgende Befehle aus:

```
# Credential Store konfigurieren
/subsystem=elytron/credential-store=credentialStore:add(location="/pfad/zu/credential-store.cs", credential-reference={clear-text="MeinCredentialStorePasswort"})

# Server neu laden, um die Änderungen zu aktivieren
reload
```

#### Schritt 4: OIDC-Konfiguration anpassen

Bearbeiten Sie die JBoss-Konfigurationsdatei (standalone.xml oder domain.xml) und ändern Sie den Eintrag für das OIDC-Client-Secret:

```xml
<subsystem xmlns="urn:wildfly:elytron-oidc-client:1.0">
    <provider name="keycloak">
        <provider-url>http://keycloak:8080/realms/PoCRealm%20Oauth2OpenIdConnect</provider-url>
        <ssl-required>external</ssl-required>
    </provider>
    <secure-deployment name="jee-backend-1.0">
        <provider>keycloak</provider>
        <client-id>angular-client</client-id>
        <credential name="secret" secret="${CREDENTIAL_STORE:credentialStore:oidc-client-secret}"/>
    </secure-deployment>
</subsystem>
```

### Methode 1B: Properties-Datei (einfacher für PoC)

#### Schritt 1: Properties-Datei erstellen

Erstellen Sie eine Datei `oidc-config.properties` im Verzeichnis `$JBOSS_HOME/standalone/configuration/`:

```properties
# OIDC-Konfiguration
oidc.client.secret=MeinOIDCClientSecret
```

#### Schritt 2: JBoss für die Properties-Datei konfigurieren

Starten Sie die JBoss CLI:

```bash
./jboss-cli.sh --connect
```

Führen Sie folgende Befehle aus:

```
# System-Property für das Client-Secret hinzufügen
/system-property=oidc.client.secret:add(value="MeinOIDCClientSecret")

# Server neu laden
reload
```

#### Schritt 3: OIDC-Konfiguration anpassen

Bearbeiten Sie die JBoss-Konfigurationsdatei und ändern Sie den Eintrag für das OIDC-Client-Secret:

```xml
<subsystem xmlns="urn:wildfly:elytron-oidc-client:1.0">
    <provider name="keycloak">
        <provider-url>http://keycloak:8080/realms/PoCRealm%20Oauth2OpenIdConnect</provider-url>
        <ssl-required>external</ssl-required>
    </provider>
    <secure-deployment name="jee-backend-1.0">
        <provider>keycloak</provider>
        <client-id>angular-client</client-id>
        <credential name="secret" secret="${oidc.client.secret}"/>
    </secure-deployment>
</subsystem>
```

Alternativ können Sie das System-Property auch direkt in der standalone.xml definieren:

```xml
<system-properties>
    <property name="oidc.client.secret" value="MeinOIDCClientSecret"/>
</system-properties>
```

## Teil 2: Konfiguration für JBoss EAP 8.0.5.1 mit OIDC-Client 2.0

### Methode 2A: Elytron Credential Store (sicher für Produktionsumgebungen)

#### Voraussetzungen
- JBoss EAP 8.0.5.1
- OIDC-Client 2.0
- Administrativer Zugriff auf den Server
- JDK 11 oder höher (empfohlen für EAP 8.x)

#### Schritt 1: Credential Store erstellen

```bash
# Wechseln Sie in das bin-Verzeichnis von JBoss
cd $JBOSS_HOME/bin

# Erstellen des Credential Store mit dem für EAP 8.x geeigneten Typ
./elytron-tool.sh credential-store --create \
  --location=/pfad/zu/credential-store.cs \
  --password MeinCredentialStorePasswort \
  --type KeyStoreCredentialStore \
  --key-store-type PKCS12
```

#### Schritt 2: OIDC-Client-Secret im Credential Store speichern

```bash
./elytron-tool.sh credential-store \
  --location=/pfad/zu/credential-store.cs \
  --password MeinCredentialStorePasswort \
  --type KeyStoreCredentialStore \
  --key-store-type PKCS12 \
  --add oidc-client-secret \
  --secret MeinOIDCClientSecret
```

#### Schritt 3: Credential Store in EAP 8.x konfigurieren

Starten Sie die JBoss CLI:

```bash
./jboss-cli.sh --connect
```

Führen Sie folgende Befehle aus:

```
# Credential Store konfigurieren
/subsystem=elytron/credential-store=credentialStore:add(location="/pfad/zu/credential-store.cs", credential-reference={clear-text="MeinCredentialStorePasswort"}, create=false, key-store-type=PKCS12)

# Server neu laden, um die Änderungen zu aktivieren
reload
```

#### Schritt 4: OIDC-Konfiguration anpassen (für OIDC-Client 2.0)

Bearbeiten Sie die EAP-Konfigurationsdatei (standalone.xml oder domain.xml). Beachten Sie, dass der Namespace bei OIDC-Client 2.0 aktualisiert wurde:

```xml
<subsystem xmlns="urn:wildfly:elytron-oidc-client:2.0">
    <secure-deployment name="jee-backend-1.0">
        <provider-url>http://keycloak:8080/realms/PoCRealm%20Oauth2OpenIdConnect</provider-url>
        <client-id>angular-client</client-id>
        <provider>keycloak</provider>
        <ssl-required>external</ssl-required>
        <credential name="secret" secret="${CREDENTIAL_STORE:credentialStore:oidc-client-secret}"/>
        <principal-attribute>preferred_username</principal-attribute>
        <enable-basic-auth>false</enable-basic-auth>
        <public-client>false</public-client>
        <confidential-port>8443</confidential-port>
    </secure-deployment>
</subsystem>
```

### Methode 2B: Microprofile Config (empfohlen für EAP 8.x)

EAP 8.x unterstützt standardmäßig MicroProfile Config, was eine moderne Alternative zu Properties-Dateien bietet.

#### Schritt 1: MicroProfile Config Quelle erstellen

Erstellen Sie eine Datei `META-INF/microprofile-config.properties` in Ihrem Deployment-Archiv (WAR/EAR):

```properties
# OIDC-Konfiguration
oidc.client.secret=MeinOIDCClientSecret
```

#### Schritt 2: OIDC-Konfiguration anpassen (für OIDC-Client 2.0)

```xml
<subsystem xmlns="urn:wildfly:elytron-oidc-client:2.0">
    <secure-deployment name="jee-backend-1.0">
        <provider-url>http://keycloak:8080/realms/PoCRealm%20Oauth2OpenIdConnect</provider-url>
        <client-id>angular-client</client-id>
        <provider>keycloak</provider>
        <ssl-required>external</ssl-required>
        <credential name="secret" secret="${mp-config:oidc.client.secret}"/>
        <principal-attribute>preferred_username</principal-attribute>
        <enable-basic-auth>false</enable-basic-auth>
        <public-client>false</public-client>
        <confidential-port>8443</confidential-port>
    </secure-deployment>
</subsystem>
```

### Methode 2C: Einfache System-Property (für schnelle PoC in EAP 8.x)

#### Schritt 1: System-Property in EAP 8.x setzen

Über CLI:

```
/system-property=oidc.client.secret:add(value="MeinOIDCClientSecret")
reload
```

Oder in standalone.xml:

```xml
<system-properties>
    <property name="oidc.client.secret" value="MeinOIDCClientSecret"/>
</system-properties>
```

#### Schritt 2: OIDC-Konfiguration anpassen (für OIDC-Client 2.0)

```xml
<subsystem xmlns="urn:wildfly:elytron-oidc-client:2.0">
    <secure-deployment name="jee-backend-1.0">
        <provider-url>http://keycloak:8080/realms/PoCRealm%20Oauth2OpenIdConnect</provider-url>
        <client-id>angular-client</client-id>
        <provider>keycloak</provider>
        <ssl-required>external</ssl-required>
        <credential name="secret" secret="${oidc.client.secret}"/>
        <principal-attribute>preferred_username</principal-attribute>
        <enable-basic-auth>false</enable-basic-auth>
        <public-client>false</public-client>
        <confidential-port>8443</confidential-port>
    </secure-deployment>
</subsystem>
```

## Wichtige Unterschiede zwischen OIDC-Client 1.0 und 2.0

1. **Namespace-Änderung**: `urn:wildfly:elytron-oidc-client:1.0` → `urn:wildfly:elytron-oidc-client:2.0`

2. **Konfigurationsstruktur**: OIDC-Client 2.0 hat eine andere XML-Struktur, wobei der `<provider>` nicht mehr als eigenständiges Element, sondern als Attribut innerhalb des `<secure-deployment>` konfiguriert wird.

3. **Zusätzliche Attribute**: OIDC-Client 2.0 bietet zusätzliche Konfigurationsattribute für bessere Kontrolle und Sicherheit.

4. **MicroProfile Integration**: EAP 8.x und OIDC-Client 2.0 haben eine bessere Integration mit MicroProfile Config.

5. **Expression-Resolution**: Die Syntax für Expression-Resolution wurde verbessert und bietet mehr Optionen.

## Sicherheitshinweise

1. Für **Produktionsumgebungen** sollten Sie immer den **Elytron Credential Store** oder die **MicroProfile Config** Methode verwenden.

2. Die **System-Property-Methode** ist nur für Entwicklungs- und Testumgebungen geeignet.

3. Für JBoss EAP 8.x mit OIDC-Client 2.0 ist die **MicroProfile Config** Methode besonders empfehlenswert, da sie modern, flexibel und gut in das Framework integriert ist.

4. Erstellen Sie regelmäßige Backups des Credential Store und sichern Sie die Passwörter an einem sicheren Ort.

5. Rotieren Sie das OIDC-Client-Secret regelmäßig als Best Practice.
