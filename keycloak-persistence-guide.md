# Keycloak-Konfiguration dauerhaft speichern

Diese Anleitung zeigt, wie Sie Ihre Keycloak-Konfiguration persistent speichern und bei Bedarf wiederherstellen können, selbst wenn Container neu gebaut werden.

## 1. Realm-Export/Import (empfohlen)

Der Export/Import-Mechanismus ist die zuverlässigste Methode, um eine reproduzierbare Keycloak-Konfiguration zu gewährleisten.

### 1.1 Realm exportieren

Nachdem Sie Ihren Realm vollständig konfiguriert haben (Clients, Benutzer, Rollen, etc.):

```bash
# Export eines Realms im Docker-Container
docker exec -it keycloak \
  /opt/keycloak/bin/kc.sh export \
  --file /tmp/realm-export.json \
  --realm PoCRealm_Oauth2OpenIdConnect \
  --users realm_file
```

Dann kopieren Sie die Datei aus dem Container:

```bash
docker cp keycloak:/tmp/realm-export.json ./realm-export.json
```

### 1.2 Realm-Import bei Container-Start automatisieren

Erstellen Sie ein angepasstes Dockerfile für Keycloak:

```dockerfile
FROM quay.io/keycloak/keycloak:latest

# Realm-Konfiguration kopieren
COPY realm-export.json /opt/keycloak/data/import/

# Enable health and metrics
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true

# Configure database
ENV KC_DB=postgres
ENV KC_DB_URL=jdbc:postgresql://postgres:5432/keycloak
ENV KC_DB_USERNAME=keycloak
ENV KC_DB_PASSWORD=password

# Configure HTTPS
ENV KC_HOSTNAME_STRICT=false

WORKDIR /opt/keycloak
# Import Realm beim Start (erster Aufruf)
ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start-dev", "--import-realm"]
```

Alternativ in docker-compose.yml:

```yaml
services:
  keycloak:
    image: quay.io/keycloak/keycloak:latest
    volumes:
      - ./realm-export.json:/opt/keycloak/data/import/realm-export.json
    command: ["start-dev", "--import-realm"]
    environment:
      - KC_DB=postgres
      - KC_DB_URL=jdbc:postgresql://postgres:5432/keycloak
      - KC_DB_USERNAME=keycloak
      - KC_DB_PASSWORD=password
    ports:
      - "8080:8080"
    depends_on:
      - postgres
```

## 2. Persistente Speicherung mit Datenbank

Für langfristige Datenspeicherung sollten Sie eine persistente Datenbank verwenden.

### 2.1 Postgresql-Datenbank für Keycloak einrichten

```yaml
services:
  postgres:
    image: postgres:14
    volumes:
      - postgres_data:/var/lib/postgresql/data
    environment:
      POSTGRES_DB: keycloak
      POSTGRES_USER: keycloak
      POSTGRES_PASSWORD: password
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U keycloak"]
      interval: 5s
      timeout: 5s
      retries: 5
      
  keycloak:
    image: quay.io/keycloak/keycloak:latest
    depends_on:
      postgres:
        condition: service_healthy
    volumes:
      - ./realm-export.json:/opt/keycloak/data/import/realm-export.json
    environment:
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: password
      KC_HOSTNAME: localhost
    command: 
      - start-dev
      - --import-realm
    ports:
      - "8080:8080"

volumes:
  postgres_data:
```

## 3. Kombinierte Lösung (empfohlen)

Die beste Praxis ist, Realm-Export und persistente Datenbank zu kombinieren:

1. **Für die Entwicklung und CI/CD**:
   - Verwenden Sie die Realm-Export-Datei als "Wahrheit" der Konfiguration
   - Commiten Sie diese Datei in Ihre Versionskontrolle

2. **Für die Laufzeit**:
   - Verwenden Sie eine persistente Datenbank
   - Importieren Sie den Realm beim ersten Start

3. **Für Backups**:
   - Exportieren Sie den Realm regelmäßig
   - Sichern Sie die Datenbank regelmäßig

### 3.1 Vollständige docker-compose.yml Lösung

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:14
    container_name: keycloak-postgres
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./db-backup:/backup
    environment:
      POSTGRES_DB: keycloak
      POSTGRES_USER: keycloak
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-password}
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U keycloak"]
      interval: 5s
      timeout: 5s
      retries: 5
    restart: unless-stopped
    networks:
      - keycloak-network
      
  keycloak:
    image: quay.io/keycloak/keycloak:latest
    container_name: keycloak
    depends_on:
      postgres:
        condition: service_healthy
    volumes:
      - ./realm-export.json:/opt/keycloak/data/import/realm-export.json
      - ./themes:/opt/keycloak/themes
    environment:
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: ${POSTGRES_PASSWORD:-password}
      KC_HOSTNAME: localhost
      KEYCLOAK_ADMIN: ${KEYCLOAK_ADMIN:-admin}
      KEYCLOAK_ADMIN_PASSWORD: ${KEYCLOAK_ADMIN_PASSWORD:-admin}
    command: 
      - start-dev
      - --import-realm
    ports:
      - "8080:8080"
    restart: unless-stopped
    networks:
      - keycloak-network

  # Optionaler Backup-Service
  backup:
    image: postgres:14
    container_name: keycloak-backup
    volumes:
      - ./db-backup:/backup
    environment:
      PGPASSWORD: ${POSTGRES_PASSWORD:-password}
    command: >
      bash -c "while true; do 
        pg_dump -h postgres -U keycloak keycloak > /backup/keycloak_backup_`date +%Y%m%d_%H%M%S`.sql;
        echo 'Backup completed';
        sleep 86400;
      done"
    depends_on:
      - postgres
    restart: unless-stopped
    networks:
      - keycloak-network

volumes:
  postgres_data:

networks:
  keycloak-network:
    driver: bridge
```

### 3.2 Automatisches Backup-Skript

Erstellen Sie ein Skript `backup-keycloak.sh`:

```bash
#!/bin/bash
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Export Realm
echo "Exporting Realm configuration..."
docker exec keycloak /opt/keycloak/bin/kc.sh export --file /tmp/realm-export_${TIMESTAMP}.json --realm PoCRealm_Oauth2OpenIdConnect --users realm_file
docker cp keycloak:/tmp/realm-export_${TIMESTAMP}.json ./backups/realm-export_${TIMESTAMP}.json

# Kopiere die aktuelle Version für Import
cp ./backups/realm-export_${TIMESTAMP}.json ./realm-export.json

# Backup Datenbank
echo "Backing up database..."
docker exec keycloak-postgres pg_dump -U keycloak keycloak > ./backups/keycloak_db_${TIMESTAMP}.sql

echo "Backup completed successfully!"
```

Machen Sie das Skript ausführbar:
```bash
chmod +x backup-keycloak.sh
```

## 4. Wiederherstellung nach Neuinstallation

Wenn Sie das System neu aufsetzen müssen:

1. Stellen Sie sicher, dass Ihre `realm-export.json` verfügbar ist
2. Starten Sie die Container mit der obigen Konfiguration
3. Der Realm wird automatisch importiert

Wenn Sie auch die Datenbankdaten wiederherstellen möchten:

```bash
# Container stoppen
docker-compose down

# Datenbank-Volume löschen wenn nötig
docker volume rm keycloak_postgres_data

# Container neu starten, diesmal ohne Import
docker-compose up -d postgres

# Datenbank wiederherstellen
cat ./backups/keycloak_db_TIMESTAMP.sql | docker exec -i keycloak-postgres psql -U keycloak

# Keycloak starten
docker-compose up -d keycloak
```

## 5. Für Produktionsumgebungen

Für Produktionsumgebungen sollten folgende Anpassungen vorgenommen werden:

1. `start-dev` durch `start` ersetzen
2. HTTPS konfigurieren
3. Admin-Passwörter sicher speichern (z.B. mit Docker Secrets)
4. Postgres mit sicherer Konfiguration versehen

Beispiel für Keycloak Production-Start:
```yaml
command:
  - start
  - --optimized
  - --https-certificate-file=/opt/keycloak/conf/cert.pem
  - --https-certificate-key-file=/opt/keycloak/conf/key.pem
```

## 6. Fazit

Mit dieser Konfiguration haben Sie:

1. Eine versionierbare Realm-Konfiguration als JSON-Datei
2. Persistente Datenspeicherung in Postgres
3. Automatisches Backup für Konfiguration und Daten
4. Einfache Wiederherstellung bei Neuinstallation

Diese Kombination gewährleistet, dass Ihre Keycloak-Konfiguration jederzeit wiederhergestellt werden kann, auch wenn Container oder Volumes gelöscht werden.
