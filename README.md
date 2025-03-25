# Oauth2OpenIDConnectAngularFrontendJeeBackend

This project was generated using [Angular CLI](https://github.com/angular/angular-cli) version 19.2.1.

## Development server

To start a local development server, run:

```bash
ng serve
```

Once the server is running, open your browser and navigate to `http://localhost:4200/`. The application will automatically reload whenever you modify any of the source files.

## Code scaffolding

Angular CLI includes powerful code scaffolding tools. To generate a new component, run:

```bash
ng generate component component-name
```

For a complete list of available schematics (such as `components`, `directives`, or `pipes`), run:

```bash
ng generate --help
```

## Building

To build the project run:

```bash
ng build
```

This will compile your project and store the build artifacts in the `dist/` directory. By default, the production build optimizes your application for performance and speed.

## Running unit tests

To execute unit tests with the [Karma](https://karma-runner.github.io) test runner, use the following command:

```bash
ng test
```

## Running end-to-end tests

For end-to-end (e2e) testing, run:

```bash
ng e2e
```

Angular CLI does not come with an end-to-end testing framework by default. You can choose one that suits your needs.

## Additional Resources

For more information on using the Angular CLI, including detailed command references, visit the [Angular CLI Overview and Command Reference](https://angular.dev/tools/cli) page.

## Docker Problematiken

Das grundlegende Problem verstehen
Wenn du Änderungen an deinem Frontend-Code vornimmst und diese nicht in der laufenden Anwendung erscheinen, könnte dies an verschiedenen Faktoren liegen:

**Caching-Probleme:** Docker oder der Browser speichert alte Versionen deiner Dateien im Cache.
**Volumen-Mounts:** Der Container verwendet möglicherweise nicht deine aktuellen Dateien.
**Build-Prozess-Probleme:** Deine Änderungen werden beim Build-Prozess nicht richtig übernommen.

# Lösungsansätze im Detail

# Frontend-Aktualisierung in Docker-Umgebungen

Diese Anleitung beschreibt, wie Sie Änderungen am Frontend-Code in einer Docker-Umgebung korrekt übernehmen können.

## Das grundlegende Problem

Bei der Verwendung von Docker mit Angular (oder anderen Frontend-Frameworks) kann es vorkommen, dass Änderungen am Quellcode nicht automatisch in der laufenden Anwendung sichtbar werden. Dies liegt hauptsächlich an der Art und Weise, wie Docker Images gebaut und Container ausgeführt werden.

## Lösungsansätze

### Option 1: Vollständiger Rebuild (Produktions-Ansatz)

Dieser Ansatz ist für Produktionsbuilds und finale Tests geeignet:

```bash
# 1. Angular-Anwendung bauen
ng build

# 2. Docker-Image neu bauen ohne Cache
docker-compose build --no-cache frontend

# 3. Container neu starten
docker-compose up -d frontend
```

Der Parameter `--no-cache` ist wichtig, da er Docker zwingt, alle Build-Schritte neu auszuführen und keine gecachten Schritte zu verwenden.

### Option 2: Entwicklungsmodus mit Volume-Mounts (empfohlen für aktive Entwicklung)

Für eine effizientere Entwicklung können Sie eine separate Docker-Compose-Konfiguration erstellen, die direktes Mounting des Quellcodes ermöglicht:

1. Erstellen Sie eine `docker-compose.dev.yml` Datei:

```yaml
services:
  # ... andere Services (keycloak, backend, etc.) ...

  frontend-dev:
    build:
      context: .
      dockerfile: Dockerfile.dev
    container_name: angular-frontend-dev
    volumes:
      - ./:/app
      - /app/node_modules
    ports:
      - "4200:4200"
    depends_on:
      - keycloak
    networks:
      - poc-network
```

2. Starten Sie den Entwicklungsserver:

```bash
docker-compose -f docker-compose.dev.yml up frontend-dev
```

Mit dieser Methode werden Änderungen am Code automatisch erkannt und der Browser wird aktualisiert.

## Verbesserte Docker-Konfiguration

### Optimiertes Frontend-Dockerfile (Mehrstufiger Build)

Ersetzen Sie Ihr aktuelles Frontend-Dockerfile durch dieses mehrstufige Dockerfile:

```dockerfile
# Build-Phase
FROM node:20-alpine AS build
WORKDIR /app

# Kopiere package.json und installiere Abhängigkeiten
COPY package*.json ./
RUN npm install

# Kopiere den Quellcode und baue die Anwendung
COPY . .
RUN npm run build

# Deployment-Phase
FROM nginx:alpine
# Kopiere die gebauten Dateien aus der Build-Phase
COPY --from=build /app/dist/oauth2-open-idconnect-angular-frontend-jee-backend/browser /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

Dieser Ansatz bietet mehrere Vorteile:

- Der Build-Prozess ist in Docker integriert
- Abhängigkeiten werden im Container installiert
- Die Konsistenz zwischen Entwicklungs- und Produktionsumgebungen wird verbessert

## Fehlerbehebung: Änderungen werden nicht übernommen

Wenn trotz Neustart des Containers Änderungen nicht übernommen werden:

1. **Vollständiger Neustart:**

   ```bash
   # Stoppe alle laufenden Container
   docker-compose down

   # Entferne alle ungenutzten Ressourcen (optional, `aber hilfreich`)
   docker system prune -a

   # Baue die Images neu ohne Cache zu verwenden
   docker-compose build --no-cache

   # Starte die Container neu
   docker-compose up -d
   ```

2. **Browser-Cache leeren:**
   Führen Sie einen Hard-Refresh im Browser durch (`Strg+F5 oder Cmd+Shift+R`).

3. **Build-Prozess prüfen:**

   ```bash
   # Überprüfen Sie die Ausgabe auf Fehler oder Warnungen.
   ng build --verbose
   ```

4. **Container-Logs überprüfen:**

   ```bash
   # Suchen nach Fehlern oder Warnungen, die auf Probleme hindeuten könnten.
   docker-compose logs -f frontend
   ```

5. **Container-Inhalt überprüfen:**
   ```bash
   # Stelle sicher, dass die Dateien im Container aktuell sind.
   docker exec -it angular-frontend sh
   ls -la /usr/share/nginx/html
   ```

## Bekannte Probleme und Lösungen

### "ng: not found" beim Starten des Development-Containers

Wenn beim Starten des Development-Containers der Fehler `sh: ng: not found` auftritt, liegt das daran, dass das Angular CLI nicht im Pfad des Containers verfügbar ist. Dies kann auf verschiedene Weise behoben werden:

1. Verwenden Sie `npx` in der `docker-compose.dev.yml`:

   ```yaml
   command: npx ng serve --host 0.0.0.0
   ```

2. Erstellen Sie ein eigenes Development-Dockerfile, das das Angular CLI global installiert:

   ```dockerfile
   FROM node:16-alpine
   RUN npm install -g @angular/cli
   # ... weitere Konfiguration
   ```

3 Stellen Sie sicher, dass in Ihrer `package.json` der `start`-Befehl korrekt definiert ist und fügen Sie `--host 0.0.0.0` hinzu, damit der Server von außerhalb des Containers erreichbar ist:

```json
"scripts": {
"start": "ng serve --host 0.0.0.0"
}
```

## Automatisiertes Build-Skript (optional)

Sie können den Build-Prozess mit einem Skript automatisieren:

### Für Windows (build-frontend.bat):

```batch
@echo off
echo Building Angular application...
call ng build
echo Building Docker image...
docker-compose build --no-cache frontend
echo Restarting container...
docker-compose up -d frontend
echo Done!
```

### Für Linux/Mac (build-frontend.sh):

```bash
#!/bin/bash
echo "Building Angular application..."
ng build
echo "Building Docker image..."
docker-compose build --no-cache frontend
echo "Restarting container..."
docker-compose up -d frontend
echo "Done!"
```

Nutzen Sie das Skript mit:

```bash
# Windows
.\build-frontend.bat

# Linux/Mac
chmod +x build-frontend.sh
./build-frontend.sh
```

## Zusammenfassung

1. **Für Produktionsbuilds:** Verwenden Sie den vollständigen Rebuild-Ansatz.
2. **Für aktive Entwicklung:** Verwenden Sie den Entwicklungsmodus mit Volume-Mounts.
3. **Für optimale Konfiguration:** Implementieren Sie das mehrstufige Dockerfile.
4. **Bei Problemen:** Folgen Sie dem Fehlerbehebungsleitfaden.
