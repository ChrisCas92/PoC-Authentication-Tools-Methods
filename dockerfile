# Stage 1: Build the Angular app
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build --prod

# Stage 2: Serve the app with Nginx
FROM nginx:alpine
# Passe den Pfad an den Namen deines Build-Ordners an (standardmäßig "dist/<project-name>")
COPY --from=build /app/dist/oauth2-open-idconnect-angular-frontend-jee-backend /usr/share/nginx/html
EXPOSE 80
