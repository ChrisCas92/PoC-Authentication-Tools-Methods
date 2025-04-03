// src/app/app.config.ts
import { ApplicationConfig, importProvidersFrom } from '@angular/core';
import { provideRouter } from '@angular/router';
import { provideZoneChangeDetection } from '@angular/core';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { OAuthModule, provideOAuthClient } from 'angular-oauth2-oidc';

import { routes } from './app.routes';
import { authInterceptor } from '../auth/auth.interceptor';
import { authConfig } from '../auth/auth.config';

export const appConfig: ApplicationConfig = {
  providers: [
    provideZoneChangeDetection({ eventCoalescing: true }),
    provideRouter(routes),
    provideHttpClient(withInterceptors([authInterceptor])),
    importProvidersFrom(
      OAuthModule.forRoot()
    ),
    provideOAuthClient({
      resourceServer: {
        // URL des JBoss/WildFly-Backends im Docker-Netzwerk
        allowedUrls: ['http://jboss-backend:8081/jee-backend-1.0'],
        sendAccessToken: true,
      }
    }),
    // Bereitstellen der Auth-Konfiguration
    {
      provide: 'authConfig',
      useValue: authConfig
    }
  ]
};
