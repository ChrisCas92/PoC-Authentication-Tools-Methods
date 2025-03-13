// main.ts
import { bootstrapApplication } from '@angular/platform-browser';
import { importProvidersFrom } from '@angular/core';
import { HttpClientModule, HTTP_INTERCEPTORS } from '@angular/common/http';
import { OAuthModule } from 'angular-oauth2-oidc';

import { AppComponent } from './app/app.component';
import { AuthInterceptor } from './auth/auth.interceptor';

bootstrapApplication(AppComponent, {
  providers: [
    // Importiere Module als Provider
    importProvidersFrom(HttpClientModule, OAuthModule.forRoot()),
    // Registriere den HTTP-Interceptor
    {
      provide: HTTP_INTERCEPTORS,
      useClass: AuthInterceptor,
      multi: true,
    },
  ],
});
