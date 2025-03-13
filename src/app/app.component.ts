// app.component.ts
import { Component, OnInit } from '@angular/core';
import { OAuthService, AuthConfig } from 'angular-oauth2-oidc';

@Component({
  selector: 'app-root',
  template: `
    <div *ngIf="!loggedIn">
      <button (click)="login()">Login</button>
    </div>
    <div *ngIf="loggedIn">
      <h1>Willkommen, {{ userName }}</h1>
      <button (click)="logout()">Logout</button>
    </div>
  `
})
export class AppComponent implements OnInit {
  loggedIn = false;
  userName = '';

  authConfig: AuthConfig = {
    issuer: 'http://localhost:8080/realms/POCRealm',
    clientId: 'angular-client',  // Entspricht der in Keycloak konfigurierten Client-ID
    redirectUri: window.location.origin,
    responseType: 'code', // Authorization Code Flow (mit PKCE)
    scope: 'openid profile email',
    showDebugInformation: true,
    useSilentRefresh: true,
    silentRefreshRedirectUri: window.location.origin + '/silent-refresh.html'
  };

  constructor(private oauthService: OAuthService) {}

  ngOnInit(): void {
    // Konfiguration des OAuthService
    this.oauthService.configure(this.authConfig);
    this.oauthService.setupAutomaticSilentRefresh();

    // Laden des Discovery-Dokuments und Versuch des Logins
    this.oauthService.loadDiscoveryDocumentAndTryLogin().then(loggedIn => {
      this.loggedIn = loggedIn;
      if (loggedIn) {
        const claims = this.oauthService.getIdentityClaims();
        this.userName = claims ? claims['preferred_username'] : 'unbekannt';
      }
    });
  }

  // Startet den Login-Flow
  login(): void {
    this.oauthService.initLoginFlow();
  }

  // Führt den Logout durch
  logout(): void {
    this.oauthService.logOut();
  }
}
