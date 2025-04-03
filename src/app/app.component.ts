import { NgIf, AsyncPipe } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { OAuthService } from 'angular-oauth2-oidc';
import { authConfig } from '../auth/auth.config';
import { HttpClient } from '@angular/common/http';
import { AuthService } from '../auth/auth.service';
import { Observable } from 'rxjs';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [NgIf, AsyncPipe],
  templateUrl: './app.component.html',
  styles: [`
    .user-info {
      margin-top: 10px;
      padding: 10px;
      background-color: #f5f5f5;
      border-radius: 4px;
    }
    .user-info p {
      margin: 5px 0;
    }
  `]
})
export class AppComponent implements OnInit {
  // Observables für die Benutzerinformationen
  winAccountName$: Observable<string | undefined>;
  upn$: Observable<string | undefined>;
  mandant$: Observable<string | null>;

  get loggedIn(): boolean {
    return this.authService.isAuthenticated();
  }

  constructor(
    private oauthService: OAuthService,
    private http: HttpClient,
    private authService: AuthService
  ) {
    // OAuth konfigurieren
    this.configureOAuth();

    // Observables initialisieren
    this.winAccountName$ = this.authService.getWinAccountName();
    this.upn$ = this.authService.getUpn();
    this.mandant$ = this.authService.mandant$;
  }

  async configureOAuth() {
    this.oauthService.configure(authConfig);

    try {
      // Nur Discovery Document laden
      await this.oauthService.loadDiscoveryDocument();
      console.log('Discovery Document geladen');

      // Optional: URL-Parameter prüfen, ob wir in einem Auth-Callback sind
      // Dies hilft, wenn der Benutzer nach der Authentifizierung zurückgeleitet wird
      const hasCodeParam = window.location.search.includes('code=');
      if (hasCodeParam) {
        console.log('Authorization Code gefunden, verarbeite Login...');
        await this.oauthService.tryLogin();
      }
    } catch (error) {
      console.error('OAuth Konfigurationsfehler:', error);
    }
  }

  ngOnInit(): void {
    // Bereits im Konstruktor behandelt
  }

  login(): void {
    this.authService.login();
  }

  logout(): void {
    this.authService.logout();
  }

  testPublicEndpoint() {
    this.http.get('/api/public')
      .subscribe({
        next: (response) => {
          console.log('Public Endpoint Antwort:', response);
          alert('Public Endpoint Zugriff erfolgreich: ' + JSON.stringify(response));
        },
        error: (error) => {
          console.error('Fehler beim Zugriff auf Public Endpoint:', error);
          alert('Fehler beim Zugriff auf Public Endpoint: ' + error.message);
        }
      });
  }

  testSecuredEndpoint() {
    this.http.get('/api/secured')
      .subscribe({
        next: (response) => {
          console.log('Secured Endpoint Antwort:', response);
          alert('Secured Endpoint Zugriff erfolgreich: ' + JSON.stringify(response));
        },
        error: (error) => {
          console.error('Fehler beim Zugriff auf Secured Endpoint:', error);
          alert('Fehler beim Zugriff auf Secured Endpoint: ' + error.message);
        }
      });
  }

  testAdminEndpoint() {
    this.http.get('/api/admin')
      .subscribe({
        next: (response) => {
          console.log('Admin Endpoint Antwort:', response);
          alert('Admin Endpoint Zugriff erfolgreich: ' + JSON.stringify(response));
        },
        error: (error) => {
          console.error('Fehler beim Zugriff auf Admin Endpoint:', error);
          alert('Fehler beim Zugriff auf Admin Endpoint: ' + error.message);
        }
      });
  }
}
