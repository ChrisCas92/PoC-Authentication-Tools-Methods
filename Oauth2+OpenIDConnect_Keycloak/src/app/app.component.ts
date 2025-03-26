import { NgIf } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { OAuthService } from 'angular-oauth2-oidc';
import { authConfig } from '../auth/auth.config';
import { HttpClient } from '@angular/common/http';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [NgIf],
  templateUrl: './app.component.html'
})
export class AppComponent implements OnInit {
  loggedIn = false;

 // Inject HttpClient in constructor
constructor(private oauthService: OAuthService, private http: HttpClient) {
    // Configure and initialize OAuth
    this.configureOAuth();
  }

  async configureOAuth() {
    // Configure the OAuth service
    this.oauthService.configure(authConfig);

    try {
      // Load discovery document
      await this.oauthService.loadDiscoveryDocumentAndTryLogin();

      // Check if the user is logged in
      this.loggedIn = this.oauthService.hasValidAccessToken();

      console.log('OAuth configured successfully');
      console.log('Logged in status:', this.loggedIn);
    } catch (error) {
      console.error('OAuth configuration error:', error);
    }
  }

  ngOnInit(): void {
    // Already handled in constructor
  }

  login(): void {
    console.log('Starting login flow');
    this.oauthService.initLoginFlow();
  }

  logout(): void {
    console.log('Logging out');
    this.oauthService.logOut();
  }

  testPublicEndpoint() {
    this.http.get('/api/public')
      .subscribe({
        next: (response) => {
          console.log('Public endpoint response:', response);
          alert('Public endpoint access successful: ' + JSON.stringify(response));
        },
        error: (error) => {
          console.error('Error accessing public endpoint:', error);
          alert('Error accessing public endpoint: ' + error.message);
        }
  });
  }

  testSecuredEndpoint() {
    this.http.get('/api/secured')
      .subscribe({
      next: (response) => {
        console.log('Secured endpoint response:', response);
        alert('Secured endpoint access successful: ' + JSON.stringify(response));
      },
      error: (error) => {
        console.error('Error accessing secured endpoint:', error);
        alert('Error accessing secured endpoint: ' + error.message);
      }
      });
  }

  testAdminEndpoint() {
    this.http.get('/api/admin')
      .subscribe({
        next: (response) => {
          console.log('Admin endpoint response:', response);
          alert('Admin endpoint access successful: ' + JSON.stringify(response));
        },
        error: (error) => {
          console.error('Error accessing admin endpoint:', error);
          alert('Error accessing admin endpoint: ' + error.message);
        }
      });
  }
}
