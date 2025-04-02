// src/auth/auth.service.ts
import { Injectable } from '@angular/core';
import { OAuthService, OAuthEvent } from 'angular-oauth2-oidc';
import { BehaviorSubject, Observable, filter, map } from 'rxjs';
import { Router } from '@angular/router';
import { UserClaims, extractMandantFromUpn } from './auth.config';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private userInfoSubject = new BehaviorSubject<UserClaims | null>(null);
  public userInfo$ = this.userInfoSubject.asObservable();

  // Mandanten-Info als separater Stream
  private mandantSubject = new BehaviorSubject<string | null>(null);
  public mandant$ = this.mandantSubject.asObservable();

  constructor(
    private oauthService: OAuthService,
    private router: Router
  ) {
    // Auf Events vom OAuthService reagieren
    this.oauthService.events
      .pipe(
        filter((e: OAuthEvent) => e.type === 'token_received' || e.type === 'logout')
      )
      .subscribe(event => {
        if (event.type === 'token_received') {
          this.handleTokenReceived();
        } else if (event.type === 'logout') {
          this.handleLogout();
        }
      });

    // Initialer Check
    if (this.oauthService.hasValidAccessToken()) {
      this.handleTokenReceived();
    }
  }

  private handleTokenReceived(): void {
    // ID-Token dekodieren und Claims extrahieren
    const claims = this.oauthService.getIdentityClaims() as UserClaims;

    if (claims) {
      this.userInfoSubject.next(claims);

      // Mandanten-ID aus UPN extrahieren
      const mandantId = extractMandantFromUpn(claims.upn);
      this.mandantSubject.next(mandantId);

      console.log('Claims geladen:', claims);
      console.log('Mandanten-ID:', mandantId);
    } else {
      console.warn('Keine Claims im ID-Token gefunden');
    }
  }

  private handleLogout(): void {
    this.userInfoSubject.next(null);
    this.mandantSubject.next(null);
  }

  public login(): void {
    this.oauthService.initLoginFlow();
  }

  public logout(): void {
    this.oauthService.logOut();
  }

  // Getter für Token
  public getIdToken(): string {
    return this.oauthService.getIdToken();
  }

  public getAccessToken(): string {
    return this.oauthService.getAccessToken();
  }

  // Getter für Claims
  public getWinAccountName(): Observable<string | undefined> {
    return this.userInfo$.pipe(
      map(user => user?.winaccountname)
    );
  }

  public getUpn(): Observable<string | undefined> {
    return this.userInfo$.pipe(
      map(user => user?.upn)
    );
  }

  public isAuthenticated(): boolean {
    return this.oauthService.hasValidAccessToken();
  }
}
