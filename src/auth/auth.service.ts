// src/auth/auth.service.ts
import { Injectable } from '@angular/core';
import { OAuthService, OAuthEvent } from 'angular-oauth2-oidc';
import { BehaviorSubject, Observable, filter, map } from 'rxjs';
import { Router } from '@angular/router';
import { UserClaims, extractMandantFromUpn } from './auth.config';

// Definieren Sie eine Mapping-Tabelle für Präfixe zu Domains
const PREFIX_TO_DOMAIN: Record<string, string> = {
  'now': 'now-it.drv',
  'rh': 'rhl.drv',
  'bh': 'bsh.drv',
  // Weitere Mappings hier...
};
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
    const claims = this.oauthService.getIdentityClaims() as UserClaims;

    if (claims) {
      // UPN korrigieren, wenn er nicht das richtige Format hat
      let upn = claims.upn;
      if (upn && !upn.includes('@')) {
        // Default-Domain (falls kein passendes Präfix gefunden wird)
        let domain = 'now-it.drv';

        // Prüfen, ob der Benutzername mit einem bekannten Präfix beginnt
        let prefixFound = false;

        // Alle bekannten Präfixe durchgehen und prüfen
        for (const prefix in PREFIX_TO_DOMAIN) {
          if (upn.startsWith(prefix)) {
            domain = PREFIX_TO_DOMAIN[prefix];
            prefixFound = true;
            console.log(`Präfix '${prefix}' gefunden, verwende Domain: ${domain}`);
            break;
          }
        }

        if (!prefixFound) {
          console.warn(`Kein passendes Präfix für '${upn}' gefunden, verwende Standard-Domain: ${domain}`);
        }

        // Domain anhängen
        upn = `${upn}@${domain}`;
        console.log('Korrigierter UPN:', upn);

        // Korrigierten UPN in die Claims einfügen
        claims.upn = upn;
      }

      // Claims mit korrigiertem UPN ins Subject setzen
      this.userInfoSubject.next(claims);

      // Mandanten-ID aus dem korrigierten UPN extrahieren
      const mandantId = extractMandantFromUpn(claims.upn);
      this.mandantSubject.next(mandantId);

      console.log('Claims geladen:', claims);
      console.log('Mandanten-ID:', mandantId);
    } else {
      console.warn('Keine Claims im ID-Token gefunden');
      this.userInfoSubject.next(null);
      this.mandantSubject.next(null);
    }
  }

  private handleLogout(): void {
    this.userInfoSubject.next(null);
    this.mandantSubject.next(null);
  }
// src/auth/auth.service.ts
public login(): void {
  console.log('Login gestartet...');

  // Prüfen, ob Discovery Document geladen ist
  if (!this.oauthService.discoveryDocumentLoaded) {
    console.warn('Discovery Document ist nicht geladen, lade es jetzt...');
    this.oauthService.loadDiscoveryDocument().then(() => {
      console.log('Discovery Document nachgeladen, starte Login-Flow');
      this.oauthService.initLoginFlow();
    }).catch(error => {
      console.error('Fehler beim Laden des Discovery Documents:', error);
    });
    return;
  }

  try {
    console.log('Initiiere Login-Flow');
    this.oauthService.initLoginFlow();
  } catch (error) {
    console.error('Fehler beim Initiieren des Login-Flows:', error);
  }
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
