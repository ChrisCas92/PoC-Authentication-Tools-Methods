// src/auth/auth.config.ts
import { AuthConfig } from 'angular-oauth2-oidc';

export const authConfig: AuthConfig = {
  issuer: 'http://localhost:8080/realms/PoCRealm-Oauth2OpenIdConnect',
  redirectUri: window.location.origin,
  clientId: 'angular-client',
  responseType: 'code',
  scope: 'openid profile email',
  showDebugInformation: true,
  requireHttps: false,
  disableAtHashCheck: true,
  useIdTokenHintForSilentRefresh: true,
  // Client Secret hinzufügen
  dummyClientSecret: '9Ie6TbfCfkurKsUkq6Yx0zMtUE3J4Flv'
  // Das ist die korrekte Eigenschaft, die angibt, ob ID-Tokens angefordert werden
  // 'requestIdToken' existiert nicht, stattdessen müssen wir responseType anpassen
  // responseType: 'code id_token' würde sowohl Authorization Code als auch ID-Token anfordern
  // Aber wir verwenden hier 'code', und das ID-Token wird beim Token-Austausch angefordert
};

// Interface für die erwarteten Claims im Token
export interface UserClaims {
  // Standardmäßige OIDC-Claims + winaccountname und upn
  sub: string; // Eindeutige ID des Benutzers
  winaccountname?: string;  // Windows-Kontoname des Benutzers falls verfügbar
  upn?: string; // User Principal Name (UPN) des Benutzers
  email?: string;
  name?: string;
  preferred_username?: string;
}

// Mapping von Domains zu Mandanten-IDs
export const domainToMandantMapping: Record<string, string> = {
  'rhl.drv': '13',
  'bsh.drv': '14',
  'now-it.drv': '15',
  // Weitere Mappings hinzufügen
};

// In auth.config.ts
export function extractMandantFromUpn(upn: string | undefined): string | null {
  if (!upn) {
    console.warn('Kein UPN vorhanden');
    return null;
  }

  // Wenn UPN bereits ein @ enthält, normale Extraktion verwenden
  if (upn.includes('@')) {
    const domain = upn.split('@')[1];
    return domainToMandantMapping[domain] || null;
  }

  // Spezielle Mapping-Logik für einfache Benutzernamen ohne Domain
  if (upn.startsWith('now')) {
    // NOW-IT-Benutzer gehören zu Mandant 15
    return '15';
  } else if (upn.startsWith('rhl')) {
    // RHL-Benutzer gehören zu Mandant 13
    return '13';
  } else if (upn.startsWith('bsh')) {
    // BSH-Benutzer gehören zu Mandant 14
    return '14';
  }

  console.warn('Konnte Mandanten-ID nicht aus UPN/Username ermitteln:', upn);
  return null;
}
