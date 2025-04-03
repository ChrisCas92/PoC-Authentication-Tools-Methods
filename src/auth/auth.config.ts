// src/auth/auth.config.ts
import { AuthConfig } from 'angular-oauth2-oidc';

export const authConfig: AuthConfig = {
  issuer: `http://localhost:8080/realms/PoCRealm%20Oauth2OpenIdConnect`,
  redirectUri: window.location.origin,
  clientId: 'angular-client',
  responseType: 'code',
  scope: 'openid profile email',
  showDebugInformation: true,
  requireHttps: false,
  disableAtHashCheck: true,
  useIdTokenHintForSilentRefresh: true,
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

// Helfer-Funktion zum Extrahieren der Mandanten-ID aus dem UPN
export function extractMandantFromUpn(upn: string | undefined): string | null {
  if (!upn || !upn.includes('@')) {
    console.warn('Ungültiger UPN: ', upn);
    return null;
  }

  const domain = upn.split('@')[1];

  const mandantId = domainToMandantMapping[domain];

  if (!mandantId) {
    console.warn(`Keine Mandanten-ID für Domain gefunden: ${domain}`);
    return null;
  }

  return mandantId;
}
