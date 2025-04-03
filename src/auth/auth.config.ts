// src/auth/auth.config.ts
import { AuthConfig } from 'angular-oauth2-oidc';

export const authConfig: AuthConfig = {
  issuer: ``,
  clientId: '',
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
  sub: string;
  winaccountname?: string;
  upn?: string;
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
    return null;
  }

  const domain = upn.split('@')[1];
  return domainToMandantMapping[domain] || null;
}
