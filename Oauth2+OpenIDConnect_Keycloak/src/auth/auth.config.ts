import { AuthConfig } from 'angular-oauth2-oidc';

export const authConfig: AuthConfig = {
  // Use localhost because the browser accesses Keycloak directly
  issuer: 'http://localhost:8080/realms/PoCRealm%20Oauth2OpenIdConnect',
  redirectUri: window.location.origin,
  clientId: 'angular-client',
  responseType: 'code',
  scope: 'openid profile email',
  showDebugInformation: true,
  requireHttps: false,
  disableAtHashCheck: true
};
