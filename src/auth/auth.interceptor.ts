// src/auth/auth.interceptor.ts
import { HttpInterceptorFn, HttpRequest, HttpHandlerFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { AuthService } from './auth.service';

export const authInterceptor: HttpInterceptorFn = (
  req: HttpRequest<unknown>,
  next: HttpHandlerFn
) => {
  const authService = inject(AuthService);

  // Benutze ID-Token statt Access-Token (entsprechend den Anforderungen)
  const idToken = authService.getIdToken();

  if (idToken && shouldAddToken(req.url)) {
    // Authorization Header mit Bearer Token hinzufügen
    const authReq = req.clone({
      setHeaders: { Authorization: `Bearer ${idToken}` }
    });
    return next(authReq);
  }

  return next(req);
};

// Hilfsfunktion, um festzulegen, für welche URLs der Token verwendet werden soll
function shouldAddToken(url: string): boolean {
  // Token nur für Backend-API-Aufrufe hinzufügen
  return url.includes('/api/');
}
