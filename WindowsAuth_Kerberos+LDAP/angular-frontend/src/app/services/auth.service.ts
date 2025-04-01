import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Observable, BehaviorSubject, throwError } from 'rxjs';
import { catchError, tap, map } from 'rxjs/operators';
import { User } from '../models/user.model';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private http = inject(HttpClient);

  private currentUserSubject = new BehaviorSubject<User | null>(null);
  public currentUser$ = this.currentUserSubject.asObservable();

  private isAuthenticatedSubject = new BehaviorSubject<boolean>(false);
  public isAuthenticated$ = this.isAuthenticatedSubject.asObservable();

  constructor() {
    // Check authentication status when service is created
    this.checkAuthStatus().subscribe();
  }

  public get currentUser(): User | null {
    return this.currentUserSubject.value;
  }

  /**
   * Checks if the user is authenticated with the backend
   */
  checkAuthStatus(): Observable<boolean> {
    return this.http.get<any>('/api/auth/status', { withCredentials: true })
      .pipe(
        map(response => {
          const isAuthenticated = response && response.authenticated;
          this.isAuthenticatedSubject.next(isAuthenticated);

          if (isAuthenticated) {
            this.loadUserDetails().subscribe();
          }

          return isAuthenticated;
        }),
        catchError(error => {
          this.isAuthenticatedSubject.next(false);
          return throwError(() => error);
        })
      );
  }

  /**
   * Loads detailed user information from the backend
   */
  loadUserDetails(): Observable<User> {
    return this.http.get<User>('/api/auth/user', { withCredentials: true })
      .pipe(
        tap(user => {
          this.currentUserSubject.next(user);
        }),
        catchError(this.handleError)
      );
  }

  /**
   * Refreshes user information by forcing a reload from LDAP
   */
  refreshUserDetails(): Observable<User> {
    return this.http.post<User>('/api/auth/refresh', {}, { withCredentials: true })
      .pipe(
        tap(user => {
          this.currentUserSubject.next(user);
        }),
        catchError(this.handleError)
      );
  }

  /**
   * Handles HTTP errors
   */
  private handleError(error: HttpErrorResponse) {
    console.error('Auth service error:', error);

    if (error.status === 401) {
      return throwError(() => 'Authentication failed. Please ensure you are logged into your Windows domain.');
    }

    return throwError(() => 'An error occurred. Please try again later.');
  }
}
