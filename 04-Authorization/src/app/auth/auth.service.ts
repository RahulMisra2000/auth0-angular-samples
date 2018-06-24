import { Injectable } from '@angular/core';
import { AUTH_CONFIG } from './auth0-variables';
import { Router } from '@angular/router';
import 'rxjs/add/operator/filter';
import * as auth0 from 'auth0-js';

(window as any).global = window;

@Injectable()
export class AuthService {

  userProfile: any;
  requestedScopes: string = 'openid profile read:messages write:messages';

  auth0 = new auth0.WebAuth({
    clientID: AUTH_CONFIG.clientID,
    domain: AUTH_CONFIG.domain,
 // We are requesting AT and IT
    responseType: 'token id_token',
 // This is the namespace url of the API configuration in the Auth0 Portal
    audience: AUTH_CONFIG.apiUrl,       
 // Auth0 will redirect the browser here after a successful authentication and provide goodies as hash fragment
    redirectUri: AUTH_CONFIG.callbackURL,
 // These are the OpenId scopes and API scopes that the application is requesting from the user
    // --------------------------------------
    // Hence they are called REQUESTED SCOPES
    scope: this.requestedScopes
    // --------------------------------------
  });

  constructor(public router: Router) {}

  public login(): void {
    this.auth0.authorize();       // This gets the Authentication Process going ...
  }

  public handleAuthentication(): void {
    this.auth0.parseHash((err, authResult) => {     // This places all the goodies in the authResult for us to use
      if (authResult && authResult.accessToken && authResult.idToken) {
        this.setSession(authResult);
        this.router.navigate(['/home']);
      } else if (err) {
        this.router.navigate(['/home']);
        console.log(err);
        alert(`Error: ${err.error}. Check the console for further details.`);
      }
    });
  }

  public getProfile(cb): void {
    const accessToken = localStorage.getItem('access_token');
    if (!accessToken) {
      throw new Error('Access token must exist to fetch profile');
    }

    const self = this;    // ****************** Very interesting
    this.auth0.client.userInfo(accessToken, (err, profile) => {
      if (profile) {
        self.userProfile = profile;
      }
      cb(err, profile);
    });
  }

  private setSession(authResult): void {
    // Set the time that the access token will expire at
    const expiresAt = JSON.stringify((authResult.expiresIn * 1000) + new Date().getTime());

    // ------------------------------------------------------------
    // authResult.scope is the GRANTED SCOPES ... granted by Auth0
    // ------------------------------------------------------------
    // Granted scopes could be different from Requested Scopes because the RULES at Auth0 Portal can 
    // change them. Read my Angular2 - Security Google document about RULES
    // If GRANTED SCOPES is empty that means Auth0 gave us all the REQUESTED SCOPES so, use the REQUESTED SCOPES 
    // If GRANTED SCOPES has something then, it means that Auth0 did an override so, use the GRANTED SCOPES
    // That is how Auth0's logic is
    const scopes = authResult.scope || this.requestedScopes || '';

    localStorage.setItem('access_token', authResult.accessToken);
    localStorage.setItem('id_token', authResult.idToken);
    localStorage.setItem('expires_at', expiresAt);
    localStorage.setItem('scopes', JSON.stringify(scopes));
  }

  public logout(): void {
    // Remove tokens and expiry time from localStorage
    localStorage.removeItem('access_token');
    localStorage.removeItem('id_token');
    localStorage.removeItem('expires_at');
    localStorage.removeItem('scopes');
    // Go back to the home route
    this.router.navigate(['/']);
  }

  public isAuthenticated(): boolean {
    // Check whether the current time is past the
    // access token's expiry time
    const expiresAt = JSON.parse(localStorage.getItem('expires_at') || '{}');
    return new Date().getTime() < expiresAt;
  }

  public userHasScopes(scopes: Array<string>): boolean {
    const grantedScopes = JSON.parse(localStorage.getItem('scopes')).split(' ');
    return scopes.every(scope => grantedScopes.includes(scope));
  }

}

