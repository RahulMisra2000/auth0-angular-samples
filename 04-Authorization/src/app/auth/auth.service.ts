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
    // This points to the developers' subdomain at Auth0 ...Each subscription(aka tenant) to Auth0 gets a subdomain of auth0.com
    // e.g. https://companyx.auth0.com
    domain: AUTH_CONFIG.domain,
    
    // This points to the Application Settings that have been created by the developer at the Auth0 portal
    // A developer can configure multiple applications settings under the above domain
    // Each Application (e.g Angular SPA) a developer codes is being pointed to a specific application settings at Auth0 portal
    clientID: AUTH_CONFIG.clientID,
    
    // Here we are telling Auth0 which FLOW we are interested in .... We are requesting AT and IT tokens
    // When you request token (means requesting AT) and id_token (means requesting IT) -- it is IMPLICIT GRANT FLOW
    responseType: 'token id_token',
    
    // This is the namespace url identifier the developer creates at the Auth0 portal (under API menu) to REPRESENT the real API that is 
    // coded in the Resource Serve. It is JUST an identifier and does NOT point to any real url **********
    // The API scopes are created at the Auth0 Portal under this namespace url 
    // A developer can configure multiple API identifiers under the above domain
    // Here we are telling which API identifier to use
    audience: AUTH_CONFIG.apiUrl,           
    
    // We are requesting Auth0 to redirect the browser to this url after a successful authentication and provide 
    // goodies - AT, GRANTED scope, IT, idTokenPayload, ExpiresIn - as hash fragment
    redirectUri: AUTH_CONFIG.callbackURL,
    
    // These are the OpenId scopes and API scopes that the application is REQUESTING from the user AND if user OKs during the 
    // authentication flow then
    // the same are REQUESTED behind the scenes from Auth0 during the authentication process. By default, Auth0 always agrees and 
    // provides it UNLESS we write RULES at Auth0 portal. 
    
    // These RULES based on TONS of info it receives about the user and even from external sources can 
    // deny the entire Authentication (even if the user's credentials were good). In such case the user will see an error message
    // on the UI of the login screen and the authentication flow will stop because no tokens are sent to the browser.
    // If the rules approve the authentication (this is the default) the RULES can still modify the AT and IT payload because they
    // have access to the AT and IT tokens. They can do CRUD on the claims that are inside the AT and IT and they can also change 
    // the scope inside the AT. Basically, the RULES get a crack at at the AT and IT before they are sent down to the browser.
    // **** So, what the browser receives inside the goodies is the GRANTED stuff and this may be different from the REQUESTED stuff *******
    // --------------------------------------
    // Hence these are the REQUESTED SCOPES
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

    const self = this;    // ********************************************* Very interesting
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
    // change the scope: inside the AT. Read my Angular2 - Security Google document about RULES
    // If GRANTED SCOPES is empty that means Auth0 gave us all the REQUESTED SCOPES so, use the REQUESTED SCOPES 
    // If GRANTED SCOPES is not empty then, it means that RULES did an override so, use the GRANTED SCOPES
    // That is how Auth0 company has coded it 
    
    // Here it is saying is that if there is something in the authResult.scope then use it. 
    // If it is empty then use the requestedScopes and if that is empty then save empty meaning no scopes were requested .. that won't
    // happen, because we alwats request scopes
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

  public userHasScopes(sc: Array<string>): boolean {
    const grantedScopes = JSON.parse(localStorage.getItem('scopes')).split(' ');
    return sc.every(s => grantedScopes.includes(s));
  }

}

