import { Injectable } from '@angular/core';
import { AUTH_CONFIG } from './auth0-variables';
import { Router } from '@angular/router';
import 'rxjs/add/operator/filter';
import * as auth0 from 'auth0-js';

(window as any).global = window;

@Injectable()
export class AuthService {

  
  // *********** Think of this as PRIMING the Auth0.js library so we can make API calls -----------------------------
  // ----------------------------------------------------------------------------------------------------------------
  auth0 = new auth0.WebAuth({
    clientID: AUTH_CONFIG.clientID,
    domain: AUTH_CONFIG.domain,
    responseType: 'token id_token',                       
    audience: `https://${AUTH_CONFIG.domain}/userinfo`,  
    redirectUri: AUTH_CONFIG.callbackURL,
    scope: 'openid profile email'                         // The scopes we would like to receive in the idToken
  });
  // ----------------------------------------------------------------------------------------------------------------
  
  
  userProfile: any;

  constructor(public router: Router) {}

  public login(): void {
    this.auth0.authorize();                             // This API gets the authentication process rolling ...
                                                        // Takes the browser from our SPA to https://domain/authorize ENDPOINT
                                                        // Then redirects to https://domain/login ENDPOINT
                                                        // Then the login widget appears
                                                        // Then a number of things can happen depending on whether social media provider
                                                        // is clicked or username/pwd is provided to go against Auth0 database, etc
                                                        // Ultimately Auth0 REDIRECTS to the callback URL which is in our SPA
                                                        // This kicks off the SPA again.....
                                                        // In the hash fragment of the callback URL are the tokens, etc. which
                                                        // we get extracted by using .parseHash() API as shown below.
                                                        // We call it from the BootStrap component's ngOnit                                                  
  }

  public handleAuthentication(): void {
    this.auth0.parseHash((err, authResult) => {
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
  // ***************** authResult javascript object given to us has the following : ****************
  // .accessToken
  // .idToken         ____.____._____
  // .refreshToken    null
  // .expiresIn
  // .idTokenPayload  (this repeats all the claims inside that are already inside the idToken)
  // In our example because we have requested the following scopes      scope: 'openid profile email'
  // this is what is in the .idTokenPayload
  // This same info can also be extracted from the idToken by using some library API but the .parseHash()'s 
  // returns the javascript object whose .idTokenPayload property has all this neatly available
      // iss:"https://rahulmisra2000.auth0.com/"                                            // Always present
      // iat:1529727545                                                                     // Always present
      // exp:1529763545                                                                     // Always present
      // sub:"auth0|5b2d5aef52e65360e5dff35b"                                               // Always present
      // aud:"Qcq75xR4VjcLRzyUx0GjrMKDJE5dh7po"                                             // Always present

      // email:"rahulmisra2000@gmail.com"                                                   because  scope: email   was specified
      // email_verified:true                                                                because  scope: email   was specified
      // name:"rahulmisra2000@gmail.com"                                                    because  scope: profile was specified 
      // nickname:"rahulmisra2000"                                                          because  scope: profile was specified
      // nonce:"UV51J7PYirEdcUzUeFzmVEbst9reC-rN"                                           because  scope: profile was specified
      // picture:"https://s.gravatar.com/avatar/725bd805b8fffa980a
          // 84ccf51d74a484?s=480&r=pg&d=https%3A%2F%2Fcdn.auth0.com%2Favatars%2Fra.png"    because  scope: profile was specified

  
  
  
  // -----------------------------------------------------------------------------------------------------------
  // *** By calling the .userInfo() API, we can also get hold off the stuff returned by profile and email scopes 
  // -----------------------------------------------------------------------------------------------------------
  public getProfile(cb): void {
    const accessToken = localStorage.getItem('access_token');
    if (!accessToken) {
      throw new Error('Access token must exist to fetch profile');
    }

    const self = this;
    this.auth0.client.userInfo(accessToken, (err, profile) => {               // ANOTHER LIBRARY API   .userInfo()
      if (profile) {
        self.userProfile = profile;
      }
      cb(err, profile);
    });
  }
  // -----------------------------------------------------------------------------------------------------------
  
  private setSession(authResult): void {
    // Set the time that the access token will expire at
    const expiresAt = JSON.stringify((authResult.expiresIn * 1000) + new Date().getTime());
    localStorage.setItem('access_token', authResult.accessToken);
    localStorage.setItem('id_token', authResult.idToken);
    localStorage.setItem('expires_at', expiresAt);
  }

  public logout(): void {
    // Remove tokens and expiry time from localStorage
    localStorage.removeItem('access_token');
    localStorage.removeItem('id_token');
    localStorage.removeItem('expires_at');
    // Go back to the home route
    this.router.navigate(['/']);
  }

  public isAuthenticated(): boolean {
    // Check whether the current time is past the
    // access token's expiry time
    const expiresAt = JSON.parse(localStorage.getItem('expires_at') || '{}');
    return new Date().getTime() < expiresAt;
  }

}

