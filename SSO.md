### Function: `oAuthUrl`

#### Description
Generates an OAuth URL for user authentication. It creates a promise that returns the URL for initiating the OAuth flow with the specified parameters.

#### Parameters

- `oAuthParams: T.OAuthParams`: Object containing OAuth parameters such as client secret, redirect URI, etc.
- `state?: string`: An optional state parameter to be passed to OAuth for CSRF protection.
- `scopes?: string[]`: An optional array of scope strings for the OAuth flow.

#### Returns
- `Promise<{ url: string }>`: A promise that resolves with an object containing the URL to redirect the user for OAuth authentication.

#### Example Usage
```javascript
const params = {
  clientSecret: 'your-client-secret',
  redirectUri: 'your-redirect-uri',
  // other necessary OAuth parameters
};
const state = 'your-csrf-state';
const scopes = ['email', 'profile'];

oAuthUrl(params, state, scopes).then(({ url }) => {
  // Redirect user to this URL
  window.location.href = url;
});
```

---

### Function: `oAuthCallback`

#### Description
Handles the OAuth callback from the authentication service. It extracts the authorization code from the callback and retrieves user information based on that code.

#### Parameters

- `code: string`: The authorization code received from the OAuth provider.
- `oAuthParams: T.OAuthParams`: Object containing OAuth parameters used for the callback.

#### Returns
- `Promise<T.Profile>`: A promise that resolves with the user's profile information, including `firstName`, `lastName`, and `email`.

#### Example Usage
```javascript
const code = 'authorization-code-received';
const params = {
  clientSecret: 'your-client-secret',
  redirectUri: 'your-redirect-uri',
  // other necessary OAuth parameters
};

oAuthCallback(code, params).then(profile => {
  // Handle the received profile information
  console.log(profile);
});
```

---

### Function: `oAuthCallbackWithAuthentication`

#### Description
Completes the OAuth callback process and also handles user sign up or authentication based on the `isSignup` flag.

#### Parameters

- `code: string`: The authorization code received from the OAuth provider.
- `oAuthParams: T.OAuthParams`: Object containing OAuth parameters.
- `isSignup`: A boolean flag to indicate whether to sign up the user.
- `instance`: An instance identifier required during signup.

#### Returns
- `Promise<AuthenticationOutputPermission & T.Profile>`: A promise that resolves with the authentication or signup response including permissions and profile information.

#### Example Usage
```javascript
const code = 'authorization-code-received';
const params = {
  clientSecret: 'your-client-secret',
  redirectUri: 'your-redirect-uri',
  // other necessary OAuth parameters
};
const isSignup = true;
const instance = 'instance-identifier';

oAuthCallbackWithAuthentication(code, params, isSignup, instance).then(response => {
  // Handle the authentication/signup response
  console.log(response);
}).catch(error => {
  // Handle errors
  console.error(error);
});
```

---

**Note:** Replace `'your-client-secret'`, `'your-redirect-uri'`, `'authorization-code-received'`, and `'instance-identifier'` with actual values provided by your OAuth provider and application setup. Always ensure that your client secret and other sensitive information are securely stored and not exposed on the client side.
