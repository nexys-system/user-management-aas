export enum AuthenticationType {
  password = 1,
  google = 2,
  github = 3,
}

export type AuthenticationServices = "google" | "github";

export interface Authentication {
  value: string;
  type: AuthenticationType;
}

export interface Profile {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
}

export interface Locale {
  country: string;
  lang: string;
}

export enum Permission {
  app = 1,
  admin = 2,
  superadmin = 3,
}

export interface AuthenticationOut {
  profile: Profile;
  locale: Locale;
  permissions: Permission[];
}

export interface Tokens {
  accessToken: string;
  refreshToken: string;
}

export interface OAuthParams {
  service: AuthenticationServices;
  clientId: string;
  secret: string;
  redirectUrl: string;
}
