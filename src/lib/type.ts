export enum AuthenticationType {
  password = 1,
  google = 2,
  github = 3,
}

export type AuthenticationServices =
  | "google"
  | "github"
  | "zoho"
  | "swissid"
  | "microsoft";

export interface Authentication {
  value: string;
  type: AuthenticationType;
}

export interface Profile {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  instance: { uuid: string };
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

export type RefreshOut = AuthenticationOut & Pick<Tokens, "accessToken">;

export type AuthorizeOut =
  | ErrorAuthorization
  | (Omit<TokenShape, "iat"> & { accessToken?: string });

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

export interface OAuthCallbackWithAuthenticationOptions {
  isSignup: boolean;
}

export enum UserStatus {
  active = 1,
  pending = 2,
  inactive = 3,
}

export interface ErrorAuthorization {
  body: any;
  status: number;
}

export interface TokenShape {
  id: string;
  instanceId: string;
  permissions: number[];
  iat: number;
}
