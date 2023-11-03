export enum AuthenticationType {
  password = 1,
  google = 2,
  github = 3,
  // linkedin = 4,
  // microsoft = 5,
  // ibm = 6,
  ethereum = 7,
  // twitter = 8,
  // swissId = 9,
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

export interface Profile extends UserCore {
  id: string;
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
  | (Omit<TokenShape, "iat" | "exp"> & { accessToken?: string });

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
  instance: { uuid: string };
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
  email: string;
  instanceId: string;
  permissions: number[];
  iat: number;
  exp: number;
}

export interface UserCore {
  email: string;
  firstName: string;
  lastName: string;
}

export interface User extends Partial<UserCore> {
  uuid: string;
  locale: Locale;
}

export type Action = "SET_ACTIVE" | "RESET_PASSWORD" | "CHANGE_EMAIL" | "2FA";

export interface ActionPayload {
  id: string;
  instance: { uuid: string };
  action: Action;
  issued: number;
  expires: number;
}

export interface UserAuthentication {
  uuid: string;
  value: string;
  isEnabled: boolean;
  type: AuthenticationType;
}
