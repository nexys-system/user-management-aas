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
  billing = 4
  // beyong 4, permissions are custom and depend on the instance
}

export interface AuthenticationOut<P extends Permission = Permission> {
  profile: Profile;
  locale: Locale;
  permissions: P[];
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

export interface TokenShape <P extends Permission = Permission> {
  id: string;
  email: string;
  instanceId: string;
  permissions: P[];
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

export type StateShape<P extends Permission = Permission> = Pick<
  TokenShape<P>,
  "id" | "email" | "instanceId" | "permissions"
>;
