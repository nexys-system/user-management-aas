import { urlPrefix } from "./constants";
import * as T from "./type";
import * as U from "./utils";

const authenticationServiceToType = (
  service: T.AuthenticationServices
): T.AuthenticationType => {
  switch (service) {
    case "github":
      return T.AuthenticationType.github;
    default:
      return T.AuthenticationType.google;
  }
};

class UserManagementService {
  request: <A = any>(path: string, payload: any) => Promise<A>;
  getAccessToken: (id: string) => string;

  constructor(token: string, jwtSecret: string) {
    this.request = U.request(token, urlPrefix);
    this.getAccessToken = U.getAccessToken(jwtSecret);
  }

  signup = async (
    profile: Pick<T.Profile, "firstName" | "lastName" | "email">,
    authentication: T.Authentication
  ): Promise<T.AuthenticationOut & T.Tokens> => {
    const r = await this.request<
      T.AuthenticationOut & { refreshToken: string }
    >("/signup", {
      profile,
      authentication,
    });

    const accessToken = this.getAccessToken(r.profile.uuid);

    return {
      ...r,
      accessToken,
    };
  };

  authenticate = async (
    authentication: T.Authentication,
    email?: string,
    ip?: string
  ): Promise<T.AuthenticationOut & T.Tokens> => {
    const r = await this.request<
      T.AuthenticationOut & { refreshToken: string }
    >("/authenticate", { authentication, email, ip });

    const accessToken = this.getAccessToken(r.profile.uuid);

    return { ...r, accessToken };
  };

  statusChange = async (uuid: string, status: T.UserStatus) =>
    this.request<{ response: boolean }>("/status/change", {
      uuid,
      status,
    });

  refresh = async (
    refreshToken: string
  ): Promise<T.AuthenticationOut & Pick<T.Tokens, "accessToken">> => {
    const r = await this.request<T.AuthenticationOut>("/refresh", {
      refreshToken,
    });

    const accessToken = this.getAccessToken(r.profile.uuid);

    return { ...r, accessToken };
  };

  logout = async (refreshToken: string) =>
    this.request("/logout", { refreshToken });

  logoutAll = async (uuid: string) => this.request("/logout/all", { uuid });

  // oauth
  oAuthUrl = async (
    oAuthParams: T.OAuthParams,
    state?: string,
    scopes?: string[]
  ): Promise<{ url: string }> =>
    this.request("/oauth/url", { oAuthParams, state, scopes });

  oAuthCallback = async (
    code: string,
    oAuthParams: T.OAuthParams
  ): Promise<Pick<T.Profile, "firstName" | "lastName" | "email">> =>
    this.request("/oauth/callback", { oAuthParams, code });

  oAuthCallbackWithAuthentication = async (
    code: string,
    oAuthParams: T.OAuthParams,
    { isSignup }: Partial<T.OAuthCallbackWithAuthenticationOptions>
  ): Promise<T.AuthenticationOut & T.Tokens> => {
    const profile = await this.oAuthCallback(code, oAuthParams);

    const type = authenticationServiceToType(oAuthParams.service);

    try {
      if (isSignup) {
        const r = await this.signup(profile, {
          type,
          value: profile.email,
        });

        await this.statusChange(r.profile.uuid, T.UserStatus.active);

        return r;
      }

      return this.authenticate({ type, value: profile.email });
    } catch (err) {
      throw Error((err as Error).message);
    }
  };
}

export default UserManagementService;
