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

interface OAuthCallbackWithAuthenticationOptions {
  isSignup: boolean;
}

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
  ): Promise<
    {
      uuid: string;
      authentication: { uuid: string };
    } & T.Tokens
  > => {
    const r = await this.request<{
      uuid: string;
      token: string;
      authentication: { uuid: string };
    }>("/signup", {
      profile,
      authentication,
    });

    const accessToken = this.getAccessToken(r.uuid);

    return {
      uuid: r.uuid,
      authentication: r.authentication,
      accessToken,
      refreshToken: r.token,
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

    const accessToken = this.getAccessToken(r.profile.id);

    return { ...r, accessToken };
  };

  oAuthCallbackWithAuthentication = async (
    code: string,
    oAuthParams: T.OAuthParams,
    { isSignup }: Partial<OAuthCallbackWithAuthenticationOptions>
  ): Promise<T.AuthenticationOut & T.Tokens> => {
    const profile = await this.oAuthCallback(code, oAuthParams);

    const type = authenticationServiceToType(oAuthParams.service);

    try {
      if (isSignup) {
        const r = await this.signup(profile, {
          type,
          value: profile.email,
        });

        return {
          profile: { ...profile, id: r.uuid },
          locale: { country: "", lang: "" },
          permissions: [],
          accessToken: r.accessToken,
          refreshToken: r.refreshToken,
        };
      }

      return this.authenticate({ type, value: profile.email });
    } catch (err) {
      throw Error((err as Error).message);
    }
  };

  refresh = async (
    refreshToken: string
  ): Promise<T.AuthenticationOut & Pick<T.Tokens, "accessToken">> => {
    const r = await this.request<T.AuthenticationOut>("/refresh", {
      refreshToken,
    });

    const accessToken = this.getAccessToken(r.profile.id);

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
}

export default UserManagementService;
