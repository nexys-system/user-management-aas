import { urlPrefix } from "./constants";
import * as T from "./type";
import * as U from "./utils";

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
  ): Promise<{
    uuid: string;
    token: string;
    authentication: { uuid: string };
  }> => {
    const payload = {
      profile,
      authentication,
    };

    return this.request("/signup", payload);
  };

  authenticate = (
    authentication: T.Authentication,
    email?: string,
    ip?: string
  ): Promise<T.AuthenticationOut & { refreshToken: string }> =>
    this.request("/authenticate", { authentication, email, ip });

  refresh = async (refreshToken: string): Promise<T.AuthenticationOut> =>
    this.request("/refresh", { refreshToken });

  deleteRefreshToken = async (refreshToken: string) =>
    this.request("/refresh/delete", { refreshToken });

  deleteAllToken = async (uuid: string) =>
    this.request("/refresh/delete/all", { uuid });

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
