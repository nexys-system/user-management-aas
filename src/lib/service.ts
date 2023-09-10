import JWT from "jsonwebtoken";
import { urlPrefix, tokenValidityDefault } from "./constants";
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
  getAccessToken: (
    id: string,
    email: string,
    instanceId: string,
    permissions: number[]
  ) => string;
  authorize: (
    accessToken?: string,
    refreshToken?: string
  ) => Promise<T.AuthorizeOut>;

  instance: { uuid: string };
  product: { id: number };

  notificationCallback?: (message: string) => Promise<void>

  constructor(
    token: string,
    jwtSecret:
      | string
      | { publicKey: string; privateKey: string; algorithm: JWT.Algorithm },
    options: {
      tokenValidity?: number;
      urlPrefix?: string;
      notificationCallback?: (message: string) => Promise<void> // ability to pass an object that will send a notification
    } = {}
  ) {
    const tokenDecoded = JWT.decode(token);

    if (!tokenDecoded || typeof tokenDecoded === "string") {
      throw Error("token could not be decoded");
    }

    if (!("instance" in tokenDecoded && "product" in tokenDecoded)) {
      throw Error("user management token: wrong shape");
    }

    this.instance = { uuid: tokenDecoded.instance };
    this.product = { id: tokenDecoded.product };
    this.request = U.request(token, options.urlPrefix || urlPrefix);
    this.getAccessToken = U.getAccessToken(
      typeof jwtSecret === "string" ? jwtSecret : jwtSecret.privateKey,
      typeof jwtSecret !== "string" ? jwtSecret.algorithm : undefined
    );
    this.authorize = U.authorize(
      this.refresh,
      this.getAccessToken,
      typeof jwtSecret === "string" ? jwtSecret : jwtSecret.publicKey,
      options.tokenValidity || tokenValidityDefault,
      typeof jwtSecret !== "string" ? jwtSecret.algorithm : undefined
    );

    // set notification callback function
    if (options.notificationCallback) {
      this.notificationCallback = options.notificationCallback;
    }
  }

  signup = async (
    profile: Pick<T.Profile, "firstName" | "lastName" | "email">,
    authentication: T.Authentication,
    instance: { uuid: string } = this.instance
  ): Promise<T.AuthenticationOut & T.Tokens> => {
    const r = await this.request<
      T.AuthenticationOut & { refreshToken: string }
    >("/signup", {
      profile,
      instance,
      authentication,
    });

    const accessToken = this.getAccessToken(
      r.profile.id,
      r.profile.email,
      instance.uuid,
      r.permissions
    );

    // send notification that user was created
    if (this.notificationCallback) {
      this.notificationCallback("signup: " + JSON.stringify(r.profile));
    }

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

    const accessToken = this.getAccessToken(
      r.profile.id,
      r.profile.email,
      r.profile.instance.uuid,
      r.permissions
    );

    return { ...r, accessToken };
  };

  statusChange = async (uuid: string, status: T.UserStatus) =>
    this.request<{ response: boolean }>("/status/change", {
      uuid,
      status,
    });

  refresh = async (refreshToken: string): Promise<T.RefreshOut> => {
    const r = await this.request<T.AuthenticationOut>("/refresh", {
      refreshToken,
    });

    const accessToken = this.getAccessToken(
      r.profile.id,
      r.profile.email,
      r.profile.instance.uuid,
      r.permissions
    );

    return { ...r, accessToken };
  };

  logout = async (uuid: string, refreshToken: string) =>
    this.request("/logout", { uuid, refreshToken });

  logoutAll = async (uuid: string) => this.request("/logout/all", { uuid });

  profile = async (uuid: string) => this.request("/profile", { uuid });

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
    {
      isSignup,
      instance = this.instance,
    }: Partial<T.OAuthCallbackWithAuthenticationOptions>
  ): Promise<T.AuthenticationOut & T.Tokens> => {
    const { firstName, lastName, email } = await this.oAuthCallback(
      code,
      oAuthParams
    );

    const type = authenticationServiceToType(oAuthParams.service);

    try {
      if (isSignup) {
        if (!instance) {
          throw Error("for signup, instance must be given/defined");
        }

        const response = await this.signup(
          { firstName, lastName, email },
          {
            type,
            value: email,
          },
          instance
        );

        await this.statusChange(response.profile.id, T.UserStatus.active);

        return response;
      }

      return this.authenticate({ type, value: email });
    } catch (err) {
      throw Error((err as Error).message);
    }
  };
}

export default UserManagementService;
