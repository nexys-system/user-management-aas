// see https://stackoverflow.com/a/74112582/1659569
/// <reference lib="dom" />
import crypto from "crypto";
import JWT from "jsonwebtoken";
import * as T from "./type";

export const jwtAlgorithmDefault: JWT.Algorithm = "RS256";

export const requestToResponse = async (
  token: string,
  url: string,
  payload: any
): Promise<Response> => {
  const body = JSON.stringify(payload);
  const headers = {
    Authorization: "Bearer " + token,
    "content-type": "application/json",
  };

  return fetch(url, {
    method: "POST",
    body,
    headers,
  });
};

export const request =
  (token: string, urlPrefix: string) =>
  async <A = any>(path: string, payload: any): Promise<A> => {
    const url = urlPrefix + path;
    const response = await requestToResponse(token, url, payload);

    if (response.status !== 200) {
      const t = await response.text();

      throw Error(t);
    }

    return response.json();
  };

export const getAccessToken =
  (
    {
      jwtSecretOrPrivateKey,
      algorithm,
    }: { jwtSecretOrPrivateKey: string; algorithm?: JWT.Algorithm },
    tokenValidity: number
  ) =>
  (id: string, email: string, instanceId: string, permissions: number[]) => {
    const exp = Math.floor(new Date().getTime() / 1000 + tokenValidity);

    const tokenContent: Omit<T.TokenShape, "iat"> = {
      id,
      email,
      instanceId,
      permissions,
      exp,
    };

    const options: JWT.SignOptions = {};

    if (algorithm) {
      options.algorithm = algorithm;
    }

    return JWT.sign(tokenContent, jwtSecretOrPrivateKey, options);
  };

export const verifyAccessToken = (
  token: string,
  jwtSecret: string,
  algorithm?: JWT.Algorithm
): T.TokenShape => {
  const options: JWT.VerifyOptions | undefined = algorithm
    ? { algorithms: [algorithm] }
    : undefined;

  return JWT.verify(token, jwtSecret, options) as T.TokenShape;
};

export const isErrorAuthorization = (
  a: T.ErrorAuthorization | any
): a is T.ErrorAuthorization => {
  const { body, status } = a;

  const statusCondition: boolean = typeof status === "number";

  const bodyCondition: boolean = typeof body === "object";

  return bodyCondition && statusCondition;
};

export const authorize =
  (
    refresh: (refreshtoken: string) => Promise<T.RefreshOut>,
    getAccessToken: (
      id: string,
      email: string,
      instanceId: string,
      permissions: number[]
    ) => string,
    jwtSecretOrPublicKey: string,
    tokenValidity: number,
    algorithm?: JWT.Algorithm
  ) =>
  async (
    accessToken?: string,
    refreshToken?: string
  ): Promise<T.AuthorizeOut> => {
    if (!accessToken) {
      const status = 401;
      const body = { error: "access token expected" };
      return { status, body };
    }

    try {
      const verified = verifyAccessToken(
        accessToken,
        jwtSecretOrPublicKey,
        algorithm
      );

      if (typeof verified === "string") {
        const status = 401;
        const body = { error: "could not read token" };
        return { status, body };
      }

      const { id, email, instanceId, permissions, iat } = verified;

      if (!iat || typeof iat !== "number") {
        const status = 401;
        const body = { error: "token does not contain iat" };
        return { status, body };
      }

      // get current time
      const ts = new Date().getTime() / 1000;

      if (ts > tokenValidity + iat && refreshToken) {
        try {
          //console.log('refreshgin');
          const r = await refresh(refreshToken);

          if (!r.profile) {
            const status = 403;
            const body = { error: "could not refresh token" };
            return { status, body };
          }

          const accessToken = getAccessToken(
            r.profile.id,
            r.profile.email,
            r.profile.instance.uuid,
            r.permissions
          );
          return { accessToken, id, email, instanceId, permissions };
        } catch (err) {
          const status = 403;
          const body = { error: "something went wrong while refreshing token" };
          return { status, body };
        }
      }

      return { id, email, instanceId, permissions };
    } catch (err) {
      const status = 401;
      const body = { error: (err as Error).message };
      return { status, body };
    }
  };

export const isAuthService = (s: string): s is T.AuthenticationServices =>
  ["google", "github", "zoho", "swissid", "microsoft"].includes(s);

export const authenticationServiceToType = (
  service: T.AuthenticationServices
): T.AuthenticationType => {
  switch (service) {
    case "github":
      return T.AuthenticationType.github;
    default:
      return T.AuthenticationType.google;
  }
};

export const generateSecretKey = (length: number = 16): string =>
  crypto.randomBytes(length).toString("hex");

export const isAuthenticationOut2FA = (r: any): r is T.AuthenticationOut2FA => {
  return (
    "action" in r &&
    r.action === "2FA" &&
    "payload" in r &&
    typeof r.payload === "string"
  );
};
