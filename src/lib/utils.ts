// see https://stackoverflow.com/a/74112582/1659569
/// <reference lib="dom" />
import JWT from "jsonwebtoken";
import * as T from "./type";

export const jwtAlgorithmDefault: JWT.Algorithm = "RS256";

export const request =
  (token: string, urlPrefix: string) =>
  async <A = any>(path: string, payload: any): Promise<A> => {
    const body = JSON.stringify(payload);
    const headers = {
      Authorization: "Bearer " + token,
      "content-type": "application/json",
    };

    const url = urlPrefix + path;

    const r = await fetch(url, {
      method: "POST",
      body,
      headers,
    });

    if (r.status !== 200) {
      const t = await r.text();

      throw Error(t);
    }

    console.log(r.status);

    return r.json();
  };

export const getAccessToken =
  (jwtSecretOrPrivateKey: string, algorithm?: JWT.Algorithm) =>
  (id: string, email: string, instanceId: string, permissions: number[]) => {
    const tokenContent: Omit<T.TokenShape, "iat"> = {
      id,
      email,
      instanceId,
      permissions,
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
          return { accessToken, id, instanceId, permissions };
        } catch (err) {
          const status = 403;
          const body = { error: "something went wrong while refreshing token" };
          return { status, body };
        }
      }

      return { id, instanceId, permissions };
    } catch (err) {
      const status = 401;
      const body = { error: (err as Error).message };
      return { status, body };
    }
  };

export const isAuthService = (s: string): s is T.AuthenticationServices =>
  ["google", "github", "zoho", "swissid", "microsoft"].includes(s);
