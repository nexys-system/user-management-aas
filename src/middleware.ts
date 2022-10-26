import Koa from "koa";
import JWT from "jsonwebtoken";
import userManagement from "./user-management";
import { Constants } from "./lib";
import * as Config from "./config";

export const isAuthenticated = async (ctx: Koa.Context, next: Koa.Next) => {
  const accessToken = ctx.cookies.get(Constants.cookieValues.accessToken);
  const refreshToken = ctx.cookies.get(Constants.cookieValues.refreshToken);

  if (!accessToken) {
    ctx.status = 401;
    ctx.body = { error: "access token expected" };
    return;
  }

  const verified = JWT.verify(accessToken, "mysecret");

  if (typeof verified === "string") {
    ctx.status = 401;
    ctx.body = { error: "could not read token" };
    return;
  }

  const { id, iat } = verified;

  if (!iat || typeof iat !== "number") {
    ctx.status = 401;
    ctx.body = { error: "token does not contain iat" };
    return;
  }

  const ts = new Date().getTime() / 1000;

  if (ts > Config.tokenValidity + iat && refreshToken) {
    try {
      //console.log('refreshgin');
      const r = await userManagement.refresh(refreshToken);

      if (!r.profile) {
        ctx.status = 403;
        ctx.body = { error: "could not refresh token" };
        return;
      }

      const accessToken = userManagement.getAccessToken(r.profile.uuid);
      ctx.cookies.set(Constants.cookieValues.accessToken, accessToken);
    } catch (err) {
      ctx.status = 403;
      ctx.body = { error: "something went wrong while refreshing token" };
      return;
    }
  }

  ctx.state = { id };

  return await next();
};
