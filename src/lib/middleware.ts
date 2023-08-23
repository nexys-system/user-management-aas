// this is the only part of the library that is Koa dependent
import Koa from "koa";

import * as Constants from "./constants";
import * as Utils from "./utils";
import UserManagementService from "./service";

export const isAuthenticatedNonMiddleware =
  (userManagement: UserManagementService) => async (ctx: Koa.Context) => {
    // get access and refresh tokens
    const accessToken: string | undefined =
      ctx.cookies.get(Constants.cookieValues.accessToken) ||
      ctx.headers["authorization"]?.slice(7);
    const refreshToken = ctx.cookies.get(Constants.cookieValues.refreshToken);

    const r = await userManagement.authorize(accessToken, refreshToken);

    if (Utils.isErrorAuthorization(r)) {
      ctx.status = r.status;
      ctx.body = r.body;
      return;
    }

    const { accessToken: newAccessToken, id, permissions, instanceId } = r;

    if (newAccessToken) {
      //const accessToken = userManagement.getAccessToken(id);
      ctx.cookies.set(Constants.cookieValues.accessToken, newAccessToken);
    }

    ctx.state = { id, instanceId, permissions };
  };

export const isAuthenticated =
  (userManagement: UserManagementService) =>
  async (ctx: Koa.Context, next: Koa.Next) => {
    await isAuthenticatedNonMiddleware(userManagement)(ctx);

    return await next();
  };
