// this is the only part of the library that is Koa dependent
import Koa from "koa";

import * as Constants from "./constants";
import * as Utils from "./utils";
import UserManagementService from "./service";
import { Permission } from "./type";

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

    const {
      accessToken: newAccessToken,
      id,
      permissions,
      instanceId,
      email,
    } = r;

    if (newAccessToken) {
      //const accessToken = userManagement.getAccessToken(id);
      ctx.cookies.set(Constants.cookieValues.accessToken, newAccessToken);
    }

    ctx.state = { id, email, instanceId, permissions };
  };

export const isAuthenticated =
  (userManagement: UserManagementService) =>
  async (ctx: Koa.Context, next: Koa.Next) => {
    await isAuthenticatedNonMiddleware(userManagement)(ctx);

    if ("id" in ctx.state && "instanceId" in ctx.state) {
      return await next();
    }

    return;
  };

export const hasPermission = (permission: Permission) => async (ctx: any) => {
  const { permissions } = ctx.state;

  //  console.log("in", permission, permissions);

  if (
    !permissions ||
    !Array.isArray(permissions) ||
    !permissions.includes(permission)
  ) {
    ctx.status = 403;
    ctx.body = {
      error: "Forbidden",
      message:
        "You do not have the required permission to access this resource.",
    };
    return;
  }
};
