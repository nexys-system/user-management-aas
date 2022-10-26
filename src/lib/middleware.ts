// this is the only part of the library that is Koa dependent
import Koa from "koa";

import * as Constants from "./constants";
import * as Utils from "./utils";
import UserManagementService from "./service";

export const isAuthenticated =
  (userManagement: UserManagementService) =>
  async (ctx: Koa.Context, next: Koa.Next) => {
    const accessToken = ctx.cookies.get(Constants.cookieValues.accessToken);
    const refreshToken = ctx.cookies.get(Constants.cookieValues.refreshToken);

    const r = await userManagement.authorize(accessToken, refreshToken);

    if (Utils.isErrorAuthorization(r)) {
      ctx.status = r.status;
      ctx.body = r.body;
      return;
    }

    const { accessToken: newAccessToken, id } = r;

    if (newAccessToken) {
      const accessToken = userManagement.getAccessToken(id);
      ctx.cookies.set(Constants.cookieValues.accessToken, accessToken);
    }

    ctx.state = { id };

    return await next();
  };
