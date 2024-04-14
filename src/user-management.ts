import * as Config from "./config.js";
import UserManagementService, { Middleware } from "./lib/index.js";

const userManagement = new UserManagementService(
  Config.token,
  Config.jwtSecret
);

export const isAuthenticated = Middleware.isAuthenticated(userManagement);

export default userManagement;
