import * as Config from "./config";
import UserManagementService, { Middleware } from "./lib";

const userManagement = new UserManagementService(
  Config.token,
  Config.jwtSecret
);

export const isAuthenticated = Middleware.isAuthenticated(userManagement);

export default userManagement;
