import * as Config from "./config";
import UserManagementService from "./lib";

const user = new UserManagementService(Config.token, Config.jwtSecret);

export default user;
