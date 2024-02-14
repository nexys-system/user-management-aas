import JWT from "jsonwebtoken";
import { urlPrefix, tokenValidityDefault } from "./constants.js";
import * as T from "./type.js";
import * as U from "./utils.js";
import { createActionPayload, decryptPayload } from "./action-payload.js";

export interface UserManagementOptions {
  secretKey?: string; // this secretkey will be used to create encrypted strings that are sent to the user typically for account activation or password reset, if not given it will be generated automatically
  tokenValidity?: number; // Number of seconds the JSON Web Token (JWT) is valid for.
  urlPrefix?: string; // Base URL to be prefixed to the paths
  notificationCallback?: (message: string) => Promise<void>; // ability to pass an object that will send a notification
  emailCallback?: (subject: string, body: string, to: string) => Promise<void>; // Function to handle sending emails, receives subject, body, and recipient's email address.
}

class UserManagementService<Permission extends T.Permission = T.Permission> {
  token: string;
  request: <A = any>(path: string, payload?: any) => Promise<A>;

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

  secretKey: string;

  notificationCallback?: (message: string) => Promise<void>;
  emailCallback?: (subject: string, body: string, to: string) => Promise<void>;

  constructor(
    token: string,
    jwtSecret:
      | string
      | { publicKey: string; privateKey: string; algorithm: JWT.Algorithm },

    options: UserManagementOptions = {}
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
    this.token = token;

    const jwtSecretOrPrivateKey =
      typeof jwtSecret === "string" ? jwtSecret : jwtSecret.privateKey;
    const algorithm: JWT.Algorithm | undefined =
      typeof jwtSecret !== "string" ? jwtSecret.algorithm : undefined;

    this.secretKey = options.secretKey || U.generateSecretKey();

    this.getAccessToken = U.getAccessToken(
      {
        jwtSecretOrPrivateKey,
        algorithm,
      },
      options.tokenValidity || tokenValidityDefault
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

    if (options.emailCallback) {
      this.emailCallback = options.emailCallback;
    }
  }

  signup = async (
    profile: Pick<T.Profile, "firstName" | "lastName" | "email">,
    authentication: T.Authentication,
    instance: { uuid?: string; name?: string } = this.instance,
    emailMessage?: {
      subject: string;
      body: (activationToken: string) => string;
    }
  ): Promise<
    T.AuthenticationOut<Permission> & T.Tokens & { activationToken: string }
  > => {
    const response = await this.request<
      T.AuthenticationOut<Permission> &
        T.Tokens & {
          activationToken: string;
        }
    >("/signup", {
      profile,
      instance,
      authentication,
    });

    const accessToken = this.getAccessToken(
      response.profile.id,
      response.profile.email,
      response.profile.instance.uuid,
      response.permissions
    );

    // send notification that user was created
    if (this.notificationCallback) {
      this.notificationCallback("signup: " + JSON.stringify(response.profile));
    }

    if (this.emailCallback && emailMessage) {
      this.emailCallback(
        emailMessage.subject,
        emailMessage.body(response.activationToken),
        response.profile.email
      );
    }

    return {
      ...response,
      accessToken,
    };
  };

  authenticate = async (
    authentication: T.Authentication,
    instance?: { uuid: string }, // if the instance of the user differs from the main instance (multi tenant setup)
    email?: string,
    ip?: string
  ): Promise<T.AuthAnd2FAOut<Permission>> => {
    const r = await this.request<
      | (T.AuthenticationOut<Permission> & { refreshToken: string })
      | T.AuthenticationOut2FA
    >("/authenticate", {
      authentication,
      email,
      ip,
      instanceUuid: instance?.uuid,
    });

    // if 2FA is required the authentication process is aborted and a different response is returned, so the user can resume the authentiation journey, ie. pass the TOTP code
    // authenticate2FA will then need to be called
    if (U.isAuthenticationOut2FA(r)) {
      return { action: r.action, payload: r.payload };
    }

    return this.toAuthOut(r);
  };

  // function to resume and complete the 2FA process
  authenticate2FA = async (code: string, payload: string, ip: string) => {
    const r = await this.request<
      T.AuthenticationOut<Permission> & { refreshToken: string }
    >("/authenticate2FA", {
      code,
      payload,
      ip,
    });

    return this.toAuthOut(r);
  };

  toAuthOut = ({
    profile,
    permissions,
    locale,
    refreshToken,
  }: T.AuthenticationOut<Permission> & {
    refreshToken: string;
  }): T.AuthenticationOut<Permission> & T.Tokens => {
    const accessToken = this.getAccessToken(
      profile.id,
      profile.email,
      profile.instance.uuid,
      permissions
    );

    return { profile, permissions, locale, refreshToken, accessToken };
  };

  userByEmail = async (
    email: string,
    instance?: { uuid: string }
  ): Promise<{
    profile: T.Profile;
    status: T.UserStatus;
    locale: T.Locale;
    UserAuthentication?: T.UserAuthentication[];
  }> => this.request("/user-by-email", { email, instance });

  /**
   * Initiates the password recovery process for users by accepting their registered email. If the email is found in the system, a password reset token is sent to it.
   * @returns token
   */
  passwordForgot = async (
    email: string,
    emailMessage?: {
      subject: string;
      body: (token: string) => string;
    }
  ) => {
    const { profile } = await this.userByEmail(email, this.instance);
    const token = createActionPayload(
      profile.id,
      { uuid: profile.instance.uuid },
      "RESET_PASSWORD",
      this.secretKey
    );

    // send email with token to user
    this.emailCallback &&
      emailMessage &&
      this.emailCallback(
        emailMessage.subject,
        emailMessage.body(token),
        profile.email
      );

    return token;
  };

  /**
   *  Completes the password recovery process by allowing users to set a new password using a valid reset token received via email.
   */
  passwordReset = async (
    token: string,
    newPassword: string
  ): Promise<{ success: boolean; updated: number }> => {
    const { id } = decryptPayload(token, this.secretKey, "RESET_PASSWORD");

    return this.changePassword(id, newPassword);
  };

  refresh = async (refreshToken: string): Promise<T.RefreshOut> => {
    const r = await this.request<T.AuthenticationOut<Permission>>("/refresh", {
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

  statusChange = async (uuid: string, status: T.UserStatus) =>
    this.request<{ response: boolean }>("/status/change", {
      uuid,
      status,
    });

  profile = async (uuid: string, instance: { uuid: string }) =>
    this.request("/profile", { uuid, instanceUuid: instance.uuid });

  profileUpdate = async (
    uuid: string,
    profile: Pick<T.Profile, "firstName" | "lastName">
  ) => this.request("/profile/update", { uuid, profile });

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
    }: Partial<T.OAuthCallbackWithAuthenticationOptions>,
    ip?: string
  ): Promise<T.AuthenticationOut<Permission> & T.Tokens> => {
    const { firstName, lastName, email } = await this.oAuthCallback(
      code,
      oAuthParams
    );

    const type = U.authenticationServiceToType(oAuthParams.service);

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

      if ("name" in instance) {
        throw Error("Login: instance name cannot be given");
      }

      if (!("uuid" in instance)) {
        throw Error("Login: instance uuid must be given");
      }

      const r = await this.authenticate(
        { type, value: email },
        { uuid: instance.uuid || "" },
        undefined,
        ip
      );

      if (U.isAuthenticationOut2FA(r)) {
        throw Error("signup returns 2fa, cant happen");
      }

      return r;
    } catch (err) {
      throw Error((err as Error).message);
    }
  };

  //

  changePassword = async (
    uuid: string,
    password: string,
    oldPassword?: string
  ) =>
    this.request("/profile/password/change", {
      uuid,
      password,
      oldPassword,
    });

  changeEmail = async (uuid: string, email: string) =>
    this.request("/profile/email/change", {
      uuid,
      email,
    });

  // CRUD
  list = async () => this.request("/admin/list");

  detail = async (uuid: string) => this.request("/admin/detail", { uuid });

  insert = async (
    profile: T.Profile,
    locale?: T.Locale,
    status?: T.UserStatus
  ): Promise<{ uuid: string }> =>
    this.request("/admin/insert", { profile, locale, status });

  update = async (
    uuid: string,
    data: Partial<T.UserCore> & { locale?: T.Locale }
  ) => this.request("/admin/update", { uuid, data });

  deleteById = async (uuid: string): Promise<boolean> =>
    this.request("/admin/delete", { uuid });

  permissionList = async () => this.request("/admin/permission/list");

  userPermissionList = async (
    uuid: string
  ): Promise<
    {
      permission: Permission;
      userPermission: { uuid: string };
      logDateAdded: string;
    }[]
  > => this.request("/admin/permission/user/list", { uuid });

  /**
   * toggles (inserts/deletes) a permission for a user
   *
   * @param uuid: The UUID of the user.
   * @param permission: the permission to be toggled
   */
  userPermissionToggle = async (
    uuid: string,
    permission: Permission
  ): Promise<{ success: true; deleted: 1 } | { uuid: string }> =>
    this.request("/admin/permission/user/toggle", { uuid, permission });

  deleteByUuid = async (uuid: string) => this.request("/delete", { uuid });

  /**
   * Inserts an action log entry. This function is used to record user actions in the system.
   * It accepts multiple attributes, including a UUID for the user, a URL or path that was observed,
   * an action that was performed, and an additional value related to the action.
   *
   * @param uuid: The UUID of the user.
   * @param url: (Optional) The URL or path that was observed during the action.
   * @param action: (Optional) A string representing the action performed by the user.
   * @param value: (Optional) Additional value or information related to the action.
   */
  actionLogInsert = async (
    uuid: string,
    { url, action, value }: { url?: string; action?: string; value?: string }
  ) => this.request("/action-log/insert", { uuid, url, action, value });

  /**
   * Retrieves a list of key-value pairs from the user management backend.
   *
   * This function makes an HTTP request to the "/key-value/list" endpoint.
   * It can be used to fetch key-value pairs associated with a specific user or all pairs
   * within the instance. If a 'user' object with a UUID is provided in the filters,
   * the function returns pairs associated with that user. Otherwise, it returns
   * all key-value pairs in the instance.
   *
   * @param {Object} filters - Optional filters to refine the results. Can include a
   *                           'user' object with a UUID to fetch pairs for a specific user.
   * @returns {Promise} A promise resolving to the list of key-value pairs.
   */
  keyValueList = (filters: {
    user?: { uuid: string };
  }): Promise<
    { uuid: string; key: string; value: string; logDateAdded: string }[]
  > => this.request("/key-value/list", filters);

  /**
   * Inserts a new key-value pair into the user management backend.
   *
   * This function sends a POST request to the "/key-value/insert" endpoint.
   * It is used to add a new key-value pair, either associated with a specific user
   * (if a 'user' object with a UUID is provided) or to the instance in general.
   * The 'key' and 'value' fields are required for creating the pair.
   *
   * @param {Object} data - Data for the new key-value pair. Must contain 'key' and 'value'.
   *                        Optionally, a 'user' object with a UUID can be included to associate
   *                        the pair with a specific user.
   * @returns {Promise} A promise that resolves when the insertion is complete.
   */
  keyValueInsert = (data: {
    key: string;
    value: string;
    user?: { uuid: string };
  }): Promise<{ uuid: string }> => this.request("/key-value/insert", data);

  /**
   * Deletes a key-value pair from the user management backend.
   *
   * This function sends a request to the "/key-value/delete" endpoint for removing
   * a specific key-value pair, identified by its UUID. This is used to delete pairs
   * that are either associated with a specific user or the instance as a whole.
   * The function requires an object containing the 'uuid' of the pair to be deleted.
   *
   * @param {Object} data - The object containing the 'uuid' of the key-value pair to be deleted.
   * @returns {Promise} A promise that resolves when the deletion is completed.
   */
  keyValueDelete = (data: {
    uuid: string;
  }): Promise<{ success: boolean; updated: number }> =>
    this.request("/key-value/delete", data);

  /**
   * Retrieves a list of files from the backend.
   *
   * This function makes an HTTP request to the "/file/list" endpoint.
   * It can be used to fetch a list of files, optionally filtered based on the 'user' object.
   * If a 'user' object with a UUID is provided in the filters, it returns files associated
   * with that specific user. Otherwise, it returns all files.
   *
   * @param {Object} filters - Optional filters to refine the file list. Can include a
   *                           'user' object with a UUID to fetch files for a specific user.
   * @returns {Promise<Array>} A promise resolving to an array of file objects, each including
   *                           UUID, filename, content type, size, and the date added.
   */
  fileList = (filters: {
    user?: { uuid: string };
  }): Promise<
    {
      uuid: string;
      filename: string;
      contentType?: string;
      size?: number;
      logDateAdded: string;
    }[]
  > => this.request("/file/list", filters);

  /**
   * Inserts a new file into the backend.
   *
   * This function sends a POST request to the "/file/insert" endpoint.
   * It is used to add a new file with a 'filename' and optional 'fileContent'.
   * A 'user' object with a UUID can also be provided to associate the file with a specific user.
   *
   * @param {Object} data - Data for the new file. Must contain 'filename'.
   *                        Optionally, 'fileContent' and a 'user' object with a UUID can be included.
   * @returns {Promise<Object>} A promise resolving to an object containing the UUID of the newly added file.
   */
  fileInsert = (data: {
    filename: string;
    fileContent?: string;
    user?: { uuid: string };
  }): Promise<{ uuid: string }> => this.request("/file/insert", data);

  /**
   * Deletes a specific file from the backend.
   *
   * This function sends a request to the "/file/delete" endpoint to remove a file,
   * identified by its UUID. It is used to delete files from the backend storage.
   *
   * @param {Object} data - The object containing the 'uuid' of the file to be deleted.
   * @returns {Promise<Object>} A promise resolving to an object indicating the success
   *                             of the operation and the number of records updated.
   */
  fileDelete = (data: {
    uuid: string;
  }): Promise<{ success: boolean; updated: number }> =>
    this.request("/file/delete", data);

  /**
   * Serves a requested file as an ArrayBuffer.
   *
   * This asynchronous function is designed to handle requests for specific files identified by their UUID.
   * When called with a UUID, it retrieves the corresponding file from the backend and serves it as an ArrayBuffer.
   * This is particularly useful for delivering binary data, like images or documents, to the client.
   * The function ensures that the file associated with the given UUID is retrieved and then
   * converts it into an ArrayBuffer format, which is suitable for transmission over network protocols.
   *
   * @param {string} uuid - The UUID of the file to be served.
   * @returns {Promise<ArrayBuffer>} A promise that resolves to the file data in ArrayBuffer format,
   *                                  or rejects in case of any errors during file retrieval or conversion.
   */
  fileServe = async (uuid: string): Promise<ArrayBuffer> => {
    const response = await U.requestToResponse(
      this.token,
      urlPrefix + "/file/serve",
      { uuid }
    );

    if (response.status !== 200) {
      throw Error(await response.text());
    }

    return response.arrayBuffer();
  };

  // Retrieves a list of system logs based on the provided filters.
  // Filters can include an instance identified by its UUID or a user identified by their UUID.
  // Returns a promise that resolves to an array of SystemLog objects.
  systemLogList = (filters: {
    instance?: { uuid: string };
    user?: { uuid: string };
  }): Promise<T.SystemLog[]> => this.request("/system-log/list", filters);

  // Inserts a new system log entry into the database.
  // The function takes a system log object, excluding its UUID, as this is typically generated by the system.
  // Returns a promise that resolves to an object containing the UUID of the newly created system log entry.
  systemLogInsert = (
    data: Omit<T.SystemLog, "uuid" | "logDateAdded">
  ): Promise<{ uuid: string }> => this.request("/system-log/insert", data);

  // Deletes a system log entry identified by its UUID.
  // The function takes an object containing the UUID of the system log to be deleted.
  // Returns a promise that resolves to an object indicating the operation's success status and the number of updated (deleted) entries.
  systemLogDelete = (data: {
    uuid: string;
  }): Promise<{ success: boolean; updated: number }> =>
    this.request("/system-log/delete", data);
}

export default UserManagementService;
