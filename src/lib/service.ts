import JWT from "jsonwebtoken";
import { urlPrefix, tokenValidityDefault } from "./constants.js";
import * as T from "./type.js";
import * as U from "./utils.js";
import { createActionPayload, decryptPayload } from "./action-payload.js";

export interface UserManagementOptions {
  secretKey?: string; // this secretkey will be used to create encrypted strings that are sent to the user typically for account activation or password reset, if not given it will be generated automatically
  tokenValidity?: number;
  urlPrefix?: string;
  notificationCallback?: (message: string) => Promise<void>; // ability to pass an object that will send a notification
  emailCallback?: (subject: string, body: string, to: string) => Promise<void>;
}

class UserManagementService {
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
    instance: { uuid: string } = this.instance,
    emailMessage?: {
      subject: string;
      body: (activationToken: string) => string;
    }
  ): Promise<T.AuthenticationOut & T.Tokens & { activationToken: string }> => {
    const response = await this.request<
      T.AuthenticationOut & { refreshToken: string; activationToken: string }
    >("/signup", {
      profile,
      instance,
      authentication,
    });

    const accessToken = this.getAccessToken(
      response.profile.id,
      response.profile.email,
      instance.uuid,
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
    email?: string,
    ip?: string
  ): Promise<T.AuthenticationOut & T.Tokens> => {
    const { profile, permissions, locale, refreshToken } = await this.request<
      T.AuthenticationOut & { refreshToken: string }
    >("/authenticate", { authentication, email, ip });

    const accessToken = this.getAccessToken(
      profile.id,
      profile.email,
      profile.instance.uuid,
      permissions
    );

    return { profile, permissions, locale, refreshToken, accessToken };
  };

  userByEmail = async (
    email: string
  ): Promise<{
    profile: T.Profile;
    status: T.UserStatus;
    locale: T.Locale;
    UserAuthentication?: T.UserAuthentication[];
  }> => {
    return await this.request("/user-by-email", { email });
  };

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
    const { profile } = await this.userByEmail(email);
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
  passwordReset = async (token: string, newPassword: string) => {
    const { id } = decryptPayload(token, this.secretKey, "RESET_PASSWORD");

    return this.changePassword(id, newPassword);
  };

  refresh = async (refreshToken: string): Promise<T.RefreshOut> => {
    const r = await this.request<T.AuthenticationOut>("/refresh", {
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

  profile = async (uuid: string) => this.request("/profile", { uuid });

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
    }: Partial<T.OAuthCallbackWithAuthenticationOptions>
  ): Promise<T.AuthenticationOut & T.Tokens> => {
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

      return this.authenticate({ type, value: email });
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
      permission: T.Permission;
      userPermission: { uuid: string };
      logDateAdded: string;
    }[]
  > => this.request("/admin/permission/user/list", { uuid });

  userPermissionToggle = async (
    uuid: string,
    permission: T.Permission
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
}

export default UserManagementService;
