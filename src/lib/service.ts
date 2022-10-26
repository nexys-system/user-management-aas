import { urlPrefix } from './constants';
import * as T from './type';
import * as U from './utils';

class UserManagementService {
  request: <A = any>(path: string, payload: any) => Promise<A>;
  getAccessToken: (id: string) => string;

  constructor(token: string, jwtSecret: string) {
    this.request = U.request(token, urlPrefix);
    this.getAccessToken = U.getAccessToken(jwtSecret);
  }

  authenticate = (googleEmail: string) => {
    const payload = {
      value: googleEmail,
      type: T.AuthenticationType.google
    };

    console.log({ payload });

    return this.request('/authenticate', payload);
  };

  reAuthenticate = async (
    refreshToken: string
  ): Promise<{
    profile: T.Profile;
    permissions: number[];
    locale: T.Locale;
  }> => this.request('/re-authenticate', { refreshToken });

  signup = async (firstName: string, lastName: string, email: string) => {
    const payload = {
      profile: {
        email,
        firstName,
        lastName
      },
      authentication: { value: email, type: T.AuthenticationType.google }
    };

    return this.request('/signup', payload);
  };
}

export default UserManagementService;
