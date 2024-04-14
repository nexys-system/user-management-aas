import bcrypt from "bcryptjs";
import { AuthenticationType } from "../type.js";

export const matchPassword = (p: string, hash: string): Promise<boolean> =>
  bcrypt.compare(p, hash);

const salt = 8;
export const hashPassword = (p: string): Promise<string> =>
  bcrypt.hash(p, salt);

/**
 * hide the password when displaying list of auth
 * @param userAuthentication : userAuthentication row
 * @returns userAuthentication but password replaced
 */
export const hideHashedPassword = <A extends { type: AuthenticationType }>(
  userAuthentication: A
): A => {
  if (userAuthentication.type === AuthenticationType.password) {
    const value = "xxx";
    return { ...userAuthentication, value };
  }

  return userAuthentication;
};
