import * as CryptoService from "@nexys/crypto";
import { Action, ActionPayload, AuthenticationOut } from "./type.js";

type Uuid = string;

export const twoFaPayload = (
  data: Pick<AuthenticationOut, "profile" | "permissions" | "locale"> & {
    auth: {
      uuid: Uuid;
      value: string;
    };
  },
  secretKey: string,
  duration: number = 10 * 1000 // valid for 10min
): string => encrypt(data, secretKey, "2FA", duration);

export const createActionPayload = (
  id: Uuid,
  instance: { uuid: Uuid },
  action: Action,
  secretKey: string
): string => {
  const actionPayload: Pick<ActionPayload, "id" | "instance"> = {
    id,
    instance,
  };

  return encrypt(actionPayload, secretKey, action);
};

export const encrypt = <A>(
  data: A,
  secretKey: string,
  action: Action,
  duration: number = 24 * 3600 * 1000 // resource is valid for 1 day, by default
): string => {
  const issued = new Date().getTime();
  const expires = issued + duration;
  const payload = { ...data, action, issued, expires };

  return CryptoService.Symmetric.encrypt(JSON.stringify(payload), secretKey);
};

export const decryptPayload = <A = ActionPayload>(
  ciphertext: string,
  secretKey: string,
  expectedAction?: Action
): A & { issued: number; expires: number; action: Action } => {
  try {
    const decrypted = CryptoService.Symmetric.decrypt(ciphertext, secretKey);
    const r: A & { issued: number; expires: number; action: Action } =
      JSON.parse(decrypted);

    const dt = new Date().getTime();

    if (r.issued > dt) {
      throw Error("resource was not created yet (this should never happen)");
    }

    if (r.expires < dt) {
      throw Error("resource expired");
    }

    if (expectedAction && r.action !== expectedAction) {
      throw Error("wrong excepted action");
    }

    return r;
  } catch (err) {
    throw Error("could not decrypt encrypted string" + err);
  }
};
