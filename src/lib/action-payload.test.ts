import {
  twoFaPayload,
  createActionPayload,
  decryptPayload,
} from "./action-payload";
import { generateSecretKey } from "./utils";
import { Action, AuthenticationOut, Locale, Permission, Profile } from "./type";

test("encrypt / descrupt", () => {
  const secretKey = generateSecretKey(); // Generate a secret key for testing
  const id = "id";
  const instanceUuid = "instanceUuid";

  const payload = createActionPayload(
    id,
    { uuid: instanceUuid },
    "RESET_PASSWORD",
    secretKey
  );

  const {
    id: id2,
    expires,
    action,
  } = decryptPayload(payload, secretKey, "RESET_PASSWORD");

  expect(expires).toBeGreaterThan(new Date().getTime());
  expect(action).toBe("RESET_PASSWORD");
  expect(id).toEqual(id2);
});

describe("Encryption and Decryption Services", () => {
  const secretKey = generateSecretKey(); // Generate a secret key for testing
  const uuid = "123e4567-e89b-12d3-a456-426614174000";
  const profile: Profile = {
    id: "sd",
    firstName: "John",
    lastName: "Doe",
    email: "jphn@doe.com",
    instance: { uuid: "s" },
  };
  const permissions: Permission[] = [Permission.app];
  const locale: Locale = { lang: "fr", country: "CH" };
  const action: Action = "CHANGE_EMAIL";

  test("2FA payload encryption and decryption", () => {
    const data: Pick<
      AuthenticationOut,
      "profile" | "permissions" | "locale"
    > & {
      auth: {
        uuid: string;
        value: string;
      };
    } = {
      profile,
      permissions,
      locale,
      auth: {
        uuid,
        value: "secretValue",
      },
    };

    const encrypted = twoFaPayload(data, secretKey);
    const decrypted = decryptPayload(encrypted, secretKey);

    expect(decrypted).toMatchObject(data);
    expect(decrypted.action).toBe("2FA");
  });

  test("Action payload encryption and decryption", () => {
    const instance = { uuid };
    const encrypted = createActionPayload(uuid, instance, action, secretKey);
    const decrypted = decryptPayload(encrypted, secretKey, action);

    expect(decrypted.id).toBe(uuid);
    expect(decrypted.instance).toMatchObject(instance);
    expect(decrypted.action).toBe(action);
  });

  test("generate token", async () => {
    const encrypted = createActionPayload(
      "myUuid",
      { uuid: "instanceUuid" },
      "RESET_PASSWORD",
      secretKey
    );
    const decrypted = decryptPayload(encrypted, secretKey);

    const dt = new Date().getTime();

    expect(decrypted.id).toEqual("myUuid");
    expect(decrypted.instance).toEqual({ uuid: "instanceUuid" });
    expect(decrypted.issued).toBeLessThanOrEqual(dt);
    expect(decrypted.expires).toBeGreaterThan(dt);
  });
});
