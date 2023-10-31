import jwt from "jsonwebtoken";
import { generateKeyPairSync } from "crypto";
import { RefreshOut } from "./type";
import * as U from "./utils";
import { tokenValidity } from "../config";

const id = "123";
const email = "j@b";
const instanceId = "instanceid";
const profile = {
  id,
  email,
  instance: { uuid: instanceId },
  firstName: "j",
  lastName: "b",
};
const locale = { country: "US", lang: "en" };
const permissions = [1];

const refreshFunc = (token: string): Promise<RefreshOut> => {
  return Promise.resolve({
    accessToken: token,
    profile,
    permissions,
    locale,
  });
};

test("authorize", async () => {
  const jwtSecret = "mysecret";

  const payload = { id, email, instanceId, permissions };

  const getAccessToken = U.getAccessToken(
    { jwtSecretOrPrivateKey: jwtSecret },
    tokenValidity
  );
  const token = getAccessToken(id, email, instanceId, permissions);

  //const token = jwt.sign(payload, jwtSecret);

  //const getAccessToken = () => "token";
  const authorizeFunc = U.authorize(
    refreshFunc,
    getAccessToken,
    jwtSecret,
    60 * 15
  );
  const authorizeResult = await authorizeFunc(token);
  expect(authorizeResult).toEqual(payload);
});

test("authorize asymetric", async () => {
  // generate public and private keys
  const algorithm = U.jwtAlgorithmDefault;
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });

  // to string (pem format)
  const ePublicKey = publicKey.export({ type: "spki", format: "pem" });
  const ePrivateKey = privateKey.export({
    type: "pkcs8",
    format: "pem",
  }) as string;
  // end generate public/private

  const getAccessToken = U.getAccessToken(
    { jwtSecretOrPrivateKey: ePrivateKey as string, algorithm },
    tokenValidity
  );
  const token = getAccessToken(id, email, instanceId, permissions);

  const authorizeFunc = U.authorize(
    refreshFunc,
    getAccessToken,
    ePublicKey as string,
    60 * 15,
    algorithm
  );
  const authorizeResult = await authorizeFunc(token);

  const expectedPayload = { id, email, instanceId, permissions };
  expect(authorizeResult).toEqual(expectedPayload);
});

test("sign an d verify asymetric jwt (just for reference)", () => {
  const algorithm = "RS256";

  const payload = { a: "bla" };
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });

  // to string (pem format)
  const ePublicKey = publicKey.export({ type: "spki", format: "pem" });
  const ePrivateKey = privateKey.export({ type: "pkcs8", format: "pem" });

  const token = jwt.sign(payload, ePrivateKey, { algorithm });

  expect(typeof token).toBe("string");

  const { iat, ...decoded } = jwt.verify(token, ePublicKey, {
    algorithms: [algorithm],
  }) as object as { iat: string };
  expect(decoded).toEqual(payload);
  expect(typeof iat).toBe("number");
});
