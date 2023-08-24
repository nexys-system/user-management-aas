import jwt from "jsonwebtoken";
import { generateKeyPairSync } from "crypto";
import { RefreshOut } from "./type";
import * as U from "./utils";

const id = "123";
const instanceId = "instanceid";
const profile = {
  firstName: "j",
  lastName: "b",
  email: "j@b",
  id,
  instance: { uuid: instanceId },
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

  const payload = { id, instanceId, permissions };
  const token = jwt.sign(payload, jwtSecret);

  const getAccessToken = () => "token";
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
  const ePrivateKey = privateKey.export({ type: "pkcs8", format: "pem" });
  // end generate pulbic/private

  const getAccessToken = U.getAccessToken(ePrivateKey as string, algorithm);
  const token = getAccessToken(id, instanceId, permissions);

  const authorizeFunc = U.authorize(
    refreshFunc,
    getAccessToken,
    ePublicKey as string,
    60 * 15,
    algorithm
  );
  const authorizeResult = await authorizeFunc(token);

  const expectedPayload = { id, instanceId, permissions };
  expect(authorizeResult).toEqual(expectedPayload);
});
