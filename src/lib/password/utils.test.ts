import { AuthenticationType } from "../type.js";
import * as U from "./utils.js";

test("hideHashedPassword", () => {
  const ua = {
    uuid: "1",
    value: "hashedPassword",
    type: AuthenticationType.password,
    isEnabled: true,
    user: { uuid: "u1" },
  };

  const ua2 = {
    uuid: "1",
    value: "xxx",
    type: AuthenticationType.password,
    isEnabled: true,
    user: { uuid: "u1" },
  };
  expect(U.hideHashedPassword(ua)).toEqual(ua2);
});
