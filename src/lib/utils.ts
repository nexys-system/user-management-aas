import JWT from "jsonwebtoken";

export const request =
  (token: string, urlPrefix: string) =>
  async <A = any>(path: string, payload: any): Promise<A> => {
    const body = JSON.stringify(payload);
    const headers = {
      Authorization: "Bearer " + token,
      "content-type": "application/json",
    };

    const url = urlPrefix + path;

    const r = await fetch(url, {
      method: "POST",
      body,
      headers,
    });

    if (r.status !== 200) {
      const t = await r.text();

      throw Error(t);
    }

    console.log(r.status);

    return r.json();
  };

export const getAccessToken = (jwtSecret: string) => (id: string) =>
  JWT.sign({ id }, jwtSecret);
