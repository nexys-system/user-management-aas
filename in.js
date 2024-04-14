import A from "./dist/service.js";

const clientId = "phenomx.prod.login";
const secret =
  "VzVYNVc2Nk0zNCoqODk0S1dVMjhSNCoqLS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR1RBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJIa3dkd0lCQVFRZ2N6R3IxcW9ubDJJVmxZbTcKbFVuYzBTRzhvV3NKWjhVNGFlcnNqZmtDVTVXZ0NnWUlLb1pJemowREFRZWhSQU5DQUFRaExJcElZY3FrK0l6awpJVEZKQzBSZXZ0cjFQY2hablF3R3FHRW9NSVlyek4rZVF4T2NJd3pYc2hmb0kxZUxGTWJIbjdEK1dra21lSG1KCm5PSE5VcnkyCi0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0=";

const token =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwcm9kdWN0IjozMjUsImluc3RhbmNlIjoiNWYzM2FhNGItZjdmYi0xMWVlLTliYWQtNDIwMTBhYWMwMDFjIiwiaWF0IjoxNzEzMTMyNzA1fQ.mAhXGvyrcxGWLLCP4QQskfqBjkCAxRuqRJ-1frLIcjI";

const a = new A(token, "default");
const redirectUrl = "https://api.phenomxhealth.com/auth/oauth/callback";

const main = async () => {
  const oauthParams = {
    service: "apple",
    clientId,
    secret,
    redirectUrl,
  };
  const url = await a.oAuthUrl(oauthParams);
  console.log(url);

  const code =
    "c3a5bc9607b6c4e2186332e8c7ac80d54.0.sswz.067vEeYqbiUdZGDgXBr00Q";

  const c = await a.oAuthCallback(code, oauthParams);

  console.log(c);
};

main();
