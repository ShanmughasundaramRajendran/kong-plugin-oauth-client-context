"use strict";

const assert = require("assert");
const crypto = require("crypto");

const BASE_URL = process.env.BASE_URL || "http://localhost:8000";
const APIKEY_C1 = process.env.APIKEY_C1 || "demo-consumer-apikey";
const APIKEY_C2 = process.env.APIKEY_C2 || "demo-consumer-apikey-2";
const APIKEY_C3 = process.env.APIKEY_C3 || "demo-consumer-apikey-3";

const HEADER_INCLUDE_VALUE = process.env.HEADER_INCLUDE_VALUE || "include-header-1";
const HEADER_REPLACE_VALUE = process.env.HEADER_REPLACE_VALUE || "replaced-by-header-2";

const RS_PRIVATE_KEY = process.env.LOCAL_TEST_RS_PRIVATE_KEY || `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC3u6HaTXrk5m2W
wTVttoD8jxzHGtfkedtIOQaRF+vHZRqDpS4K+vQQOJpcLivfbE7zjBcY4NrIstgT
DKOg6jq98S1a5eaDoyesikJLgXbGmw7FzBwOaQd1DNJyqQU5vZkTEk/MQznMk6k3
yYW80CIh4Eax1SU82ktYoQsPz1I92sS0z3tm++roOiQlSRgA63Su6VxsbqfVcH4u
3AH7WEyZV4L9fkOJ8/B0/ll2rwO+Ydp2QmCg8v1HCYroA7neIMXxmRvO2fwLOSpO
fDhFEDYwv+rhHl+A2Qe7U6oEWvWd6B/LRdrjh1TS1OQYCG11XTAg8DTzCYHwOZbw
lWbQ9gCrAgMBAAECggEAEDLYuDhwh1HRg6MRJNUcVif/74XsVtZvgNSWQaCMRw4g
4k5j2s/5SJzU7x+a+p2/8DT/rE/Wui8aYcORgZRlDW4AA62VPzHZQ5sE8Uc+w4/U
I5g1OQgFgkpZG4bPUSHoJwhMRMQAiorSNnrr8ZOgDsCJOxCBsfXFAtFf+krbA1zp
mch3+Dn4cs+BA0bkqbdwZq8c9l9xKTZRZilfrsJfbPdB5NOHbwpLxsRuuSJ6mWC2
XIS6r/Ht4iAJQqHqEvJPQ+MHLRkN800RIpm6uym5mUGZrQkcOs74vD2DolqobBe+
NJ42ot92YbveUVEygHaoQ2F6t1zUHLTDMCK7a2TjIQKBgQD9cQYVvG/6fWEui1hx
s2NUnz1+gwKRde9vC0dxyBvbxwkD5RbjKv0UJF2gv/Ey9HL7KV6YsuhrcyNdkRnh
rHa0oYyTLjy4bE4BFMnHGl/HJQb7C/u+affsrLDc3qaem53CANYQmJQFyzuUxVJC
YwKSxtMeFp3ziVY6fgHsab30UwKBgQC5lnVnaFssMiNQCiCAtFEuO9JXETDqTc4J
LkSkZdTBqjlHtYnVwbCky/doGJq8riOyUc3AdOGjdYfr01x6I3grccwQ0YSVZNUq
ew3rUri6w/txcZbVBQPcnuKbh8jzuvNWEMapuVtImLv0cXs/0mnS3zhgozJsv/43
GiUWWsy3SQKBgBkwzLwIWND6+VfY/dd/TxYwJbqXZv/ySvQsmNNUYoB7zgeXE6lM
so739l5t9Zls9qjEOeTPk45qiU9ZhssJi1r027YdWGe0TCSLXmrt0itHIOR/Emyg
t8XMfF/XuZP2P73yu1Q29i+FPczRuBVlJfJU1NMeyGBWfD2gHKzU7c6FAoGAa3bJ
Qvi1mpDpy8YhbgV74Ja5RLtqpLIq9Tv6eWuR2Ba2lmRzjPhcTgDhoUBmEY2QlAg0
aRYFNj6vVwoLyZnSUu3RKYf5CvzZRoD83WAIIfWsGtOYcH837j9+nmrxHNkLYLHU
J6FyT0ZJx9ESejFgH8AsCCFX6IsALG4SPbCUTCkCgYBGsNOvoKA6+tiL5TcC1GvN
BUxUlI/qT56uH8eIop8+UWBBGitzWhzo2kOMcagQ2K93WGdFRyMpQjcaaCNmMol9
7eveJSsCfcR9t0eqd9PHYpCdHPI2i+4kKSxkcvxUqkaPXR4x+vk6jK34/dbrePMM
jnOmBD3+NgzJShVMu6Gihw==
-----END PRIVATE KEY-----`;

const ES_PRIVATE_KEY = process.env.LOCAL_TEST_ES_PRIVATE_KEY || `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPMsmJLI3mB7M/bMHpOnWzLuQ2qLagZR1bqBeFDnhAbqoAoGCCqGSM49
AwEHoUQDQgAEe1+eiBvr/R3Brd1GLbOn0bZdQW1nfgf6Jry93y6+lqZPBD25AsZf
snohLGEdZhzcduSzxtQK6IHlPyfg+3F0kg==
-----END EC PRIVATE KEY-----`;

function decodeBase64Url(input) {
  const padded = input + "=".repeat((4 - (input.length % 4 || 4)) % 4);
  return Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
}

function buildIntrospectionHeader(overrides = {}) {
  const claims = {
    client_id: "oidc-client-123",
    app_id: "oidc-app-456",
    grant_type: "client_credentials",
    oauth_resource_owner_id: "oidc-owner-789",
    consent_id: "oidc-consent-111",
    ssoid: "oidc-ssoid-222",
    scopes: "payments:read payments:write",
    "x-apigw-origin-client-id": "oidc-origin-333",
    oauth_identity_type: "oidc-identity",
    auth_identity_type: "oidc-auth-identity",
    approved_operation_types: "query,mutation",
    ...overrides,
  };
  return Buffer.from(JSON.stringify(claims), "utf8").toString("base64");
}

function decodeJwt(token) {
  const parts = token.split(".");
  assert.strictEqual(parts.length, 3, "JWT should have 3 parts");
  return {
    header: JSON.parse(decodeBase64Url(parts[0])),
    payload: JSON.parse(decodeBase64Url(parts[1])),
    signature: parts[2],
  };
}

function decodeBase64UrlToBuffer(input) {
  const padded = input + "=".repeat((4 - (input.length % 4 || 4)) % 4);
  return Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

function verifyJwtSignature(token, alg) {
  const [h, p, s] = token.split(".");
  const signingInput = `${h}.${p}`;
  const signature = decodeBase64UrlToBuffer(s);
  const verifier = crypto.createVerify("SHA256");
  verifier.update(signingInput);
  verifier.end();

  if (alg === "RS256") {
    const rsaPublicKey = crypto.createPublicKey(RS_PRIVATE_KEY).export({ type: "spki", format: "pem" });
    return verifier.verify(rsaPublicKey, signature);
  }

  if (alg === "ES256") {
    const ecPublicKey = crypto.createPublicKey(ES_PRIVATE_KEY).export({ type: "spki", format: "pem" });
    return verifier.verify({ key: ecPublicKey, dsaEncoding: "ieee-p1363" }, signature);
  }

  return false;
}

async function getRoute(path, apikey, opts = {}) {
  const headers = new Headers();
  headers.set("Accept", "application/json");
  if (apikey) {
    headers.set("apikey", apikey);
  }

  if (opts.headers instanceof Headers) {
    for (const [key, value] of opts.headers.entries()) {
      headers.append(key, value);
    }
  } else if (opts.headers && typeof opts.headers === "object") {
    for (const [key, value] of Object.entries(opts.headers)) {
      headers.set(key, value);
    }
  }

  const response = await fetch(`${BASE_URL}${path}`, { method: "GET", headers });
  const body = await response.json();
  return { response, body };
}

function assertCommonHeader(decodedHeader, expectedAlg) {
  assert.strictEqual(decodedHeader.tv, 2);
  assert.strictEqual(decodedHeader.typ, "JWT");
  assert.strictEqual(decodedHeader.alg, expectedAlg);
  assert.strictEqual(decodedHeader.kid, undefined);
}

describe("oauth-client-context functional suite (mocha, OIDC input)", function () {
  this.timeout(30000);

  it("requires api key", async function () {
    const { response } = await getRoute("/test-rs", null);
    assert.strictEqual(response.status, 401);
  });

  it("RS256 route signs and injects JWT using OIDC introspection claims", async function () {
    const { response, body } = await getRoute("/test-rs", APIKEY_C1, {
      headers: {
        "X-Kong-Introspection-Response": buildIntrospectionHeader(),
        "x-consumer-extra-claim": HEADER_INCLUDE_VALUE,
        "x-consumer-replace-claim": HEADER_REPLACE_VALUE,
        "x-extra-claim": "from-additional-mapping",
      },
    });

    assert.strictEqual(response.status, 200);
    const token = body.headers["X-Client-Auth-Ctx"];
    assert.ok(token);

    const { header, payload } = decodeJwt(token);
    assertCommonHeader(header, "RS256");
    assert.strictEqual(verifyJwtSignature(token, "RS256"), true);
    assert.strictEqual(payload.client_id, "oidc-client-123");
    assert.strictEqual(payload.app_id, "oidc-app-456");
    assert.strictEqual(payload.oauth_identity_type, HEADER_REPLACE_VALUE);
    assert.strictEqual(payload.consumer_extra_claim, HEADER_INCLUDE_VALUE);
    assert.strictEqual(payload.extra_claim, "from-additional-mapping");
  });

  it("ES256 route signs and injects JWT using OIDC introspection claims", async function () {
    const { response, body } = await getRoute("/test-es", APIKEY_C1, {
      headers: {
        "X-Kong-Introspection-Response": buildIntrospectionHeader(),
      },
    });

    assert.strictEqual(response.status, 200);
    const token = body.headers["X-Client-Auth-Ctx"];
    assert.ok(token);

    const { header, payload } = decodeJwt(token);
    assertCommonHeader(header, "ES256");
    assert.strictEqual(payload.client_id, "oidc-client-123");
    assert.strictEqual(verifyJwtSignature(token, "ES256"), true);
  });

  it("billing and orders routes work with consumer-specific API keys", async function () {
    const headers = { "X-Kong-Introspection-Response": buildIntrospectionHeader() };
    const billingRs = await getRoute("/billing/rs", APIKEY_C2, { headers });
    const billingEs = await getRoute("/billing/es", APIKEY_C2, { headers });
    const ordersRs = await getRoute("/orders/rs", APIKEY_C3, { headers });
    const ordersEs = await getRoute("/orders/es", APIKEY_C3, { headers });

    assert.strictEqual(billingRs.response.status, 200);
    assert.strictEqual(billingEs.response.status, 200);
    assert.strictEqual(ordersRs.response.status, 200);
    assert.strictEqual(ordersEs.response.status, 200);
  });

  it("falls back to consumer claims when OIDC introspection header is missing", async function () {
    const { response, body } = await getRoute("/test-rs", APIKEY_C1);
    assert.strictEqual(response.status, 200);
    const { payload } = decodeJwt(body.headers["X-Client-Auth-Ctx"]);
    assert.strictEqual(payload.client_id, "consumer-client-001");
    assert.strictEqual(payload.app_id, "consumer-app-001");
  });

  it("falls back to consumer claims when OIDC introspection payload is malformed", async function () {
    const { response, body } = await getRoute("/test-rs", APIKEY_C1, {
      headers: { "X-Kong-Introspection-Response": "not-base64" },
    });
    assert.strictEqual(response.status, 200);
    const { payload } = decodeJwt(body.headers["X-Client-Auth-Ctx"]);
    assert.strictEqual(payload.client_id, "consumer-client-001");
    assert.strictEqual(payload.app_id, "consumer-app-001");
  });

  it("falls back to consumer claims when OIDC claim value is empty", async function () {
    const { response, body } = await getRoute("/test-rs", APIKEY_C1, {
      headers: {
        "X-Kong-Introspection-Response": buildIntrospectionHeader({ client_id: "", app_id: "" }),
      },
    });
    assert.strictEqual(response.status, 200);
    const { payload } = decodeJwt(body.headers["X-Client-Auth-Ctx"]);
    assert.strictEqual(payload.client_id, "consumer-client-001");
    assert.strictEqual(payload.app_id, "consumer-app-001");
  });

  it("ignores Authorization token claims when OIDC introspection claims are present", async function () {
    const { response, body } = await getRoute("/test-rs", APIKEY_C1, {
      headers: {
        Authorization: "Bearer should-not-be-used-for-claims",
        "X-Kong-Introspection-Response": buildIntrospectionHeader({ client_id: "oidc-priority-client" }),
      },
    });
    assert.strictEqual(response.status, 200);
    const { payload } = decodeJwt(body.headers["X-Client-Auth-Ctx"]);
    assert.strictEqual(payload.client_id, "oidc-priority-client");
  });

  it("handles duplicate replace-claim header values without failing", async function () {
    const multiHeaders = new Headers();
    multiHeaders.set("X-Kong-Introspection-Response", buildIntrospectionHeader());
    multiHeaders.append("x-consumer-replace-claim", "something-1");
    multiHeaders.append("x-consumer-replace-claim", "something-2");

    const { response, body } = await getRoute("/test-rs", APIKEY_C1, {
      headers: multiHeaders,
    });

    assert.strictEqual(response.status, 200);
    const { payload } = decodeJwt(body.headers["X-Client-Auth-Ctx"]);
    assert.ok(
      typeof payload.oauth_identity_type === "string" &&
      (payload.oauth_identity_type.includes("something-1") || payload.oauth_identity_type.includes("something-2"))
    );
  });

  it("sets exp relative to iat based on route ttl", async function () {
    const headers = { "X-Kong-Introspection-Response": buildIntrospectionHeader() };
    const rs = await getRoute("/test-rs", APIKEY_C1, { headers });
    const ordersEs = await getRoute("/orders/es", APIKEY_C3, { headers });
    const rsPayload = decodeJwt(rs.body.headers["X-Client-Auth-Ctx"]).payload;
    const ordersPayload = decodeJwt(ordersEs.body.headers["X-Client-Auth-Ctx"]).payload;
    assert.ok(rsPayload.exp - rsPayload.iat >= 60 && rsPayload.exp - rsPayload.iat <= 61);
    assert.ok(ordersPayload.exp - ordersPayload.iat >= 180 && ordersPayload.exp - ordersPayload.iat <= 181);
  });
});
