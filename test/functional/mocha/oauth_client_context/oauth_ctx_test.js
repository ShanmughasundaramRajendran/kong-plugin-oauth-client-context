"use strict";

const assert = require("assert");

const BASE_URL = process.env.BASE_URL || "http://localhost:8000";
const APIKEY_C1 = process.env.APIKEY_C1 || "demo-consumer-apikey";
const APIKEY_C2 = process.env.APIKEY_C2 || "demo-consumer-apikey-2";
const APIKEY_C3 = process.env.APIKEY_C3 || "demo-consumer-apikey-3";

const INCOMING_JWT = process.env.INCOMING_JWT ||
  "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJjbGllbnRfaWQiOiJqd3QtY2xpZW50LTEyMyIsImFwcF9pZCI6Imp3dC1hcHAtNDU2IiwiZ3JhbnRfdHlwZSI6ImNsaWVudF9jcmVkZW50aWFscyIsIm9hdXRoX3Jlc291cmNlX293bmVyX2lkIjoiand0LW93bmVyLTc4OSIsImNvbnNlbnRfaWQiOiJqd3QtY29uc2VudC0xMTEiLCJzc29pZCI6Imp3dC1zc29pZC0yMjIiLCJzY29wZXMiOiJwYXltZW50czpyZWFkIHBheW1lbnRzOndyaXRlIiwieC1hcGlndy1vcmlnaW4tY2xpZW50LWlkIjoiand0LW9yaWdpbi0zMzMiLCJvYXV0aF9pZGVudGl0eV90eXBlIjoib2F1dGgyLWZyb20taW5jb21pbmctdG9rZW4iLCJhdXRoX2lkZW50aXR5X3R5cGUiOiJhdXRoLWZyb20taW5jb21pbmctdG9rZW4iLCJhcHByb3ZlZF9vcGVyYXRpb25fdHlwZXMiOiJxdWVyeSxtdXRhdGlvbiJ9.sig";

const HEADER_INCLUDE_VALUE = process.env.HEADER_INCLUDE_VALUE || "include-header-1";
const HEADER_REPLACE_VALUE = process.env.HEADER_REPLACE_VALUE || "replaced-by-header-2";
const HEADER_IGNORE_VALUE = process.env.HEADER_IGNORE_VALUE || "ignored-header-3";

function decodeBase64Url(input) {
  const padded = input + "=".repeat((4 - (input.length % 4 || 4)) % 4);
  return Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
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

async function getRoute(path, apikey, opts = {}) {
  const headers = {
    Accept: "application/json",
    ...opts.headers,
  };

  if (apikey) {
    headers.apikey = apikey;
  }

  const response = await fetch(`${BASE_URL}${path}`, {
    method: "GET",
    headers,
  });

  const body = await response.json();
  return { response, body };
}

function assertCommonHeader(decodedHeader, expectedAlg, expectedKid) {
  assert.strictEqual(decodedHeader.tv, 2);
  assert.strictEqual(decodedHeader.typ, "JWT");
  assert.strictEqual(decodedHeader.alg, expectedAlg);
  assert.strictEqual(decodedHeader.kid, expectedKid);
}

function assertIncomingJwtClaims(payload) {
  assert.strictEqual(payload.client_id, "jwt-client-123");
  assert.strictEqual(payload.app_id, "jwt-app-456");
  assert.strictEqual(payload.grant_type, "client_credentials");
  assert.strictEqual(payload.oauth_resource_owner_id, "jwt-owner-789");
  assert.strictEqual(payload.consent_id, "jwt-consent-111");
  assert.strictEqual(payload.ssoid, "jwt-ssoid-222");
  assert.strictEqual(payload.scopes, "payments:read payments:write");
  assert.strictEqual(payload["x-apigw-origin-client-id"], "jwt-origin-333");
  assert.strictEqual(payload.auth_identity_type, "auth-from-incoming-token");
  assert.strictEqual(payload.approved_operation_types, "query,mutation");
}

describe("oauth-client-context functional suite (mocha)", function () {
  this.timeout(30000);

  it("requires api key", async function () {
    const { response } = await getRoute("/test-rs", null);
    assert.strictEqual(response.status, 401);
  });

  it("RS256 route signs and injects JWT with tv=2 and incoming-JWT claims", async function () {
    const { response, body } = await getRoute("/test-rs", APIKEY_C1, {
      headers: {
        Authorization: `Bearer ${INCOMING_JWT}`,
        "x-consumer-extra-claim": HEADER_INCLUDE_VALUE,
        "x-consumer-replace-claim": HEADER_REPLACE_VALUE,
        "x-consumer-ignore-claim": HEADER_IGNORE_VALUE,
      },
    });

    assert.strictEqual(response.status, 200);
    const token = body.headers["X-Client-Auth-Ctx"];
    assert.ok(token, "x-client-auth-ctx token should be present in upstream headers");

    const { header, payload } = decodeJwt(token);
    assertCommonHeader(header, "RS256", "local-test-rs");
    assertIncomingJwtClaims(payload);

    assert.strictEqual(payload.oauth_identity_type, HEADER_REPLACE_VALUE);
    assert.strictEqual(payload.consumer_extra_claim, HEADER_INCLUDE_VALUE);
    assert.ok(!Object.prototype.hasOwnProperty.call(payload, "consumer_ignore_claim"));
  });

  it("ES256 route signs and injects JWT with tv=2", async function () {
    const { response, body } = await getRoute("/test-es", APIKEY_C1, {
      headers: {
        Authorization: `Bearer ${INCOMING_JWT}`,
      },
    });

    assert.strictEqual(response.status, 200);
    const token = body.headers["X-Client-Auth-Ctx"];
    assert.ok(token);

    const { header, payload } = decodeJwt(token);
    assertCommonHeader(header, "ES256", "local-test-es");
    assert.strictEqual(payload.client_id, "jwt-client-123");
  });

  it("billing and orders routes work with consumer-specific API keys", async function () {
    const billingRs = await getRoute("/billing/rs", APIKEY_C2, {
      headers: { Authorization: `Bearer ${INCOMING_JWT}` },
    });
    const billingEs = await getRoute("/billing/es", APIKEY_C2, {
      headers: { Authorization: `Bearer ${INCOMING_JWT}` },
    });
    const ordersRs = await getRoute("/orders/rs", APIKEY_C3, {
      headers: { Authorization: `Bearer ${INCOMING_JWT}` },
    });
    const ordersEs = await getRoute("/orders/es", APIKEY_C3, {
      headers: { Authorization: `Bearer ${INCOMING_JWT}` },
    });

    assert.strictEqual(billingRs.response.status, 200);
    assert.strictEqual(billingEs.response.status, 200);
    assert.strictEqual(ordersRs.response.status, 200);
    assert.strictEqual(ordersEs.response.status, 200);

    assert.strictEqual(decodeJwt(billingRs.body.headers["X-Client-Auth-Ctx"]).header.alg, "RS256");
    assert.strictEqual(decodeJwt(billingEs.body.headers["X-Client-Auth-Ctx"]).header.alg, "ES256");
    assert.strictEqual(decodeJwt(ordersRs.body.headers["X-Client-Auth-Ctx"]).header.alg, "RS256");
    assert.strictEqual(decodeJwt(ordersEs.body.headers["X-Client-Auth-Ctx"]).header.alg, "ES256");
  });

  it("falls back to consumer claims when incoming JWT is missing", async function () {
    const { response, body } = await getRoute("/test-rs", APIKEY_C1);

    assert.strictEqual(response.status, 200);
    const { payload } = decodeJwt(body.headers["X-Client-Auth-Ctx"]);
    assert.strictEqual(payload.client_id, "consumer-client-001");
    assert.strictEqual(payload.app_id, "consumer-app-001");
  });
});
