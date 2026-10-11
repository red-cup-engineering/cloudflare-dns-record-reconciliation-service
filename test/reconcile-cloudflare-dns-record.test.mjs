import assert from "node:assert/strict";
import test from "node:test";
import { reconcileCloudflareDnsRecord } from "../src/reconcile-cloudflare-dns-record.mjs";

const input = {authentication:{profile:"named-profile",expectedAccountId:"0123456789abcdef0123456789abcdef",scopes:["account:read","dns:write"],settlementDirectory:"/tmp",browser:true},mapping:{zone:"example.test",type:"CNAME",name:"app.example.test",content:"target.example.net",proxied:false,ttl:1}};
const response = (result) => ({ok:true,json:async()=>({success:true,result})});
function fixture(records=[]) { const calls=[]; return {calls,fetch:async(url,init={})=>{calls.push({url,init});if(url.endsWith("/zones?name=example.test"))return response([{id:"zone",name:"example.test"}]);if(init.method==="POST")return response({id:"created"});if(init.method==="PUT")return response({id:"updated"});return response(records);}}; }
const options = (fetch) => ({fetch,inspect:async()=>({verified:true,credentialReturned:false}),profileCredential:async()=>({oauthToken:"secret"})});

test("creates, retains, and updates one declared record", async () => {
  const missing=fixture(),created=await reconcileCloudflareDnsRecord(input,options(missing.fetch)); assert.equal(created.disposition,"created");
  const exact=fixture([{id:"exact",...input.mapping}]),unchanged=await reconcileCloudflareDnsRecord(input,options(exact.fetch)); assert.equal(unchanged.disposition,"unchanged");
  const divergent=fixture([{id:"old",...input.mapping,content:"old.example"}]),updated=await reconcileCloudflareDnsRecord(input,options(divergent.fetch)); assert.equal(updated.disposition,"updated");
});

test("refuses ambiguous or undeclared authority", async () => {
  await assert.rejects(reconcileCloudflareDnsRecord({...input,authentication:{...input.authentication,scopes:["account:read"]}},options(fixture().fetch)),/dns:write/);
  const duplicate=fixture([{id:"one",...input.mapping},{id:"two",...input.mapping}]);
  await assert.rejects(reconcileCloudflareDnsRecord(input,options(duplicate.fetch)),/duplicate/);
});

const absentInput = {authentication:input.authentication,mapping:{zone:"example.test",type:"CNAME",name:"app.example.test",state:"absent"}};

test("absent with zero matches is unchanged and issues no mutating request", async () => {
  const empty=fixture();
  const receipt=await reconcileCloudflareDnsRecord(absentInput,options(empty.fetch));
  assert.equal(receipt.disposition,"unchanged");
  assert.equal(receipt.recordId,null);
  assert.equal(receipt.mapping.state,"absent");
  assert.ok(!empty.calls.some((call) => ["POST","PUT","DELETE"].includes(call.init.method)));
});

test("absent with one match issues exactly one DELETE and returns removed", async () => {
  const one=fixture([{id:"existing",...input.mapping}]);
  const receipt=await reconcileCloudflareDnsRecord(absentInput,options(one.fetch));
  assert.equal(receipt.disposition,"removed");
  assert.equal(receipt.recordId,"existing");
  const deletes=one.calls.filter((call) => call.init.method==="DELETE");
  assert.equal(deletes.length,1);
  assert.equal(deletes[0].url,"https://api.cloudflare.com/client/v4/zones/zone/dns_records/existing");
});

test("absent with two matches refuses ambiguous mutation", async () => {
  const duplicate=fixture([{id:"one",...input.mapping},{id:"two",...input.mapping}]);
  await assert.rejects(reconcileCloudflareDnsRecord(absentInput,options(duplicate.fetch)),/duplicate/);
});

test("mapping.state of anything but present or absent refuses with a TypeError", async () => {
  await assert.rejects(
    reconcileCloudflareDnsRecord({...absentInput,mapping:{...absentInput.mapping,state:"sideways"}},options(fixture().fetch)),
    TypeError
  );
});

const TEST_ENVIRONMENT_VARIABLE = "CLOUDFLARE_DNS_RECONCILIATION_TEST_TOKEN";
const tokenAuthentication = {token:{environmentVariable:TEST_ENVIRONMENT_VARIABLE},scopes:["dns:write"]};
const tokenInput = {authentication:tokenAuthentication,mapping:absentInput.mapping};

test("token authentication issues the Bearer header from the environment variable and skips keyring inspection", async () => {
  process.env[TEST_ENVIRONMENT_VARIABLE] = "dummy";
  try {
    const empty = fixture();
    const receipt = await reconcileCloudflareDnsRecord(tokenInput, {fetch: empty.fetch});
    assert.equal(receipt.disposition, "unchanged");
    assert.equal(receipt.inspection.mode, "environment-token");
    assert.equal(receipt.inspection.environmentVariable, TEST_ENVIRONMENT_VARIABLE);
    assert.equal(receipt.inspection.credentialReturned, false);
    assert.ok(empty.calls.length > 0);
    for (const call of empty.calls) assert.equal(call.init.headers.authorization, "Bearer dummy");
  } finally {
    delete process.env[TEST_ENVIRONMENT_VARIABLE];
  }
});

test("token authentication refuses with TOKEN_ENVIRONMENT_VARIABLE_UNSET when the environment variable is unset", async () => {
  delete process.env[TEST_ENVIRONMENT_VARIABLE];
  await assert.rejects(
    reconcileCloudflareDnsRecord(tokenInput, {fetch: fixture().fetch}),
    (error) => error.code === "TOKEN_ENVIRONMENT_VARIABLE_UNSET"
  );
});

test("authentication carrying both profile and token refuses", async () => {
  await assert.rejects(
    reconcileCloudflareDnsRecord(
      {...tokenInput, authentication:{...tokenAuthentication, profile:"named-profile"}},
      {fetch: fixture().fetch}
    ),
    TypeError
  );
});
