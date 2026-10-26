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

test("dry runs plan create, update, removal and no change without any writes", async () => {
  for (const [request, records, action] of [
    [input, [], "create"],
    [input, [{id:"old",...input.mapping,content:"old.example"}], "update"],
    [input, [{id:"exact",...input.mapping}], "none"],
    [absentInput, [{id:"existing",...input.mapping}], "remove"],
    [absentInput, [], "none"]
  ]) {
    const transport = fixture(records);
    const receipt = await reconcileCloudflareDnsRecord({...request,dryRun:true},options(transport.fetch));
    assert.equal(receipt.disposition,"planned");
    assert.equal(receipt.action,action);
    assert.equal(receipt.dryRun,true);
    assert.equal(receipt.before?.id ?? null,records[0]?.id ?? null);
    assert.equal(transport.calls.length,2);
    assert.ok(transport.calls.every(call => call.init.method === undefined));
  }
});

test("token dry run accepts read authority without loading the keyring provider", async () => {
  process.env[TEST_ENVIRONMENT_VARIABLE] = "private-dns-test-token";
  try {
    const transport=fixture();
    const request={...input,dryRun:true,authentication:{...tokenAuthentication,scopes:["dns:read"]}};
    const receipt=await reconcileCloudflareDnsRecord(request,{fetch:transport.fetch});
    assert.equal(receipt.action,"create");
    assert.equal(receipt.inspection.mode,"environment-token");
    assert.ok(!JSON.stringify(receipt).includes(process.env[TEST_ENVIRONMENT_VARIABLE]));
    const reads=transport.calls.length;
    await assert.rejects(reconcileCloudflareDnsRecord({...request,dryRun:false},{fetch:transport.fetch}),/dns:write/);
    assert.equal(transport.calls.length,reads);
  } finally { delete process.env[TEST_ENVIRONMENT_VARIABLE]; }
});

test("accepted plans refuse stale records and lost absence before mutation", async () => {
  const old={id:"old",...input.mapping,content:"old.example"};
  const plan=await reconcileCloudflareDnsRecord({...input,dryRun:true},options(fixture([old]).fetch));
  for (const records of [[],[{...old,id:"replacement"}],[{...old,content:"changed.example"}]]) {
    const transport=fixture(records);
    await assert.rejects(reconcileCloudflareDnsRecord({...input,expectedRecord:plan.before},options(transport.fetch)),/changed since/);
    assert.ok(transport.calls.every(call => call.init.method === undefined));
  }
  const created=fixture([old]);
  await assert.rejects(reconcileCloudflareDnsRecord({...input,expectedRecord:null},options(created.fetch)),/changed since/);
  assert.ok(created.calls.every(call => call.init.method === undefined));
  const unchanged=fixture([old]);
  const applied=await reconcileCloudflareDnsRecord({...input,expectedRecord:plan.before},options(unchanged.fetch));
  assert.equal(applied.disposition,"updated");
  assert.equal(unchanged.calls.filter(call => call.init.method === "PUT").length,1);
});

test("invalid dry runs and suffix-lookalike zones refuse before transport", async () => {
  const transport=fixture();
  await assert.rejects(reconcileCloudflareDnsRecord({...input,dryRun:"true"},options(transport.fetch)),/dryRun/);
  await assert.rejects(reconcileCloudflareDnsRecord({...input,mapping:{...input.mapping,name:"app.notexample.test"}},options(transport.fetch)),/mapping name/);
  assert.equal(transport.calls.length,0);
});

test("an unreadable record collection cannot become an absence or create plan", async () => {
  for (const dryRun of [true,false]) {
    const transport=fixture({unexpected:"record-shape"});
    await assert.rejects(reconcileCloudflareDnsRecord({...input,dryRun},options(transport.fetch)),/not an array/);
    assert.ok(transport.calls.every(call => call.init.method === undefined));
  }
});

test("an environment token binds a supplied account before reading or changing records", async () => {
  process.env[TEST_ENVIRONMENT_VARIABLE] = "account-bound-test-token";
  try {
    const expectedAccountId = "0123456789abcdef0123456789abcdef";
    for (const dryRun of [true,false]) {
      const request = {...tokenInput,dryRun,authentication:{...tokenAuthentication,expectedAccountId}};
      for (const account of [undefined,{id:"fedcba9876543210fedcba9876543210"}]) {
        const calls=[];
        const fetch = async(url) => { calls.push(url); return response([{id:"zone",name:"example.test",account}]); };
        await assert.rejects(reconcileCloudflareDnsRecord(request,{fetch}),/expected account/);
        assert.equal(calls.length,1);
      }
      const transport=fixture();
      const fetch = (url,init) => url.endsWith("/zones?name=example.test")
        ? Promise.resolve(response([{id:"zone",name:"example.test",account:{id:expectedAccountId}}]))
        : transport.fetch(url,init);
      const receipt=await reconcileCloudflareDnsRecord(request,{fetch});
      assert.equal(receipt.disposition,dryRun ? "planned" : "unchanged");
      assert.equal(transport.calls.length,1);
    }
    let called=false;
    await assert.rejects(reconcileCloudflareDnsRecord({...tokenInput,authentication:{...tokenAuthentication,expectedAccountId:"bad-id"}},
      {fetch:async()=>{called=true;}}),/32-character/);
    assert.equal(called,false);
  } finally { delete process.env[TEST_ENVIRONMENT_VARIABLE]; }
});

test("plans expose same-name address and CNAME conflicts and apply never removes them", async () => {
  for (const [mapping, conflicting] of [
    [input.mapping,{id:"address",...input.mapping,type:"A",content:"192.0.2.1"}],
    [input.mapping,{id:"address-v6",...input.mapping,type:"AAAA",content:"2001:db8::1"}],
    [{...input.mapping,type:"A",content:"192.0.2.1"},{id:"alias",...input.mapping}],
    [{...input.mapping,type:"AAAA",content:"2001:db8::1"},{id:"alias",...input.mapping}]
  ]) {
    const transport=fixture([conflicting]);
    const request={...input,mapping};
    const receipt=await reconcileCloudflareDnsRecord({...request,dryRun:true},options(transport.fetch));
    assert.equal(receipt.action,"blocked");
    assert.equal(receipt.before,null);
    const {zone,...observed}=conflicting;
    assert.deepEqual(receipt.conflicts,[observed]);
    assert.match(transport.calls[1].url,/dns_records\?name=app\.example\.test&per_page=100$/);
    await assert.rejects(reconcileCloudflareDnsRecord(request,options(transport.fetch)),/Conflicting/);
    assert.ok(transport.calls.every(call => call.init.method === undefined));
    const absent=await reconcileCloudflareDnsRecord({...request,dryRun:true,mapping:{...mapping,state:"absent"}},options(fixture([conflicting]).fetch));
    assert.equal(absent.action,"none");
    assert.deepEqual(absent.conflicts,[]);
  }
  const elsewhere=fixture([{id:"elsewhere",...input.mapping,name:"other.example.test",type:"A",content:"192.0.2.2"}]);
  const receipt=await reconcileCloudflareDnsRecord({...input,dryRun:true},options(elsewhere.fetch));
  assert.equal(receipt.action,"create");
  assert.deepEqual(receipt.conflicts,[]);
});

test("an incomplete record page cannot authorize a plan or mutation", async () => {
  for (const dryRun of [true,false]) {
    const calls=[];
    const fetch=async(url,init={})=>{
      calls.push({url,init});
      return url.endsWith("/zones?name=example.test") ? response([{id:"zone",name:"example.test"}]) :
        {ok:true,json:async()=>({success:true,result:[],result_info:{total_pages:2}})};
    };
    await assert.rejects(reconcileCloudflareDnsRecord({...input,dryRun},options(fetch)),/incomplete across pages/);
    assert.ok(calls.every(call => call.init.method === undefined));
  }
});

