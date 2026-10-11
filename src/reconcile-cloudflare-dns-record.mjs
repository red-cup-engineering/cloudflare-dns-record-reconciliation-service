import { inspectLinuxCloudflareAuthentication } from "@red-cup-engineering/linux-cloudflare-authentication-service";
import { createWranglerKeyringAuthoritySubstrate } from "@red-cup-engineering/linux-cloudflare-authentication-service/keyring-substrate";

const text = (value, name) => {
  if (typeof value !== "string" || !value.trim()) throw new TypeError(`${name} must be a non-empty string`);
  return value.trim();
};

function validateAuthentication(authentication) {
  if (!authentication?.scopes?.includes("dns:write")) throw new TypeError("authentication must explicitly request dns:write");
  if (authentication.profile !== undefined && authentication.token !== undefined) {
    throw new TypeError("authentication must not declare both profile and token");
  }
  if (authentication.token !== undefined) {
    if (typeof authentication.token !== "object" || authentication.token === null) {
      throw new TypeError("authentication.token must be an object");
    }
    text(authentication.token.environmentVariable, "authentication.token.environmentVariable");
  }
  return authentication;
}

function validate(input) {
  const authentication = validateAuthentication(input?.authentication);
  const candidate = input.mapping;
  if (!candidate || typeof candidate !== "object") throw new TypeError("mapping is required");
  const state = candidate.state === undefined ? "present" : candidate.state;
  if (state !== "present" && state !== "absent") throw new TypeError("mapping.state must be \"present\" or \"absent\"");
  const zone = text(candidate.zone, "mapping.zone").toLowerCase();
  const type = text(candidate.type, "mapping.type").toUpperCase();
  const name = text(candidate.name, "mapping.name").toLowerCase();
  if (!new Set(["A", "AAAA", "CNAME", "TXT"]).has(type)) throw new TypeError("mapping.type is not admitted");
  if (!name.endsWith(zone)) throw new TypeError("mapping name or ttl is invalid");
  if (state === "absent") return { authentication: input.authentication, mapping: Object.freeze({ zone, type, name, state }) };
  const mapping = Object.freeze({
    zone, type, name, state,
    content: text(candidate.content, "mapping.content"),
    proxied: candidate.proxied === true,
    ttl: Number(candidate.ttl)
  });
  if (!Number.isInteger(mapping.ttl) || mapping.ttl < 1) throw new TypeError("mapping name or ttl is invalid");
  return { authentication: input.authentication, mapping };
}

async function cloudflare(fetchImpl, token, path, init = {}) {
  const response = await fetchImpl(`https://api.cloudflare.com/client/v4${path}`, {...init, headers:{authorization:`Bearer ${token}`,...(init.headers ?? {})}});
  const body = await response.json();
  if (!response.ok || body.success !== true) throw new Error(`Cloudflare DNS request refused: ${JSON.stringify(body.errors ?? [])}`);
  return body.result;
}

/**
 * Resolve the bearer token and a non-secret inspection receipt for one
 * declared authentication shape (named keyring profile, or an environment
 * variable holding a Cloudflare API token).
 * @throws {Error} with `.code === "TOKEN_ENVIRONMENT_VARIABLE_UNSET"` when the token shape's environment variable is empty or unset.
 */
async function authenticateCloudflare(authentication, options) {
  if (authentication.token) {
    const environmentVariable = authentication.token.environmentVariable;
    const credential = process.env[environmentVariable];
    if (typeof credential !== "string" || !credential) {
      const error = new Error(`environment variable ${environmentVariable} is unset`);
      error.code = "TOKEN_ENVIRONMENT_VARIABLE_UNSET";
      throw error;
    }
    return {
      token: credential,
      inspection: Object.freeze({ mode: "environment-token", environmentVariable, credentialReturned: false })
    };
  }
  const inspection = await (options.inspect ?? inspectLinuxCloudflareAuthentication)(authentication, options);
  const credential = options.profileCredential
    ? await options.profileCredential(authentication.profile)
    : await createWranglerKeyringAuthoritySubstrate(options.keyring).readProfile(authentication.profile);
  const token = credential?.oauthToken;
  if (typeof token !== "string" || !token) throw new Error("named profile has no OAuth token");
  return { token, inspection };
}

/** Reconcile one declared Cloudflare DNS record through one verified profile or environment-token authentication. */
export async function reconcileCloudflareDnsRecord(input, options = {}) {
  const {authentication, mapping} = validate(input);
  const {token, inspection} = await authenticateCloudflare(authentication, options);
  const fetchImpl = options.fetch ?? fetch;
  const zones = await cloudflare(fetchImpl, token, `/zones?name=${encodeURIComponent(mapping.zone)}`);
  if (!Array.isArray(zones) || zones.length !== 1 || zones[0]?.name !== mapping.zone) throw new Error("Cloudflare zone resolution is not exact");
  const zoneId = zones[0].id;
  const records = await cloudflare(fetchImpl, token, `/zones/${zoneId}/dns_records?type=${mapping.type}&name=${encodeURIComponent(mapping.name)}`);
  const matches = Array.isArray(records) ? records.filter((record) => record.type === mapping.type && record.name === mapping.name) : [];
  if (matches.length > 1) throw new Error(`duplicate ${mapping.name} ${mapping.type} records refuse ambiguous mutation`);
  if (mapping.state === "absent") {
    if (matches.length === 0) return Object.freeze({type:"CloudflareDnsReconciliationReceipt",disposition:"unchanged",zoneId,recordId:null,mapping,inspection,credentialReturned:false});
    await cloudflare(fetchImpl, token, `/zones/${zoneId}/dns_records/${matches[0].id}`, {method:"DELETE"});
    return Object.freeze({type:"CloudflareDnsReconciliationReceipt",disposition:"removed",zoneId,recordId:matches[0].id,mapping,inspection,credentialReturned:false});
  }
  const same = (record) => record.content === mapping.content && record.proxied === mapping.proxied && record.ttl === mapping.ttl;
  if (matches.length === 1 && same(matches[0])) return Object.freeze({type:"CloudflareDnsReconciliationReceipt",disposition:"unchanged",zoneId,recordId:matches[0].id,mapping,inspection,credentialReturned:false});
  const method = matches.length ? "PUT" : "POST";
  const path = matches.length ? `/zones/${zoneId}/dns_records/${matches[0].id}` : `/zones/${zoneId}/dns_records`;
  const result = await cloudflare(fetchImpl, token, path, {method,headers:{"content-type":"application/json"},body:JSON.stringify(mapping)});
  return Object.freeze({type:"CloudflareDnsReconciliationReceipt",disposition:matches.length?"updated":"created",zoneId,recordId:result.id,mapping,inspection,credentialReturned:false});
}
