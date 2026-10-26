#!/usr/bin/env node
import process from "node:process";
import { reconcileCloudflareDnsRecord } from "../src/reconcile-cloudflare-dns-record.mjs";

let input = "";
for await (const chunk of process.stdin) input += chunk;
try { process.stdout.write(`${JSON.stringify(await reconcileCloudflareDnsRecord(JSON.parse(input)))}\n`); }
catch (error) { process.stderr.write(`reconcile-cloudflare-dns-record: ${error.message}\n`); process.exitCode = 1; }
