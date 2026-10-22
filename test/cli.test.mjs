import test from "node:test";import assert from "node:assert/strict";import {spawnSync} from "node:child_process";
test("CLI succeeds for valid fixture",()=>{const r=spawnSync(process.execPath,["cli.mjs","examples/valid.json"],{encoding:"utf8"});assert.equal(r.status,0);assert.match(r.stdout,/"reviewed"/)});
test("CLI fails findings gate for unsafe fixture",()=>{const r=spawnSync(process.execPath,["cli.mjs","examples/unsafe.json"],{encoding:"utf8"});assert.equal(r.status,1);assert.match(r.stdout,/pkce-s256-missing/)});
test("CLI usage is actionable",()=>{const r=spawnSync(process.execPath,["cli.mjs"],{encoding:"utf8"});assert.equal(r.status,2);assert.match(r.stdout,/Usage:/)});
test("CLI malformed JSON is safely rejected",()=>{const r=spawnSync(process.execPath,["cli.mjs","package.json","--markdown"],{encoding:"utf8"});assert.equal(r.status,2);assert.match(r.stderr,/Audit failed:/)});
