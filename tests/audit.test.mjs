import test from "node:test";
import assert from "node:assert/strict";
import {auditManifest} from "../audit.js";

test("low-permission manifest stays low priority",()=>{const r=auditManifest({manifest_version:3,permissions:["storage"]});assert.equal(r.level,"Low review priority");});
test("permission combinations receive additional findings",()=>{const r=auditManifest({manifest_version:3,permissions:["cookies","tabs","webRequest"],host_permissions:["<all_urls>"]});assert.ok(r.score>=70);assert.ok(r.findings.some(x=>x.title.includes("cookies + broad hosts")));});
test("optional sensitive permissions still appear in capability review",()=>{const r=auditManifest({manifest_version:3,optional_permissions:["history"]});assert.ok(r.permissions.includes("history"));});
test("non-object input is rejected",()=>assert.throws(()=>auditManifest([]),/JSON object/));
