import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
const root = new URL("..", import.meta.url).pathname; const out = join(root,"dist","mcp-oauth-metadata-lab");
await rm(join(root,"dist"),{recursive:true,force:true}); await mkdir(out,{recursive:true});
const files=["index.html","styles.css","cli.mjs","server.mjs","package.json","package-lock.json","plugin.json","README.md","LICENSE","PRIVACY.md","SECURITY.md","SUPPORT.md","CONTRIBUTING.md","CODE_OF_CONDUCT.md","CHANGELOG.md","src","examples","skills","docs","launch"];
for(const file of files) await cp(join(root,file),join(out,file),{recursive:true});
const walk=async(dir)=>{const {readdir}=await import("node:fs/promises");const entries=await readdir(dir,{withFileTypes:true});const result=[];for(const e of entries){const p=join(dir,e.name);if(e.isDirectory())result.push(...await walk(p));else result.push(p)}return result};
const sums={};for(const file of (await walk(out)).sort()){const data=await readFile(file);sums[file.slice(out.length+1)]=createHash("sha256").update(data).digest("hex")}await writeFile(join(root,"dist","SHA256SUMS.json"),`${JSON.stringify(sums,null,2)}\n`);
