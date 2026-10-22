import { analyzeBundle, formatMarkdown } from "./core.mjs";
const input = document.querySelector("#fixture");
const output = document.querySelector("#output");
async function loadExample(name) { input.value = await (await fetch(`examples/${name}.json`)).text(); }
document.querySelector("#valid").addEventListener("click", () => loadExample("valid"));
document.querySelector("#unsafe").addEventListener("click", () => loadExample("unsafe"));
document.querySelector("#audit").addEventListener("click", () => { try { const report = analyzeBundle(JSON.parse(input.value)); output.textContent = formatMarkdown(report); output.focus(); } catch (error) { output.textContent = `Could not analyze fixture: ${error.message}`; output.focus(); } });
await loadExample("valid");
