import {auditManifest} from "./audit.js";
const el = id => document.getElementById(id);
const demo = {manifest_version:3,name:"Synthetic Research Helper",permissions:["tabs","cookies","webRequest","nativeMessaging"],host_permissions:["<all_urls>"]};

function render() {
  try {
    const result = auditManifest(JSON.parse(el("manifest").value));
    el("score").textContent = result.score;
    el("level").textContent = result.level;
    el("summary").textContent = result.disclaimer;
    el("findings").replaceChildren(...result.findings.map(item => {
      const node = document.createElement("article");
      node.className = item.severity;
      const title = document.createElement("strong"); title.textContent = item.title;
      const detail = document.createElement("p"); detail.textContent = item.detail;
      node.append(title, detail); return node;
    }));
    el("questions").replaceChildren(...result.questions.map(text => {const li=document.createElement("li");li.textContent=text;return li;}));
  } catch (error) { el("summary").textContent = error.message; }
}
el("audit").addEventListener("click", render);
el("demo").addEventListener("click", () => {el("manifest").value=JSON.stringify(demo,null,2);render();});
