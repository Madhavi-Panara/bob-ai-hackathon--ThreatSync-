let DATA
let liveTimer=null;

async function runLiveAnalysis(){

    try{

        const response = await fetch("/api/live", {
            method: "POST"
        });

        const data = await response.json();

        DATA = data.dashboard;

        updateDashboard();

        document.getElementById("liveCount").textContent =
            DATA.summary.live_alerts;

    }
    catch(error){

        console.log("Live analysis error:", error);

    }
}
const $=s=>document.querySelector(s);
const esc=s=>String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));
const badge=v=>`<span class="badge ${v.toLowerCase()}">${v}</span>`;
const scoreBar=s=>`<div class="score"><b>${s}</b><div class="bar"><i style="width:${Math.min(100,s*2.5)}%"></i></div></div>`;

async function load(){ const r=await fetch("/api/dashboard"); DATA=await r.json(); render("command"); }

function shell(title,sub,body){
 return `<section class="page"><div class="page-head"><div><h2>${title}</h2><p>${sub}</p></div></div>${body}</section>`;
}

function stats(){
 const s=DATA.summary;
 return `<div class="stats">
  <div class="stat"><span>RAW ALERTS</span><strong>${s.total_alerts}</strong><small>multi-source signals</small></div>
  <div class="stat"><span>CORRELATED INCIDENTS</span><strong>${s.total_incidents}</strong><small>after correlation</small></div>
  <div class="stat critical"><span>CRITICAL</span><strong>${s.critical}</strong><small>immediate attention</small></div>
  <div class="stat high"><span>HIGH</span><strong>${s.high}</strong><small>investigate now</small></div>
 </div>`;
}

function pipeline(){
 return `<div class="pipeline">
  <div><b>${DATA.summary.total_alerts}</b><span>Raw Alerts</span></div><em>→</em>
  <div><b>${DATA.summary.total_incidents}</b><span>Incidents</span></div><em>→</em>
  <div><b>${DATA.summary.critical+DATA.summary.high}</b><span>Priority</span></div><em>→</em>
  <div><b>BLUF</b><span>Decision Ready</span></div>
 </div>`;
}

function incidentCard(x){
 return `<article class="incident ${x.verdict.toLowerCase()}" onclick="openIncident('${x.id}')">
  <div class="incident-top"><div><span class="inc-id">${x.id}</span>${badge(x.verdict)}</div><span class="chev">›</span></div>
  <h3>${esc(x.bottom_line.split(".")[0])}.</h3>
  <p>${esc(x.bottom_line)}</p>
  <div class="meta"><span>⚑ ${x.alert_count} correlated alerts</span><span>◈ ${x.sources.length} sources</span><span>ATT&CK ${x.techniques.join(", ")||"—"}</span></div>
  ${scoreBar(x.score)}
 </article>`;
}

function command(){
 const critical=DATA.incidents.filter(x=>x.verdict==="CRITICAL");
 return shell("Command Center","One view for what matters now — from raw signals to commander-ready decisions.",
 stats()+pipeline()+
 `<div class="section-title"><h3>Priority Threat Feed</h3><button class="linkbtn" onclick="render('incidents')">View all incidents →</button></div>
 <div class="incident-grid">${DATA.incidents.map(incidentCard).join("")}</div>
 <div class="two-col"><div class="panel"><h3>Threat Sources</h3>${["SIEM","CyberSensor","SatelliteFeed","IntelReport"].map(src=>{
  const n=DATA.alerts.filter(a=>a.source===src).length; return `<div class="source-row"><span>${src}</span><b>${n}</b><div class="tinybar"><i style="width:${n/DATA.summary.total_alerts*100}%"></i></div></div>`}).join("")}</div>
 <div class="panel"><h3>Decision Snapshot</h3><div class="decision"><span>Highest risk</span><b>${DATA.incidents[0].id} · ${DATA.incidents[0].score}</b></div><div class="decision"><span>Top target</span><b>${DATA.incidents[0].target}</b></div><div class="decision"><span>ATT&CK techniques</span><b>${new Set(DATA.incidents.flatMap(x=>x.techniques)).size}</b></div></div></div>`);
}

function incidents(){
 return shell("Incident Management","Correlated alerts are grouped into incidents and ranked using an explainable risk score.",
 `<div class="toolbar"><input id="incidentSearch" placeholder="Search incident, target, source or ATT&CK..." oninput="filterIncidents()"><select id="severityFilter" onchange="filterIncidents()"><option>ALL</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select></div>
 <div id="incidentList" class="incident-grid">${DATA.incidents.map(incidentCard).join("")}</div>`);
}

function alerts(){
 return shell("Alert Intelligence","Search and inspect the normalized multi-source alert stream.",
 `<div class="toolbar"><input id="alertSearch" placeholder="Search IP, target, source, description..." oninput="filterAlerts()"><select id="sourceFilter" onchange="filterAlerts()"><option>ALL SOURCES</option><option>SIEM</option><option>CyberSensor</option><option>SatelliteFeed</option><option>IntelReport</option></select></div>
 <div class="table-wrap"><table><thead><tr><th>TIME</th><th>SOURCE</th><th>ALERT</th><th>TARGET</th><th>SEVERITY</th><th>SOURCE IP</th></tr></thead><tbody id="alertRows">${DATA.alerts.map(a=>`<tr><td>${a.timestamp.slice(11)}</td><td><span class="source">${a.source}</span></td><td>${esc(a.description)}</td><td>${a.target}</td><td>${"●".repeat(a.severity)}</td><td class="mono">${a.src_ip}</td></tr>`).join("")}</tbody></table></div>`);
}

function mitre(){
 const used={}; DATA.incidents.forEach(i=>i.techniques.forEach(t=>used[t]=(used[t]||0)+1));
 return shell("MITRE ATT&CK Mapping","See which attacker techniques are represented across correlated incidents.",
 `<div class="mitre-grid">${Object.entries(DATA.mitre).map(([id,m])=>`<div class="mitre-card ${used[id]?'used':''}"><div class="mitre-id">${id}</div><h3>${m.name}</h3><p>${m.tactic}</p><strong>${used[id]||0} incident${used[id]===1?"":"s"}</strong></div>`).join("")}</div>`);
}

function bluf(){
 return shell("BLUF Reports","Bottom Line Up Front summaries turn technical correlation into commander-ready decisions.",
 `<div class="bluf-list">${DATA.incidents.map(x=>`<article class="bluf-row" onclick="openIncident('${x.id}')"><div>${badge(x.verdict)}<span class="inc-id">${x.id}</span></div><div><h3>${esc(x.bottom_line)}</h3><p><b>Action:</b> ${esc(x.action)}</p></div><div class="bluf-score">${x.score}</div></article>`).join("")}</div>`);
}

function render(page){
 document.querySelectorAll(".nav").forEach(n=>n.classList.toggle("active",n.dataset.page===page));
 $("#main").innerHTML={command,incidents,alerts,mitre,bluf}[page]();
}

function openIncident(id){
 const x=DATA.incidents.find(i=>i.id===id);
 $("#modalBody").innerHTML=`<div class="modal-kicker">${badge(x.verdict)} <span>${x.id}</span></div>
 <h2>Bottom Line Up Front</h2><div class="bluf-big">${esc(x.bottom_line)}</div>
 <div class="modal-stats"><div><span>RISK SCORE</span><b>${x.score}</b></div><div><span>ALERTS</span><b>${x.alert_count}</b></div><div><span>SOURCES</span><b>${x.sources.length}</b></div></div>
 <div class="modal-section"><h3>Recommended Action</h3><p>${esc(x.action)}</p></div>
 <div class="modal-section"><h3>MITRE ATT&CK</h3><div class="chips">${x.techniques.map(t=>`<span>${t} · ${DATA.mitre[t].name}</span>`).join("")}</div></div>
 <div class="modal-section"><h3>Correlated Evidence</h3><div class="evidence">${x.alerts.map(a=>`<div><b>${a.source}</b><span>${a.timestamp.slice(11)}</span><p>${esc(a.description)}</p></div>`).join("")}</div></div>`;
 $("#modal").classList.remove("hidden");
}
function filterIncidents(){let q=$("#incidentSearch").value.toLowerCase(),v=$("#severityFilter").value;$("#incidentList").innerHTML=DATA.incidents.filter(x=>(v==="ALL"||x.verdict===v)&&(`${x.id} ${x.target} ${x.sources.join(" ")} ${x.techniques.join(" ")}`).toLowerCase().includes(q)).map(incidentCard).join("")||"<div class='empty'>No matching incidents.</div>"}
function filterAlerts(){let q=$("#alertSearch").value.toLowerCase(),v=$("#sourceFilter").value;$("#alertRows").innerHTML=DATA.alerts.filter(a=>(v==="ALL SOURCES"||a.source===v)&&JSON.stringify(a).toLowerCase().includes(q)).map(a=>`<tr><td>${a.timestamp.slice(11)}</td><td><span class="source">${a.source}</span></td><td>${esc(a.description)}</td><td>${a.target}</td><td>${"●".repeat(a.severity)}</td><td class="mono">${a.src_ip}</td></tr>`).join("")||"<tr><td colspan='6'>No matching alerts.</td></tr>"}
document.addEventListener("click",e=>{const n=e.target.closest(".nav");if(n)render(n.dataset.page);if(e.target.id==="closeModal"||e.target.id==="modal")$("#modal").classList.add("hidden");});
$("#refreshBtn").addEventListener("click",load);
load();
liveTimer = setInterval(runLiveAnalysis,5000);