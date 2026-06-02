"use client";

import { useState, useCallback, useRef, useEffect } from "react";
import ReactFlow, {
  Background,
  Controls,
  useNodesState,
  useEdgesState,
  Handle,
  Position,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

// ─── Design Tokens ─────────────────────────────────────────────────────────────
const T = {
  bg0:    "#0a0b0d",
  bg1:    "#0f1117",
  bg2:    "#141720",
  bg3:    "#1c2030",
  bg4:    "#242840",
  border: "#1e2235",
  border2:"#2a2f4a",
  text0:  "#e8eaf2",
  text1:  "#9299b8",
  text2:  "#5a6080",
  text3:  "#3a3f5c",
  accent: "#4a7fa5",
  accent2:"#5c9cc5",
};

const RISK_CONFIG = {
  CRITICAL: { bg:"#2a0f0f", border:"#8b2020", text:"#e05555", dot:"#e05555" },
  HIGH:     { bg:"#2a1a0a", border:"#8b5a15", text:"#d4891a", dot:"#d4891a" },
  MEDIUM:   { bg:"#1e1e0a", border:"#6b5c10", text:"#c4a820", dot:"#c4a820" },
  LOW:      { bg:"#0a1e12", border:"#1e6b36", text:"#3db864", dot:"#3db864" },
};

// ─── Seed Data ─────────────────────────────────────────────────────────────────
const SEED_NODES = [
  { id:"internet",      type:"hostNode",     position:{x:260,y:10},  data:{label:"Internet",      sub:"External",          type:"internet", ip:"0.0.0.0/0",    critical:false, vuln_count:0 }},
  { id:"web-server",    type:"hostNode",     position:{x:260,y:110}, data:{label:"web-server-01", sub:"DMZ · nginx 1.18",  type:"host",     ip:"203.0.113.10", critical:false, vuln_count:2 }},
  { id:"cve-log4shell", type:"vulnNode",     position:{x:60,y:220},  data:{label:"CVE-2021-44228",sub:"Log4Shell · RCE",   cvss:10.0, exploitable:true }},
  { id:"cve-openssh",   type:"vulnNode",     position:{x:460,y:220}, data:{label:"CVE-2023-38408",sub:"OpenSSH · RCE",     cvss:9.8,  exploitable:true }},
  { id:"app-server",    type:"hostNode",     position:{x:260,y:330}, data:{label:"app-server-01", sub:"Internal · Tomcat", type:"host",     ip:"10.0.1.20",    critical:false, vuln_count:1 }},
  { id:"cve-pwnkit",    type:"vulnNode",     position:{x:460,y:430}, data:{label:"CVE-2021-4034", sub:"PwnKit · Priv Esc", cvss:7.8,  exploitable:true }},
  { id:"db-server",     type:"hostNode",     position:{x:260,y:520}, data:{label:"db-server-01",  sub:"Internal · Critical",type:"host",    ip:"10.0.2.50",    critical:true,  vuln_count:1 }},
  { id:"postgres",      type:"databaseNode", position:{x:60,y:620},  data:{label:"production-db", sub:"PostgreSQL · PII" }},
  { id:"root-user",     type:"userNode",     position:{x:460,y:620}, data:{label:"root",          sub:"Admin account",     is_admin:true }},
];

const SEED_EDGES = [
  { id:"e1", source:"internet",     target:"web-server",    type:"attackEdge", data:{label:"CONNECTS_TO"  }},
  { id:"e2", source:"web-server",   target:"cve-log4shell", type:"attackEdge", data:{label:"HAS_VULN"     }},
  { id:"e3", source:"web-server",   target:"cve-openssh",   type:"attackEdge", data:{label:"HAS_VULN"     }},
  { id:"e4", source:"web-server",   target:"app-server",    type:"attackEdge", data:{label:"CONNECTS_TO"  }},
  { id:"e5", source:"app-server",   target:"cve-pwnkit",    type:"attackEdge", data:{label:"HAS_VULN"     }},
  { id:"e6", source:"app-server",   target:"db-server",     type:"attackEdge", data:{label:"CONNECTS_TO"  }},
  { id:"e7", source:"db-server",    target:"postgres",      type:"attackEdge", data:{label:"RUNS"         }},
  { id:"e8", source:"cve-pwnkit",   target:"root-user",     type:"attackEdge", data:{label:"ESCALATES_TO" }},
  { id:"e9", source:"root-user",    target:"postgres",      type:"attackEdge", data:{label:"CAN_ACCESS"   }},
];

// ─── Custom Nodes ──────────────────────────────────────────────────────────────
function HostNode({ data, selected }) {
  const isInternet = data.type === "internet";
  const bg     = isInternet ? T.bg3 : data.critical ? "#1a1020" : "#1e3a5f";
  const border = isInternet ? T.border2 : data.critical ? "#5a2a6a" : "#2a4a6a";
  const dot    = data.critical ? "#9b59b6" : isInternet ? T.text2 : T.accent;
  return (
    <div style={{ background:bg, border:`1px solid ${selected ? T.accent2 : border}`, borderRadius:8, padding:"9px 13px", minWidth:150, cursor:"pointer" }}>
      <Handle type="target" position={Position.Top}    style={{ background:T.accent, border:"none", width:6, height:6 }} />
      <div style={{ display:"flex", alignItems:"center", gap:8 }}>
        <div style={{ width:7, height:7, borderRadius:"50%", background:dot, flexShrink:0 }} />
        <div style={{ minWidth:0 }}>
          <div style={{ fontSize:12, fontWeight:600, color:T.text0, fontFamily:"'IBM Plex Mono',monospace", whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis" }}>{data.label}</div>
          <div style={{ fontSize:10, color:T.text1, marginTop:1 }}>{data.sub}</div>
          {data.ip && <div style={{ fontSize:10, color:T.text2, fontFamily:"'IBM Plex Mono',monospace", marginTop:1 }}>{data.ip}</div>}
          {data.vuln_count > 0 && (
            <div style={{ marginTop:5, display:"inline-flex", alignItems:"center", gap:4, background:"#2a1a0a", border:"1px solid #5a3a10", borderRadius:4, padding:"1px 6px" }}>
              <div style={{ width:4, height:4, borderRadius:"50%", background:"#d4891a" }} />
              <span style={{ fontSize:9, color:"#d4891a", fontWeight:600 }}>{data.vuln_count} VULN{data.vuln_count>1?"S":""}</span>
            </div>
          )}
        </div>
      </div>
      <Handle type="source" position={Position.Bottom} style={{ background:T.accent, border:"none", width:6, height:6 }} />
    </div>
  );
}

function VulnNode({ data, selected }) {
  const color  = data.cvss>=9 ? "#e05555" : data.cvss>=7 ? "#d4891a" : "#c4a820";
  const bg     = data.cvss>=9 ? "#200a0a" : data.cvss>=7 ? "#201008" : "#18180a";
  const border = data.cvss>=9 ? "#6a2020" : data.cvss>=7 ? "#6a4010" : "#5a5010";
  return (
    <div style={{ background:bg, border:`1px solid ${selected ? color : border}`, borderRadius:8, padding:"9px 13px", minWidth:140, cursor:"pointer" }}>
      <Handle type="target" position={Position.Top}    style={{ background:color, border:"none", width:6, height:6 }} />
      <div style={{ display:"flex", alignItems:"flex-start", gap:7 }}>
        <div style={{ width:6, height:6, borderRadius:1, background:color, flexShrink:0, marginTop:3 }} />
        <div style={{ minWidth:0 }}>
          <div style={{ fontSize:11, fontWeight:700, color, fontFamily:"'IBM Plex Mono',monospace", whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis" }}>{data.label}</div>
          <div style={{ fontSize:10, color:T.text1, marginTop:1 }}>{data.sub}</div>
          <div style={{ marginTop:4, display:"flex", gap:4, flexWrap:"wrap" }}>
            <span style={{ fontSize:9, fontWeight:700, color, background:`${color}18`, border:`1px solid ${color}40`, borderRadius:3, padding:"1px 5px" }}>CVSS {data.cvss.toFixed(1)}</span>
            {data.exploitable && <span style={{ fontSize:9, fontWeight:600, color:"#e05555", border:"1px solid #6a202080", borderRadius:3, padding:"1px 5px" }}>EXPLOIT</span>}
          </div>
        </div>
      </div>
      <Handle type="source" position={Position.Bottom} style={{ background:color, border:"none", width:6, height:6 }} />
    </div>
  );
}

function DatabaseNode({ data, selected }) {
  return (
    <div style={{ background:"#3d1e5f", border:`1px solid ${selected?"#9b59b6":"#4a2a6a"}`, borderRadius:8, padding:"9px 13px", minWidth:145, cursor:"pointer" }}>
      <Handle type="target" position={Position.Top}    style={{ background:"#9b59b6", border:"none", width:6, height:6 }} />
      <div style={{ display:"flex", alignItems:"center", gap:8 }}>
        <div style={{ width:7, height:7, borderRadius:1, background:"#9b59b6", flexShrink:0 }} />
        <div style={{ minWidth:0 }}>
          <div style={{ fontSize:12, fontWeight:600, color:"#c39bd3", fontFamily:"'IBM Plex Mono',monospace", whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis" }}>{data.label}</div>
          <div style={{ fontSize:10, color:T.text1, marginTop:1 }}>{data.sub}</div>
        </div>
      </div>
      <Handle type="source" position={Position.Bottom} style={{ background:"#9b59b6", border:"none", width:6, height:6 }} />
    </div>
  );
}

function UserNode({ data, selected }) {
  return (
    <div style={{ background:"#1e3d50", border:`1px solid ${selected?"#5dade2":"#2a4d6a"}`, borderRadius:8, padding:"9px 13px", minWidth:140, cursor:"pointer" }}>
      <Handle type="target" position={Position.Top}    style={{ background:"#5dade2", border:"none", width:6, height:6 }} />
      <div style={{ display:"flex", alignItems:"center", gap:8 }}>
        <div style={{ width:7, height:7, borderRadius:"50%", background:data.is_admin?"#e74c3c":"#5dade2", flexShrink:0 }} />
        <div style={{ minWidth:0 }}>
          <div style={{ fontSize:12, fontWeight:600, color:T.text0, fontFamily:"'IBM Plex Mono',monospace" }}>{data.label}</div>
          <div style={{ fontSize:10, color:T.text1, marginTop:1 }}>{data.sub}</div>
          {data.is_admin && (
            <div style={{ marginTop:4, display:"inline-flex", alignItems:"center", background:"#2a0808", border:"1px solid #8b2020", borderRadius:4, padding:"1px 6px" }}>
              <span style={{ fontSize:9, color:"#e05555", fontWeight:700 }}>ROOT</span>
            </div>
          )}
        </div>
      </div>
      <Handle type="source" position={Position.Bottom} style={{ background:"#5dade2", border:"none", width:6, height:6 }} />
    </div>
  );
}

function AttackEdge({ id, sourceX, sourceY, targetX, targetY, data, selected }) {
  const midY = (sourceY + targetY) / 2;
  const d = `M ${sourceX} ${sourceY} C ${sourceX} ${midY} ${targetX} ${midY} ${targetX} ${targetY}`;
  const isRisk = ["HAS_VULN","ESCALATES_TO"].includes(data?.label);
  const stroke = isRisk ? (selected?"#e05555":"#5a2020") : (selected?T.accent2:T.border2);
  return (
    <g>
      <path id={id} d={d} fill="none" stroke={stroke} strokeWidth={selected?1.5:0.8} strokeDasharray={isRisk?"none":"4 3"} />
      {data?.label && (
        <text style={{ fontSize:9, fontFamily:"'IBM Plex Mono',monospace" }} fill={T.text2}>
          <textPath href={`#${id}`} startOffset="50%" textAnchor="middle">{data.label}</textPath>
        </text>
      )}
    </g>
  );
}

const nodeTypes = { hostNode:HostNode, vulnNode:VulnNode, databaseNode:DatabaseNode, userNode:UserNode };
const edgeTypes = { attackEdge:AttackEdge };

// ─── UI Primitives ─────────────────────────────────────────────────────────────
function RiskBadge({ level, size="sm" }) {
  const cfg = RISK_CONFIG[level] || RISK_CONFIG.LOW;
  return (
    <span style={{ display:"inline-flex", alignItems:"center", gap:5, background:cfg.bg, border:`1px solid ${cfg.border}`, borderRadius:4, padding:size==="lg"?"5px 12px":"2px 8px", fontSize:size==="lg"?12:10, fontWeight:700, color:cfg.text, fontFamily:"'IBM Plex Mono',monospace", letterSpacing:"0.08em" }}>
      <span style={{ width:5, height:5, borderRadius:"50%", background:cfg.dot, flexShrink:0 }} />
      {level}
    </span>
  );
}

function MetricCard({ label, value, sub, accent }) {
  return (
    <div style={{ background:T.bg2, border:`1px solid ${T.border}`, borderRadius:8, padding:"12px 14px", flex:1, minWidth:0 }}>
      <div style={{ fontSize:9, color:T.text2, textTransform:"uppercase", letterSpacing:"0.1em", fontWeight:600, marginBottom:5 }}>{label}</div>
      <div style={{ fontSize:20, fontWeight:700, color:accent||T.text0, fontFamily:"'IBM Plex Mono',monospace", lineHeight:1 }}>{value}</div>
      {sub && <div style={{ fontSize:9, color:T.text2, marginTop:4 }}>{sub}</div>}
    </div>
  );
}

// ─── Bottom Nav (mobile) ───────────────────────────────────────────────────────
function BottomNav({ activeView, setActiveView }) {
  const items = [
    { id:"graph",    label:"Graph",    icon:"⬡" },
    { id:"analysis", label:"Analysis", icon:"◈" },
    { id:"assets",   label:"Assets",   icon:"○" },
  ];
  return (
    <div style={{ display:"flex", background:T.bg1, borderTop:`1px solid ${T.border}`, flexShrink:0 }}>
      {items.map(item => (
        <button key={item.id} onClick={() => setActiveView(item.id)} style={{ flex:1, border:"none", background:"none", padding:"10px 0 8px", cursor:"pointer", display:"flex", flexDirection:"column", alignItems:"center", gap:3 }}>
          <span style={{ fontSize:18, color:activeView===item.id ? T.accent2 : T.text2 }}>{item.icon}</span>
          <span style={{ fontSize:9, fontWeight:600, color:activeView===item.id ? T.accent2 : T.text2, letterSpacing:"0.06em", textTransform:"uppercase" }}>{item.label}</span>
        </button>
      ))}
    </div>
  );
}

// ─── Desktop Sidebar ───────────────────────────────────────────────────────────
function Sidebar({ activeView, setActiveView }) {
  const items = [
    { id:"graph",    label:"Attack Graph", icon:"⬡" },
    { id:"analysis", label:"AI Analysis",  icon:"◈" },
    { id:"assets",   label:"Assets",       icon:"○" },
  ];
  return (
    <div style={{ width:56, background:T.bg1, borderRight:`1px solid ${T.border}`, display:"flex", flexDirection:"column", alignItems:"center", padding:"16px 0", gap:4, flexShrink:0 }}>
      <div style={{ width:28, height:28, background:T.accent, borderRadius:6, display:"flex", alignItems:"center", justifyContent:"center", marginBottom:20 }}>
        <span style={{ color:"#fff", fontSize:13, fontWeight:700 }}>A</span>
      </div>
      {items.map(item => (
        <button key={item.id} onClick={() => setActiveView(item.id)} title={item.label} style={{ width:36, height:36, border:"none", borderRadius:7, cursor:"pointer", background:activeView===item.id ? T.bg4 : "transparent", color:activeView===item.id ? T.text0 : T.text2, fontSize:16, display:"flex", alignItems:"center", justifyContent:"center", transition:"all 0.15s" }}>
          {item.icon}
        </button>
      ))}
    </div>
  );
}

// ─── Analysis Panel ────────────────────────────────────────────────────────────
function AnalysisPanel({ onAnalyze, result, loading, isMobile }) {
  const [query, setQuery] = useState("How can an attacker reach the database?");

  const EXAMPLES = [
    "How can an attacker reach the database?",
    "What is the blast radius if web-server-01 is compromised?",
    "Show all privilege escalation paths to root",
  ];

  return (
    <div style={{ display:"flex", flexDirection:"column", height:"100%", overflow:"hidden" }}>
      {/* Input */}
      <div style={{ padding:isMobile?"12px":"16px", borderBottom:`1px solid ${T.border}`, flexShrink:0 }}>
        <div style={{ fontSize:10, color:T.text2, textTransform:"uppercase", letterSpacing:"0.1em", fontWeight:600, marginBottom:8 }}>AI ATTACK ANALYSIS</div>
        <textarea
          value={query}
          onChange={e => setQuery(e.target.value)}
          rows={isMobile ? 2 : 3}
          style={{ width:"100%", background:T.bg3, border:`1px solid ${T.border2}`, borderRadius:6, padding:"9px 11px", color:T.text0, fontSize:13, fontFamily:"'IBM Plex Sans',sans-serif", resize:"none", outline:"none", boxSizing:"border-box", lineHeight:1.5 }}
          placeholder="Ask about attack paths..."
        />
        <button
          onClick={() => onAnalyze(query)}
          disabled={loading}
          style={{ width:"100%", marginTop:8, background:loading ? T.bg3 : T.accent, border:"none", borderRadius:6, padding:"9px 0", color:loading ? T.text2 : "#fff", fontSize:12, fontWeight:600, cursor:loading?"not-allowed":"pointer", transition:"background 0.15s" }}
        >
          {loading ? "Analyzing..." : "Run Analysis ◈"}
        </button>
        {/* Example queries — hidden on smallest screens to save space */}
        {!isMobile && (
          <div style={{ marginTop:10 }}>
            <div style={{ fontSize:9, color:T.text3, marginBottom:5, textTransform:"uppercase", letterSpacing:"0.08em" }}>Examples</div>
            {EXAMPLES.map(q => (
              <button key={q} onClick={() => setQuery(q)} style={{ display:"block", width:"100%", background:"none", border:"none", textAlign:"left", color:T.text2, fontSize:10, cursor:"pointer", padding:"3px 0 3px 8px", borderLeft:`2px solid ${T.border2}`, marginBottom:3, lineHeight:1.4, fontFamily:"'IBM Plex Sans',sans-serif" }}>{q}</button>
            ))}
          </div>
        )}
      </div>

      {/* Results */}
      <div style={{ flex:1, overflowY:"auto", padding:isMobile?"12px":"16px" }}>
        {loading && (
          <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
            {["Parsing query...","Traversing graph...","Enriching CVEs...","Scoring paths..."].map((s,i) => (
              <div key={s} style={{ display:"flex", alignItems:"center", gap:8, opacity:1-i*0.2 }}>
                <div style={{ width:6, height:6, borderRadius:"50%", background:i===0?T.accent2:T.border2 }} />
                <span style={{ fontSize:11, color:i===0?T.text1:T.text2 }}>{s}</span>
              </div>
            ))}
          </div>
        )}

        {result && !loading && (
          <div style={{ display:"flex", flexDirection:"column", gap:12 }}>
            <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", flexWrap:"wrap", gap:6 }}>
              <RiskBadge level={result.risk_level} size="lg" />
              <span style={{ fontSize:10, color:T.text2 }}>{result.duration_ms}ms · {result.total_paths_found} paths</span>
            </div>

            <div style={{ background:T.bg3, border:`1px solid ${T.border}`, borderRadius:6, padding:"11px 13px" }}>
              <div style={{ fontSize:9, color:T.text2, textTransform:"uppercase", letterSpacing:"0.1em", marginBottom:6, fontWeight:600 }}>EXECUTIVE SUMMARY</div>
              <p style={{ fontSize:12, color:T.text1, lineHeight:1.65, margin:0 }}>{result.executive_summary}</p>
            </div>

            {result.path_summaries?.length > 0 && (
              <div>
                <div style={{ fontSize:9, color:T.text2, textTransform:"uppercase", letterSpacing:"0.1em", marginBottom:6, fontWeight:600 }}>ATTACK PATHS</div>
                {result.path_summaries.map((p,i) => (
                  <div key={i} style={{ background:T.bg3, border:`1px solid ${T.border}`, borderRadius:5, padding:"7px 11px", marginBottom:4, fontSize:11, color:T.text1, fontFamily:"'IBM Plex Mono',monospace", lineHeight:1.5 }}>
                    <span style={{ color:T.text2, marginRight:7 }}>#{i+1}</span>{p}
                  </div>
                ))}
              </div>
            )}

            {result.recommendations?.length > 0 && (
              <div>
                <div style={{ fontSize:9, color:T.text2, textTransform:"uppercase", letterSpacing:"0.1em", marginBottom:6, fontWeight:600 }}>REMEDIATION</div>
                {result.recommendations.map((rec,i) => (
                  <div key={i} style={{ display:"flex", gap:9, marginBottom:7, padding:"8px 11px", background:T.bg3, border:`1px solid ${T.border}`, borderRadius:5 }}>
                    <div style={{ width:18, height:18, borderRadius:4, background:i===0?"#2a1a0a":T.bg4, border:`1px solid ${i===0?"#8b5a15":T.border}`, display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0 }}>
                      <span style={{ fontSize:9, fontWeight:700, color:i===0?"#d4891a":T.text2 }}>{i+1}</span>
                    </div>
                    <p style={{ fontSize:11, color:T.text1, margin:0, lineHeight:1.5 }}>{rec}</p>
                  </div>
                ))}
              </div>
            )}

            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:6 }}>
              {[
                { label:"MAX CVSS",    value:result.highest_cvss?.toFixed(1), accent:result.highest_cvss>=9?"#e05555":"#d4891a" },
                { label:"PUBLIC XPLOIT", value:result.has_public_exploit?"YES":"NO", accent:result.has_public_exploit?"#e05555":"#3db864" },
                { label:"ACT NOW",     value:result.immediate_action_required?"YES":"NO", accent:result.immediate_action_required?"#e05555":"#3db864" },
              ].map(m => (
                <div key={m.label} style={{ background:T.bg3, border:`1px solid ${T.border}`, borderRadius:5, padding:"8px 10px" }}>
                  <div style={{ fontSize:8, color:T.text2, marginBottom:3, textTransform:"uppercase", letterSpacing:"0.08em" }}>{m.label}</div>
                  <div style={{ fontSize:16, fontWeight:700, color:m.accent, fontFamily:"'IBM Plex Mono',monospace" }}>{m.value}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {!result && !loading && (
          <div style={{ textAlign:"center", padding:"32px 0" }}>
            <div style={{ fontSize:24, marginBottom:10, opacity:0.25 }}>◈</div>
            <div style={{ fontSize:12, color:T.text2, lineHeight:1.6 }}>Run a query to see AI-powered attack path analysis</div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Assets View ──────────────────────────────────────────────────────────────
function AssetsView() {
  const assets = [
    { name:"web-server-01", ip:"203.0.113.10", type:"Host",     risk:"HIGH",   vulns:2 },
    { name:"app-server-01", ip:"10.0.1.20",    type:"Host",     risk:"HIGH",   vulns:1 },
    { name:"db-server-01",  ip:"10.0.2.50",    type:"Host",     risk:"MEDIUM", vulns:1 },
    { name:"production-db", ip:"—",            type:"Database", risk:"HIGH",   vulns:0 },
  ];
  return (
    <div style={{ padding:16, overflowY:"auto", height:"100%" }}>
      <div style={{ fontSize:10, color:T.text2, textTransform:"uppercase", letterSpacing:"0.1em", fontWeight:600, marginBottom:12 }}>ASSETS</div>
      {assets.map(a => (
        <div key={a.name} style={{ background:T.bg2, border:`1px solid ${T.border}`, borderRadius:8, padding:"11px 14px", marginBottom:8, display:"flex", alignItems:"center", justifyContent:"space-between", gap:10 }}>
          <div style={{ minWidth:0 }}>
            <div style={{ fontSize:12, fontWeight:600, color:T.text0, fontFamily:"'IBM Plex Mono',monospace", whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis" }}>{a.name}</div>
            <div style={{ fontSize:10, color:T.text2, marginTop:2 }}>{a.type} · {a.ip}</div>
          </div>
          <div style={{ display:"flex", alignItems:"center", gap:8, flexShrink:0 }}>
            {a.vulns > 0 && <span style={{ fontSize:10, color:"#d4891a", background:"#2a1a0a", border:"1px solid #5a3a10", borderRadius:4, padding:"2px 7px" }}>{a.vulns}V</span>}
            <RiskBadge level={a.risk} />
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────
const MOCK_RESULT = {
  session_id:"demo",
  query:"How can an attacker reach the database?",
  risk_level:"HIGH",
  executive_summary:"Attackers can reach the production database by first exploiting CVE-2021-44228 (Log4Shell) on web-server-01 for initial access, pivoting to app-server-01, then using CVE-2021-4034 (PwnKit) to escalate privileges to root before accessing production-db.",
  path_summaries:[
    "web-server-01 → app-server-01 → production-db via CVE-2021-4034 (PwnKit)",
    "web-server-01 → app-server-01 → db-server-01 → production-db",
  ],
  recommendations:[
    "[P1] Patch CVE-2021-4034 on app-server-01 immediately — eliminates privilege escalation (Effort: LOW)",
    "[P2] Network segmentation between app-server-01 and database tier (Effort: MEDIUM)",
    "[P3] Upgrade Log4j2 on web-server-01 to 2.17.1+ (Effort: LOW)",
  ],
  total_paths_found:2,
  highest_cvss:10.0,
  has_public_exploit:true,
  immediate_action_required:true,
  duration_ms:27276,
  error:null,
};

export default function AttackGraphDashboard() {
  const [activeView, setActiveView]     = useState("graph");
  const [nodes, setNodes, onNodesChange] = useNodesState(SEED_NODES);
  const [edges, setEdges, onEdgesChange] = useEdgesState(SEED_EDGES);
  const [result, setResult]             = useState(null);
  const [loading, setLoading]           = useState(false);
  const [isMobile, setIsMobile]         = useState(false);

  // Detect mobile
  useEffect(() => {
    const check = () => setIsMobile(window.innerWidth < 768);
    check();
    window.addEventListener("resize", check);
    return () => window.removeEventListener("resize", check);
  }, []);

  const handleAnalyze = useCallback(async (query) => {
    setLoading(true);
    if (isMobile) setActiveView("analysis");
    try {
      const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
      const res = await fetch(`${API}/api/v1/analysis/analyze`, {
        method:"POST",
        headers:{ "Content-Type":"application/json" },
        body:JSON.stringify({ query, max_hops:8 }),
      });
      setResult(res.ok ? await res.json() : MOCK_RESULT);
    } catch {
      setResult(MOCK_RESULT);
    } finally {
      setLoading(false);
    }
  }, [isMobile]);

  // ── Mobile Layout ────────────────────────────────────────────────────────────
  if (isMobile) {
    return (
      <div style={{ display:"flex", flexDirection:"column", height:"100dvh", background:T.bg0, color:T.text0, fontFamily:"'IBM Plex Sans',sans-serif", overflow:"hidden" }}>
        {/* Top bar */}
        <div style={{ height:44, background:T.bg1, borderBottom:`1px solid ${T.border}`, display:"flex", alignItems:"center", padding:"0 16px", gap:10, flexShrink:0 }}>
          <div style={{ width:24, height:24, background:T.accent, borderRadius:5, display:"flex", alignItems:"center", justifyContent:"center" }}>
            <span style={{ color:"#fff", fontSize:11, fontWeight:700 }}>A</span>
          </div>
          <span style={{ fontSize:13, fontWeight:600, color:T.text0 }}>AttackGraph</span>
          <span style={{ fontSize:10, color:T.text2, fontFamily:"'IBM Plex Mono',monospace" }}>AI</span>
          <div style={{ flex:1 }} />
          <div style={{ display:"flex", alignItems:"center", gap:4 }}>
            <div style={{ width:5, height:5, borderRadius:"50%", background:"#3db864" }} />
            <span style={{ fontSize:9, color:T.text2 }}>Live</span>
          </div>
        </div>

        {/* Metrics strip */}
        <div style={{ display:"flex", gap:8, padding:"8px 12px", borderBottom:`1px solid ${T.border}`, flexShrink:0, overflowX:"auto" }}>
          {[
            { label:"Hosts",   value:"4",    accent:T.text0 },
            { label:"Vulns",   value:"4",    accent:"#d4891a" },
            { label:"Paths",   value:"2",    accent:"#e05555" },
            { label:"CVSS",    value:"10.0", accent:"#e05555" },
          ].map(m => (
            <div key={m.label} style={{ background:T.bg2, border:`1px solid ${T.border}`, borderRadius:7, padding:"7px 12px", flexShrink:0 }}>
              <div style={{ fontSize:8, color:T.text2, textTransform:"uppercase", letterSpacing:"0.08em", marginBottom:3 }}>{m.label}</div>
              <div style={{ fontSize:16, fontWeight:700, color:m.accent, fontFamily:"'IBM Plex Mono',monospace", lineHeight:1 }}>{m.value}</div>
            </div>
          ))}
        </div>

        {/* Content */}
        <div style={{ flex:1, overflow:"hidden" }}>
          {activeView === "graph" && (
            <div style={{ height:"100%", position:"relative" }}>
              <button
                onClick={() => handleAnalyze("How can an attacker reach the database?")}
                style={{ position:"absolute", bottom:16, left:"50%", transform:"translateX(-50%)", zIndex:10, background:T.accent, border:"none", borderRadius:6, padding:"9px 20px", color:"#fff", fontSize:12, fontWeight:600, cursor:"pointer", whiteSpace:"nowrap" }}
              >
                Analyze with AI ◈
              </button>
              <ReactFlow nodes={nodes} edges={edges} onNodesChange={onNodesChange} onEdgesChange={onEdgesChange} nodeTypes={nodeTypes} edgeTypes={edgeTypes} fitView fitViewOptions={{ padding:0.15 }} style={{ background:T.bg0 }} proOptions={{ hideAttribution:true }}>
                <Background color={T.border} gap={28} size={0.5} />
              </ReactFlow>
            </div>
          )}
          {activeView === "analysis" && (
            <AnalysisPanel onAnalyze={handleAnalyze} result={result} loading={loading} isMobile={true} />
          )}
          {activeView === "assets" && <AssetsView />}
        </div>

        {/* Bottom nav */}
        <BottomNav activeView={activeView} setActiveView={setActiveView} />

        <style>{`
          @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600;700&family=IBM+Plex+Sans:wght@400;500;600&display=swap');
          ::-webkit-scrollbar{width:3px;height:3px}
          ::-webkit-scrollbar-track{background:transparent}
          ::-webkit-scrollbar-thumb{background:${T.border2};border-radius:2px}
          *{-webkit-tap-highlight-color:transparent;box-sizing:border-box}
          textarea{-webkit-appearance:none}
        `}</style>
      </div>
    );
  }

  // ── Desktop Layout ────────────────────────────────────────────────────────────
  return (
    <div style={{ display:"flex", height:"100vh", background:T.bg0, color:T.text0, fontFamily:"'IBM Plex Sans',sans-serif", overflow:"hidden" }}>
      <Sidebar activeView={activeView} setActiveView={setActiveView} />

      <div style={{ flex:1, display:"flex", flexDirection:"column", overflow:"hidden" }}>
        {/* Top bar */}
        <div style={{ height:44, background:T.bg1, borderBottom:`1px solid ${T.border}`, display:"flex", alignItems:"center", padding:"0 20px", gap:12, flexShrink:0 }}>
          <span style={{ fontSize:13, fontWeight:600, color:T.text0 }}>AttackGraph</span>
          <span style={{ fontSize:10, color:T.text2, fontFamily:"'IBM Plex Mono',monospace" }}>AI</span>
          <div style={{ flex:1 }} />
          {[["Neo4j","#3db864"],["Qdrant","#3db864"],["Gemini","#3db864"]].map(([name,color]) => (
            <div key={name} style={{ display:"flex", alignItems:"center", gap:5 }}>
              <div style={{ width:6, height:6, borderRadius:"50%", background:color }} />
              <span style={{ fontSize:10, color:T.text2 }}>{name}</span>
            </div>
          ))}
        </div>

        {/* Metrics */}
        <div style={{ padding:"10px 16px", borderBottom:`1px solid ${T.border}`, display:"flex", gap:8, flexShrink:0 }}>
          <MetricCard label="Total Hosts"    value="4"    sub="1 internet-facing" />
          <MetricCard label="Vulnerabilities"value="4"    sub="3 exploitable"     accent="#d4891a" />
          <MetricCard label="Attack Paths"   value="2"    sub="to database"       accent="#e05555" />
          <MetricCard label="Highest CVSS"   value="10.0" sub="CVE-2021-44228"    accent="#e05555" />
          <MetricCard label="Risk Level"     value={<RiskBadge level="HIGH" size="lg" />} sub="Immediate action" />
        </div>

        {/* Body */}
        <div style={{ flex:1, display:"flex", overflow:"hidden" }}>
          {/* Graph */}
          <div style={{ flex:1, position:"relative", overflow:"hidden", display:activeView==="analysis"?"none":"block" }}>
            <div style={{ position:"absolute", top:12, left:12, zIndex:10, fontSize:10, color:T.text2, textTransform:"uppercase", letterSpacing:"0.1em", fontWeight:600 }}>ATTACK GRAPH</div>
            <button onClick={() => handleAnalyze("How can an attacker reach the database?")} style={{ position:"absolute", bottom:16, left:"50%", transform:"translateX(-50%)", zIndex:10, background:T.accent, border:"none", borderRadius:6, padding:"8px 20px", color:"#fff", fontSize:12, fontWeight:600, cursor:"pointer" }}>
              Analyze with AI ◈
            </button>
            <ReactFlow nodes={nodes} edges={edges} onNodesChange={onNodesChange} onEdgesChange={onEdgesChange} nodeTypes={nodeTypes} edgeTypes={edgeTypes} fitView fitViewOptions={{ padding:0.2 }} style={{ background:T.bg0 }} proOptions={{ hideAttribution:true }}>
              <Background color={T.border} gap={28} size={0.5} />
              <Controls style={{ background:T.bg2, border:`1px solid ${T.border}`, borderRadius:8 }} />
            </ReactFlow>
          </div>

          {/* Analysis full width */}
          {activeView === "analysis" && (
            <div style={{ flex:1, overflow:"hidden", borderLeft:`1px solid ${T.border}` }}>
              <AnalysisPanel onAnalyze={handleAnalyze} result={result} loading={loading} isMobile={false} />
            </div>
          )}

          {/* Right panel alongside graph */}
          {activeView !== "analysis" && (
            <div style={{ width:300, borderLeft:`1px solid ${T.border}`, background:T.bg1, overflow:"hidden", flexShrink:0 }}>
              {activeView === "assets" ? <AssetsView /> : <AnalysisPanel onAnalyze={handleAnalyze} result={result} loading={loading} isMobile={false} />}
            </div>
          )}
        </div>
      </div>

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600;700&family=IBM+Plex+Sans:wght@400;500;600&display=swap');
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.3}}
        ::-webkit-scrollbar{width:4px}
        ::-webkit-scrollbar-track{background:transparent}
        ::-webkit-scrollbar-thumb{background:${T.border2};border-radius:2px}
        .react-flow__controls button{background:${T.bg2}!important;border-color:${T.border}!important;color:${T.text1}!important}
        *{box-sizing:border-box}
      `}</style>
    </div>
  );
}
