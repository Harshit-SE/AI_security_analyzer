/**
 * OmniScan — Frontend
 *
 * Fully updated to use the Local Node.js Backend + Ollama (Llama 3 / Phi-3)
 * No external API calls!
 */

import { useState, useCallback, useRef } from "react";

// ─── Design Tokens ────────────────────────────────────────────────────────────

const SEVERITY_CONFIG = {
  Critical: { color: "#ff3b30", bg: "#ff3b3015", border: "#ff3b3040", rank: 0 },
  High:     { color: "#ff9500", bg: "#ff950015", border: "#ff950040", rank: 1 },
  Medium:   { color: "#ffcc00", bg: "#ffcc0015", border: "#ffcc0040", rank: 2 },
  Low:      { color: "#34c759", bg: "#34c75915", border: "#34c75940", rank: 3 },
  Info:     { color: "#636366", bg: "#63636615", border: "#63636640", rank: 4 },
};

const PRIORITY_CONFIG = {
  Immediate:    { color: "#ff3b30", bg: "#ff3b3020", border: "#ff3b3040" },
  "Short-term": { color: "#ff9500", bg: "#ff950020", border: "#ff950040" },
  "Long-term":  { color: "#34c759", bg: "#34c75920", border: "#34c75940" },
};

const PERSONAS = [
  { value: "beginner",  label: "Script Kiddie",      icon: "◈", desc: "Public tools, noisy" },
  { value: "insider",   label: "Insider Threat",     icon: "◉", desc: "Internal access, patient" },
  { value: "advanced",  label: "APT / Nation-State", icon: "◆", desc: "Custom exploits, persistent" },
];

const EXPLAIN_MODES = [
  { value: "beginner",  label: "Beginner",  desc: "Plain language" },
  { value: "developer", label: "Developer", desc: "Code examples" },
  { value: "expert",    label: "Expert",    desc: "CVE/CWE depth" },
];

const SCAN_MODES = ["URL", "Code", "API Endpoint"];

const LOADING_MESSAGES = [
  "Initializing scanner...",
  "Running deterministic checks...",
  "Connecting to Local AI RAG...",
  "Loading OWASP knowledge base...",
  "Simulating attacker paths with Ollama...",
  "Chaining vulnerabilities...",
  "Generating fix recommendations...",
  "Finalizing report...",
];

// ─── Safe Default Result Structure ───────────────────────────────────────────

const EMPTY_RESULT = {
  risk_score: 0,
  risk_label: "",
  executive_summary: "",
  vulnerabilities: [],
  attack_paths: [],
  vulnerability_chains: [],
  fixes: [],
  defensive_recommendations: {
    immediate_actions: [],
    security_controls: [],
    monitoring_alerts: [],
  },
};

function normalizeScanResult(raw) {
  if (!raw || typeof raw !== "object") return { ...EMPTY_RESULT };
  const rec = raw.defensive_recommendations;
  return {
    risk_score:        typeof raw.risk_score === "number" ? raw.risk_score : 0,
    risk_label:        typeof raw.risk_label === "string" ? raw.risk_label : "",
    executive_summary: typeof raw.executive_summary === "string" ? raw.executive_summary : "",
    vulnerabilities:      Array.isArray(raw.vulnerabilities)      ? raw.vulnerabilities      : [],
    attack_paths:         Array.isArray(raw.attack_paths)         ? raw.attack_paths         : [],
    vulnerability_chains: Array.isArray(raw.vulnerability_chains) ? raw.vulnerability_chains : [],
    fixes:                Array.isArray(raw.fixes)                ? raw.fixes                : [],
    defensive_recommendations: {
      immediate_actions: Array.isArray(rec?.immediate_actions) ? rec.immediate_actions : [],
      security_controls: Array.isArray(rec?.security_controls) ? rec.security_controls : [],
      monitoring_alerts: Array.isArray(rec?.monitoring_alerts) ? rec.monitoring_alerts : [],
    },
  };
}

// ─── API Layer ────────────────────────────────────────────────────────────────
// API_BASE is read from the build-time environment variable REACT_APP_API_URL.
// Set it in a .env file (e.g. REACT_APP_API_URL=https://api.yourserver.com).
// Falls back to http://localhost:3001 for local development only.
const API_BASE = (process.env.REACT_APP_API_URL || 'http://localhost:3001').replace(/\/$/, '');

async function callScanAPI({ mode, input, goal, persona, explainMode }) {
  let endpoint = '';
  let payload = { goal, persona, explainMode };

  // Route to the correct backend scanner based on the selected tab
  if (mode === 'URL') {
    endpoint = `${API_BASE}/api/scan-url`;
    payload.url = input;
  } else if (mode === 'Code') {
    endpoint = `${API_BASE}/api/scan-code`;
    payload.code = input;
    payload.filename = 'pasted_code.js';
  } else if (mode === 'API Endpoint') {
    endpoint = `${API_BASE}/api/analyze-api`;
    payload.endpoint = input;
    payload.method = 'GET';
  }

  const response = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    let errorMsg = `Backend request failed (HTTP ${response.status})`;
    try {
      const errorData = await response.json();
      if (errorData.error) errorMsg = errorData.error;
    } catch (e) {
      // Ignore JSON parse errors on fallback
    }
    throw new Error(errorMsg);
  }

  const parsed = await response.json();
  return normalizeScanResult(parsed);
}

// ─── Components ───────────────────────────────────────────────────────────────

function RiskGauge({ score, label }) {
  const safeScore = typeof score === "number" && !isNaN(score) ? score : 0;
  const pct = Math.min(safeScore / 10, 1);
  const angle = -135 + pct * 270;
  const color = safeScore >= 8 ? "#ff3b30" : safeScore >= 6 ? "#ff9500" : safeScore >= 4 ? "#ffcc00" : "#34c759";
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 4 }}>
      <svg width="160" height="100" viewBox="0 0 160 100">
        <defs>
          <linearGradient id="gaugeGrad" x1="0%" x2="100%">
            <stop offset="0%" stopColor="#34c759" /><stop offset="50%" stopColor="#ffcc00" /><stop offset="100%" stopColor="#ff3b30" />
          </linearGradient>
        </defs>
        <path d="M 20 90 A 60 60 0 0 1 140 90" fill="none" stroke="#2c2c2e" strokeWidth="10" strokeLinecap="round" />
        <path d="M 20 90 A 60 60 0 0 1 140 90" fill="none" stroke="url(#gaugeGrad)" strokeWidth="10" strokeLinecap="round"
          strokeDasharray="188.5" strokeDashoffset={188.5 * (1 - pct)} style={{ transition: "stroke-dashoffset 1s ease" }} />
        <g transform={`rotate(${angle}, 80, 90)`} style={{ transition: "transform 1s ease" }}>
          <line x1="80" y1="90" x2="80" y2="38" stroke={color} strokeWidth="2.5" strokeLinecap="round" />
          <circle cx="80" cy="90" r="5" fill={color} />
        </g>
        <text x="80" y="82" textAnchor="middle" fontSize="22" fontWeight="700" fill={color}>{safeScore.toFixed(1)}</text>
      </svg>
      {label && <span style={{ fontSize: 13, color, fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase" }}>{label}</span>}
    </div>
  );
}

function SeverityBadge({ severity }) {
  const cfg = SEVERITY_CONFIG[severity] ?? SEVERITY_CONFIG.Info;
  return (
    <span style={{ fontSize: 11, fontWeight: 600, padding: "2px 8px", borderRadius: 4,
      background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.border}`,
      letterSpacing: "0.05em", textTransform: "uppercase", whiteSpace: "nowrap" }}>
      {severity ?? "Unknown"}
    </span>
  );
}

function EmptyState({ icon, message }) {
  return (
    <div style={{ textAlign: "center", padding: "48px 20px", color: "#636366" }}>
      <div style={{ fontSize: 32, marginBottom: 12 }}>{icon}</div>
      <p style={{ fontSize: 14, margin: 0 }}>{message}</p>
    </div>
  );
}

function VulnerabilityCard({ vuln, fix, explainMode }) {
  const [expanded, setExpanded] = useState(false);
  if (!vuln || typeof vuln !== "object") return null;
  const cfg = SEVERITY_CONFIG[vuln.severity] ?? SEVERITY_CONFIG.Info;
  const explainLabel = explainMode === "beginner" ? "📖 What This Means" : explainMode === "expert" ? "🔬 Technical Analysis" : "⚙️ Developer Explanation";
  return (
    <div style={{ background: "#1c1c1e", border: `1px solid ${expanded ? cfg.border : "#2c2c2e"}`,
      borderLeft: `3px solid ${cfg.color}`, borderRadius: 10, overflow: "hidden",
      transition: "border-color 0.2s", marginBottom: 10 }}>
      <button onClick={() => setExpanded(p => !p)} aria-expanded={expanded}
        style={{ width: "100%", display: "flex", alignItems: "center", gap: 12,
          padding: "14px 16px", background: "none", border: "none", cursor: "pointer", color: "inherit", textAlign: "left" }}>
        <SeverityBadge severity={vuln.severity} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontWeight: 600, fontSize: 14, color: "#f2f2f7" }}>{vuln.name ?? "Unknown"}</div>
          <div style={{ fontSize: 12, color: "#636366", marginTop: 2 }}>
            {[vuln.type, vuln.cwe_id, vuln.cvss_score != null ? `CVSS ${Number(vuln.cvss_score).toFixed(1)}` : null].filter(Boolean).join(" · ")}
          </div>
        </div>
        <span style={{ fontSize: 18, color: "#48484a", transform: expanded ? "rotate(90deg)" : "none", transition: "transform 0.2s", flexShrink: 0 }}>›</span>
      </button>
      {expanded && (
        <div style={{ padding: "0 16px 16px", borderTop: "1px solid #2c2c2e" }}>
          <div style={{ paddingTop: 14, display: "flex", flexDirection: "column", gap: 12 }}>
            {vuln.explanation && (
              <div>
                <div style={{ fontSize: 11, color: "#636366", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 6 }}>{explainLabel}</div>
                <p style={{ fontSize: 14, color: "#ebebf5", lineHeight: 1.6, margin: 0 }}>{vuln.explanation}</p>
              </div>
            )}
            {vuln.evidence && (
              <div style={{ background: "#000", borderRadius: 8, padding: "10px 14px" }}>
                <div style={{ fontSize: 11, color: "#636366", marginBottom: 4 }}>Evidence</div>
                <code style={{ fontSize: 12, color: "#ffd60a", wordBreak: "break-all" }}>{vuln.evidence}</code>
              </div>
            )}
            {(vuln.location || vuln.real_world_impact) && (
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                {vuln.location && (
                  <div style={{ flex: 1, minWidth: 120, background: "#2c2c2e", borderRadius: 8, padding: "10px 12px" }}>
                    <div style={{ fontSize: 11, color: "#636366", marginBottom: 4 }}>📍 Location</div>
                    <div style={{ fontSize: 13, color: "#ebebf5" }}>{vuln.location}</div>
                  </div>
                )}
                {vuln.real_world_impact && (
                  <div style={{ flex: 1, minWidth: 120, background: "#2c2c2e", borderRadius: 8, padding: "10px 12px" }}>
                    <div style={{ fontSize: 11, color: "#636366", marginBottom: 4 }}>💥 Real Impact</div>
                    <div style={{ fontSize: 13, color: "#ebebf5" }}>{vuln.real_world_impact}</div>
                  </div>
                )}
              </div>
            )}
            {fix && <FixInline fix={fix} />}
          </div>
        </div>
      )}
    </div>
  );
}

function FixInline({ fix }) {
  if (!fix || typeof fix !== "object") return null;
  const steps = Array.isArray(fix.implementation_steps) ? fix.implementation_steps : [];
  const refs  = Array.isArray(fix.references)           ? fix.references           : [];
  return (
    <div style={{ background: "#0a2a1a", border: "1px solid #1d6038", borderRadius: 8, padding: "12px 14px" }}>
      <div style={{ fontSize: 11, color: "#30d158", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.08em" }}>
        🛡️ Fix · {fix.priority ?? "—"} · ~{fix.estimated_effort ?? "—"}
      </div>
      {fix.fix_summary && <p style={{ fontSize: 13, color: "#ebebf5", margin: "0 0 8px", lineHeight: 1.5 }}>{fix.fix_summary}</p>}
      {steps.length > 0 && (
        <ol style={{ margin: 0, paddingLeft: 18 }}>
          {steps.map((s, i) => <li key={i} style={{ fontSize: 13, color: "#8e8e93", marginBottom: 4, lineHeight: 1.5 }}>{s}</li>)}
        </ol>
      )}
      {fix.secure_code_example && (
        <pre style={{ marginTop: 10, background: "#000", padding: 10, borderRadius: 6, fontSize: 12, color: "#30d158", overflow: "auto", maxHeight: 200, border: "1px solid #1d6038" }}>
          {fix.secure_code_example}
        </pre>
      )}
      {refs.length > 0 && (
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 8 }}>
          {refs.map((ref, i) => (
            <a key={i} href={ref} target="_blank" rel="noopener noreferrer"
              style={{ fontSize: 11, color: "#0a84ff", textDecoration: "none", background: "#0a84ff15", padding: "2px 8px", borderRadius: 4, border: "1px solid #0a84ff30" }}>
              {String(ref).replace(/^https?:\/\//, "").split("/")[0]}
            </a>
          ))}
        </div>
      )}
    </div>
  );
}

function AttackPathCard({ path, defaultOpen }) {
  const [expanded, setExpanded] = useState(!!defaultOpen);
  if (!path || typeof path !== "object") return null;
  const steps = Array.isArray(path.steps) ? path.steps : [];
  const prob  = typeof path.success_probability === "number" ? path.success_probability : 0;
  const probColor = prob >= 70 ? "#ff3b30" : prob >= 40 ? "#ff9500" : "#34c759";
  return (
    <div style={{ background: "#1c1c1e", border: "1px solid #2c2c2e", borderRadius: 10, marginBottom: 10, overflow: "hidden" }}>
      <button onClick={() => setExpanded(p => !p)} aria-expanded={expanded}
        style={{ width: "100%", display: "flex", alignItems: "center", gap: 12, padding: "14px 16px", background: "none", border: "none", cursor: "pointer", color: "inherit" }}>
        <div style={{ width: 52, height: 52, borderRadius: 8, background: "#2c2c2e", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
          <span style={{ fontSize: 16, color: probColor, fontWeight: 700 }}>{prob}%</span>
          <span style={{ fontSize: 9, color: "#636366" }}>success</span>
        </div>
        <div style={{ flex: 1, textAlign: "left", minWidth: 0 }}>
          <div style={{ fontWeight: 600, fontSize: 14, color: "#f2f2f7" }}>🎯 {path.goal ?? "Unknown Goal"}</div>
          <div style={{ fontSize: 12, color: "#636366", marginTop: 2 }}>
            {steps.length} step{steps.length !== 1 ? "s" : ""}
            {path.complexity     ? ` · Complexity: ${path.complexity}`    : ""}
            {path.detection_risk ? ` · Detection: ${path.detection_risk}` : ""}
          </div>
        </div>
        <span style={{ fontSize: 18, color: "#48484a", transform: expanded ? "rotate(90deg)" : "none", transition: "transform 0.2s", flexShrink: 0 }}>›</span>
      </button>
      {expanded && (
        <div style={{ padding: "0 16px 16px", borderTop: "1px solid #2c2c2e" }}>
          {path.prerequisites && (
            <div style={{ background: "#2c2c2e", borderRadius: 8, padding: "8px 12px", margin: "12px 0 16px" }}>
              <span style={{ fontSize: 11, color: "#636366" }}>Prerequisites: </span>
              <span style={{ fontSize: 13, color: "#ebebf5" }}>{path.prerequisites}</span>
            </div>
          )}
          {steps.length === 0
            ? <p style={{ color: "#636366", fontSize: 13, margin: 0 }}>No detailed steps provided.</p>
            : steps.map((step, idx) => (
                <div key={idx} style={{ display: "flex", gap: 12 }}>
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "center", width: 36, flexShrink: 0 }}>
                    <div style={{ width: 28, height: 28, borderRadius: "50%", background: "#ff3b3020", border: "1.5px solid #ff3b3060",
                      display: "flex", alignItems: "center", justifyContent: "center", fontSize: 12, fontWeight: 700, color: "#ff3b30", flexShrink: 0 }}>
                      {step.step_number ?? idx + 1}
                    </div>
                    {idx < steps.length - 1 && <div style={{ width: 1, flex: 1, background: "#2c2c2e", margin: "4px 0" }} />}
                  </div>
                  <div style={{ flex: 1, paddingBottom: idx < steps.length - 1 ? 12 : 0, paddingTop: 4 }}>
                    <div style={{ fontWeight: 600, fontSize: 13, color: "#f2f2f7" }}>{step.action ?? "Unknown action"}</div>
                    <div style={{ fontSize: 12, color: "#636366", marginTop: 2 }}>
                      {step.technique && <span style={{ color: "#ff9f0a" }}>{step.technique}</span>}
                      {step.vulnerability_used && <span> · Uses <code style={{ fontSize: 11 }}>{step.vulnerability_used}</code></span>}
                    </div>
                    {step.outcome && <div style={{ fontSize: 12, color: "#8e8e93", marginTop: 4, fontStyle: "italic" }}>→ {step.outcome}</div>}
                  </div>
                </div>
              ))
          }
        </div>
      )}
    </div>
  );
}

function ChainCard({ chain }) {
  if (!chain || typeof chain !== "object") return null;
  const cfg     = SEVERITY_CONFIG[chain.combined_severity] ?? SEVERITY_CONFIG.Medium;
  const vulnIds = Array.isArray(chain.vulnerabilities) ? chain.vulnerabilities : [];
  return (
    <div style={{ background: "#1c1c1e", border: `1px solid ${cfg.border}`, borderRadius: 10, padding: "14px 16px", marginBottom: 10 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8, flexWrap: "wrap", gap: 8 }}>
        <div style={{ fontWeight: 600, fontSize: 14, color: "#f2f2f7" }}>🔗 {chain.title ?? "Unnamed Chain"}</div>
        <div style={{ display: "flex", gap: 6, alignItems: "center", flexShrink: 0 }}>
          <SeverityBadge severity={chain.combined_severity} />
          {chain.combined_cvss != null && <span style={{ fontSize: 12, color: cfg.color, fontWeight: 600 }}>CVSS {Number(chain.combined_cvss).toFixed(1)}</span>}
        </div>
      </div>
      {chain.explanation && <p style={{ fontSize: 13, color: "#8e8e93", margin: "0 0 10px", lineHeight: 1.5 }}>{chain.explanation}</p>}
      {vulnIds.length > 0 && (
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
          {vulnIds.map(id => <span key={id} style={{ fontSize: 11, background: "#2c2c2e", color: "#ebebf5", padding: "2px 8px", borderRadius: 4, fontFamily: "monospace" }}>{id}</span>)}
        </div>
      )}
    </div>
  );
}

function FixCard({ fix, vulnName }) {
  if (!fix || typeof fix !== "object") return null;
  const priorityCfg = PRIORITY_CONFIG[fix.priority] ?? PRIORITY_CONFIG["Long-term"];
  const steps = Array.isArray(fix.implementation_steps) ? fix.implementation_steps : [];
  const refs  = Array.isArray(fix.references)           ? fix.references           : [];
  return (
    <div style={{ background: "#1c1c1e", border: "1px solid #2c2c2e", borderRadius: 10, padding: "16px", marginBottom: 12 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10, gap: 8, flexWrap: "wrap" }}>
        <div style={{ fontWeight: 600, fontSize: 14, color: "#f2f2f7" }}>{vulnName ?? fix.vulnerability_id ?? "Fix"}</div>
        <div style={{ display: "flex", gap: 8, flexShrink: 0 }}>
          {fix.priority && <span style={{ fontSize: 11, padding: "2px 8px", borderRadius: 4, fontWeight: 600, background: priorityCfg.bg, color: priorityCfg.color, border: `1px solid ${priorityCfg.border}` }}>{fix.priority}</span>}
          {fix.estimated_effort && <span style={{ fontSize: 11, color: "#636366", padding: "2px 8px", background: "#2c2c2e", borderRadius: 4 }}>~{fix.estimated_effort}</span>}
        </div>
      </div>
      {fix.fix_summary && <p style={{ fontSize: 14, color: "#ebebf5", margin: "0 0 12px", lineHeight: 1.6 }}>{fix.fix_summary}</p>}
      {steps.length > 0 && (
        <ol style={{ margin: "0 0 12px", paddingLeft: 20 }}>
          {steps.map((s, i) => <li key={i} style={{ fontSize: 13, color: "#8e8e93", marginBottom: 4, lineHeight: 1.5 }}>{s}</li>)}
        </ol>
      )}
      {fix.secure_code_example && (
        <pre style={{ background: "#000", borderRadius: 8, padding: "12px 14px", fontSize: 12, color: "#30d158", overflow: "auto", border: "1px solid #1d6038", maxHeight: 250, margin: "0 0 10px" }}>
          {fix.secure_code_example}
        </pre>
      )}
      {refs.length > 0 && (
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {refs.map((ref, i) => (
            <a key={i} href={ref} target="_blank" rel="noopener noreferrer"
              style={{ fontSize: 11, color: "#0a84ff", textDecoration: "none", background: "#0a84ff15", padding: "2px 8px", borderRadius: 4, border: "1px solid #0a84ff30" }}>
              {String(ref).replace(/^https?:\/\//, "").split("/")[0]}
            </a>
          ))}
        </div>
      )}
    </div>
  );
}

function DefensePanel({ recommendations }) {
  const rec = recommendations ?? {};
  const sections = [
    { key: "immediate_actions", label: "🚨 Immediate Actions",   color: "#ff3b30", fullWidth: true  },
    { key: "security_controls", label: "🛡️ Security Controls",  color: "#0a84ff", fullWidth: false },
    { key: "monitoring_alerts", label: "📡 Monitoring & Alerts", color: "#bf5af2", fullWidth: false },
  ];
  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
      {sections.map(({ key, label, color, fullWidth }) => {
        const items = Array.isArray(rec[key]) ? rec[key] : [];
        return (
          <div key={key} style={{ background: "#1c1c1e", border: `1px solid ${color}30`, borderRadius: 12, padding: "16px", gridColumn: fullWidth ? "1 / -1" : "auto" }}>
            <div style={{ fontWeight: 600, color, marginBottom: 10, fontSize: 14 }}>{label}</div>
            {items.length === 0
              ? <p style={{ fontSize: 13, color: "#636366", margin: 0 }}>No recommendations available.</p>
              : <ul style={{ margin: 0, paddingLeft: 20 }}>
                  {items.map((item, i) => <li key={i} style={{ fontSize: 13, color: "#8e8e93", marginBottom: 6, lineHeight: 1.5 }}>{item}</li>)}
                </ul>
            }
          </div>
        );
      })}
    </div>
  );
}

function TabBar({ tabs, activeTab, onSelect }) {
  return (
    <div style={{ display: "flex", gap: 4, marginBottom: 16, background: "#1c1c1e", borderRadius: 12, padding: 4, border: "1px solid #2c2c2e" }}>
      {tabs.map(tab => (
        <button key={tab.id} onClick={() => onSelect(tab.id)}
          style={{ flex: 1, padding: "9px 8px", borderRadius: 8, border: "none", cursor: "pointer",
            fontSize: 12, fontWeight: 600, transition: "all 0.2s",
            background: activeTab === tab.id ? "#ff3b30" : "transparent",
            color:      activeTab === tab.id ? "#fff"    : "#636366" }}>
          {tab.label}
        </button>
      ))}
    </div>
  );
}

function ResultsSummary({ result }) {
  const critCount = result.vulnerabilities.filter(v => v.severity === "Critical").length;
  const highCount = result.vulnerabilities.filter(v => v.severity === "High").length;
  const stats = [
    { label: "Critical",     count: critCount,                          color: "#ff3b30" },
    { label: "High",         count: highCount,                          color: "#ff9500" },
    { label: "Attack Paths", count: result.attack_paths.length,         color: "#bf5af2" },
    { label: "Chains",       count: result.vulnerability_chains.length, color: "#ff9f0a" },
  ];
  return (
    <div style={{ background: "#1c1c1e", border: "1px solid #2c2c2e", borderRadius: 16, padding: "24px", marginBottom: 20,
      display: "flex", gap: 24, alignItems: "flex-start", flexWrap: "wrap" }}>
      <RiskGauge score={result.risk_score} label={result.risk_label} />
      <div style={{ flex: 1, minWidth: 200 }}>
        <div style={{ fontSize: 11, color: "#636366", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 10 }}>Executive Summary</div>
        <p style={{ fontSize: 14, color: "#ebebf5", lineHeight: 1.7, margin: "0 0 16px" }}>
          {result.executive_summary || "Scan complete — review findings below."}
        </p>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          {stats.map(({ label, count, color }) => (
            <div key={label} style={{ background: "#2c2c2e", borderRadius: 8, padding: "8px 14px", textAlign: "center" }}>
              <div style={{ fontSize: 20, fontWeight: 700, color }}>{count}</div>
              <div style={{ fontSize: 11, color: "#636366" }}>{label}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function ScannerPanel({ onScan, loading, loadingMessage }) {
  const [scanMode,    setScanMode]    = useState("URL");
  const [input,       setInput]       = useState("");
  const [goal,        setGoal]        = useState("");
  const [persona,     setPersona]     = useState("advanced");
  const [explainMode, setExplainMode] = useState("developer");

  const handleScan = () => { if (!input.trim() || loading) return; onScan({ mode: scanMode, input, goal, persona, explainMode }); };
  const handleModeChange = (m) => { setScanMode(m); setInput(""); };

  const inputPlaceholder =
    scanMode === "URL"          ? "https://example.com" :
    scanMode === "API Endpoint" ? "https://api.example.com/v1/users" :
    `Paste source code here...\n\n// Example:\napp.get('/user', (req, res) => {\n  db.query('SELECT * FROM users WHERE id=' + req.query.id);\n});`;

  return (
    <div style={{ background: "#1c1c1e", borderRadius: 16, border: "1px solid #2c2c2e", padding: 20, marginBottom: 20 }}>
      <div style={{ display: "flex", gap: 4, marginBottom: 16, background: "#000", borderRadius: 10, padding: 4 }}>
        {SCAN_MODES.map(m => (
          <button key={m} onClick={() => handleModeChange(m)}
            style={{ flex: 1, padding: "8px 12px", borderRadius: 8, border: "none", cursor: "pointer",
              fontSize: 13, fontWeight: 600, transition: "all 0.2s",
              background: scanMode === m ? "#ff3b30" : "transparent",
              color:      scanMode === m ? "#fff"    : "#636366" }}>
            {m === "URL" ? "🌐 " : m === "Code" ? "📄 " : "🔌 "}{m}
          </button>
        ))}
      </div>

      {scanMode === "Code"
        ? <textarea value={input} onChange={e => setInput(e.target.value)} placeholder={inputPlaceholder} rows={7}
            style={{ width: "100%", resize: "vertical", fontFamily: "monospace", fontSize: 13,
              background: "#000", color: "#f2f2f7", border: "1px solid #3a3a3c", borderRadius: 10,
              padding: "12px 14px", outline: "none", boxSizing: "border-box", lineHeight: 1.6 }} />
        : <input type="text" value={input} onChange={e => setInput(e.target.value)} placeholder={inputPlaceholder}
            onKeyDown={e => e.key === "Enter" && handleScan()}
            style={{ width: "100%", padding: "12px 16px", background: "#1c1c1e", border: "1px solid #3a3a3c",
              borderRadius: 10, color: "#f2f2f7", fontSize: 14, outline: "none", boxSizing: "border-box", fontFamily: "monospace" }} />
      }

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginTop: 14 }}>
        <div>
          <label style={{ fontSize: 11, color: "#636366", display: "block", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.08em" }}>Attacker Goal</label>
          <input value={goal} onChange={e => setGoal(e.target.value)} placeholder="e.g. bypass login"
            style={{ width: "100%", padding: "9px 12px", background: "#000", border: "1px solid #3a3a3c",
              borderRadius: 8, color: "#f2f2f7", fontSize: 13, outline: "none", boxSizing: "border-box" }} />
        </div>
        <div>
          <label style={{ fontSize: 11, color: "#636366", display: "block", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.08em" }}>Explain Mode</label>
          <select value={explainMode} onChange={e => setExplainMode(e.target.value)}
            style={{ width: "100%", padding: "9px 12px", background: "#000", border: "1px solid #3a3a3c",
              borderRadius: 8, color: "#f2f2f7", fontSize: 13, outline: "none", boxSizing: "border-box", cursor: "pointer" }}>
            {EXPLAIN_MODES.map(m => <option key={m.value} value={m.value}>{m.label} – {m.desc}</option>)}
          </select>
        </div>
        <div>
          <label style={{ fontSize: 11, color: "#636366", display: "block", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.08em" }}>Attacker Persona</label>
          <select value={persona} onChange={e => setPersona(e.target.value)}
            style={{ width: "100%", padding: "9px 12px", background: "#000", border: "1px solid #3a3a3c",
              borderRadius: 8, color: "#f2f2f7", fontSize: 13, outline: "none", boxSizing: "border-box", cursor: "pointer" }}>
            {PERSONAS.map(p => <option key={p.value} value={p.value}>{p.icon} {p.label} – {p.desc}</option>)}
          </select>
        </div>
      </div>

      <button onClick={handleScan} disabled={loading || !input.trim()}
        style={{ marginTop: 16, width: "100%", padding: "14px",
          background: loading || !input.trim() ? "#3a3a3c" : "linear-gradient(135deg, #ff3b30, #ff0080)",
          border: "none", borderRadius: 10, color: "#fff", fontSize: 15, fontWeight: 700,
          cursor: loading || !input.trim() ? "not-allowed" : "pointer",
          opacity: !input.trim() && !loading ? 0.5 : 1, transition: "all 0.2s", letterSpacing: "0.02em" }}>
        {loading ? `⟳  ${loadingMessage}` : "▶  Run Security Scan"}
      </button>
    </div>
  );
}

function LoadingDots({ message }) {
  return (
    <div style={{ textAlign: "center", padding: "40px 20px" }}>
      <style>{`@keyframes bounceDot{0%,80%,100%{transform:scale(.6);opacity:.3}40%{transform:scale(1);opacity:1}}`}</style>
      <div style={{ display: "inline-flex", gap: 6, marginBottom: 16 }}>
        {[0,1,2,3,4].map(i => (
          <div key={i} style={{ width: 8, height: 8, borderRadius: "50%", background: "#ff3b30",
            animation: `bounceDot 1.2s ease-in-out ${i * 0.15}s infinite` }} />
        ))}
      </div>
      <p style={{ color: "#636366", fontSize: 14, margin: 0 }}>{message}</p>
    </div>
  );
}

function ErrorBanner({ message, onDismiss }) {
  return (
    <div style={{ background: "#2a0a0a", border: "1px solid #ff3b3040", borderRadius: 12, padding: "14px 16px", marginBottom: 20,
      display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}>
      <div>
        <div style={{ color: "#ff3b30", fontWeight: 600, marginBottom: 4 }}>⚠ Scan Error</div>
        <div style={{ color: "#8e8e93", fontSize: 13 }}>{message}</div>
      </div>
      <button onClick={onDismiss} style={{ background: "none", border: "none", color: "#636366", cursor: "pointer", fontSize: 18, lineHeight: 1, flexShrink: 0 }}>✕</button>
    </div>
  );
}

// ─── Root App Component ───────────────────────────────────────────────────────

export default function App() {
  const [result,         setResult]         = useState(EMPTY_RESULT);
  const [hasResult,      setHasResult]      = useState(false);
  const [loading,        setLoading]        = useState(false);
  const [loadingMessage, setLoadingMessage] = useState("");
  const [error,          setError]          = useState(null);
  const [activeTab,      setActiveTab]      = useState("vulnerabilities");
  const loadingIntervalRef = useRef(null);

  const handleScan = useCallback(async ({ mode, input, goal, persona, explainMode }) => {
    setLoading(true);
    setError(null);
    setHasResult(false);
    setResult(EMPTY_RESULT);
    setActiveTab("vulnerabilities");

    let msgIndex = 0;
    setLoadingMessage(LOADING_MESSAGES[0]);
    loadingIntervalRef.current = setInterval(() => {
      msgIndex = (msgIndex + 1) % LOADING_MESSAGES.length;
      setLoadingMessage(LOADING_MESSAGES[msgIndex]);
    }, 1800);

    try {
      const normalized = await callScanAPI({ mode, input, goal, persona, explainMode });
      setResult(normalized);
      setHasResult(true);
    } catch (err) {
      setError(err?.message ?? "An unexpected error occurred. Please try again.");
    } finally {
      clearInterval(loadingIntervalRef.current);
      setLoading(false);
      setLoadingMessage("");
    }
  }, []);

  const tabs = [
    { id: "vulnerabilities", label: `🔍 Vulns (${result.vulnerabilities.length})`        },
    { id: "attacks",         label: `⚔️ Attacks (${result.attack_paths.length})`         },
    { id: "chains",          label: `🔗 Chains (${result.vulnerability_chains.length})`  },
    { id: "fixes",           label: `🛡️ Fixes (${result.fixes.length})`                 },
    { id: "defense",         label: "🏰 Defense"                                          },
  ];

  const renderTabContent = () => {
    switch (activeTab) {
      case "vulnerabilities":
        return result.vulnerabilities.length === 0
          ? <EmptyState icon="✓" message="No vulnerabilities detected in this scan." />
          : result.vulnerabilities.map((vuln, idx) => (
              <VulnerabilityCard
                key={vuln.id ?? `vuln-${idx}`}
                vuln={vuln}
                fix={result.fixes.find(f => f?.vulnerability_id === vuln?.id)}
                explainMode="developer"
              />
            ));

      case "attacks":
        return result.attack_paths.length === 0
          ? <EmptyState icon="🛡️" message="No attack paths were generated for this scan." />
          : result.attack_paths.map((path, i) => (
              <AttackPathCard key={i} path={path} defaultOpen={i === 0} />
            ));

      case "chains":
        return result.vulnerability_chains.length === 0
          ? <EmptyState icon="✓" message="No critical vulnerability chains detected." />
          : result.vulnerability_chains.map((chain, i) => (
              <ChainCard key={i} chain={chain} />
            ));

      case "fixes":
        return result.fixes.length === 0
          ? <EmptyState icon="🔧" message="No fix recommendations available." />
          : result.fixes.map((fix, i) => {
              const matchedVuln = result.vulnerabilities.find(v => v?.id === fix?.vulnerability_id);
              return <FixCard key={fix?.vulnerability_id ?? i} fix={fix} vulnName={matchedVuln?.name} />;
            });

      case "defense":
        return <DefensePanel recommendations={result.defensive_recommendations} />;

      default:
        return <EmptyState icon="?" message="Unknown tab." />;
    }
  };

  return (
    <div style={{ minHeight: "100vh", background: "#000", color: "#f2f2f7",
      fontFamily: '-apple-system, "SF Pro Display", "Segoe UI", sans-serif', paddingBottom: 60 }}>

      <header style={{ background: "linear-gradient(180deg, #1a0008 0%, #0a0010 100%)",
        borderBottom: "1px solid #2c2c2e", padding: "20px 24px" }}>
        <div style={{ maxWidth: 900, margin: "0 auto" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 4 }}>
            <div style={{ width: 36, height: 36, borderRadius: 8,
              background: "linear-gradient(135deg, #ff3b30, #ff0080)",
              display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18 }}>⚡</div>
            <h1 style={{ margin: 0, fontSize: 22, fontWeight: 700, letterSpacing: "-0.02em", color: "#f2f2f7" }}>
              OmniScan
            </h1>
            <span style={{ fontSize: 10, padding: "2px 6px", borderRadius: 4,
              background: "#ff3b3020", color: "#ff3b30", border: "1px solid #ff3b3040", fontWeight: 700 }}>
              LOCAL RAG PIPELINE
            </span>
          </div>
          <p style={{ margin: 0, fontSize: 13, color: "#636366" }}>
            Powered by Ollama + FAISS Vector DB · Offline Attack Simulation
          </p>
        </div>
      </header>

      <main style={{ maxWidth: 900, margin: "0 auto", padding: "24px 24px 0" }}>
        <ScannerPanel onScan={handleScan} loading={loading} loadingMessage={loadingMessage} />

        {loading && <LoadingDots message={loadingMessage} />}

        {error && !loading && <ErrorBanner message={error} onDismiss={() => setError(null)} />}

        {hasResult && !loading && (
          <>
            <ResultsSummary result={result} />
            <TabBar tabs={tabs} activeTab={activeTab} onSelect={setActiveTab} />
            <div key={activeTab}>{renderTabContent()}</div>
          </>
        )}
      </main>
    </div>
  );
}