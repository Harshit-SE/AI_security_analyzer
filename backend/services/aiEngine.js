/**
 * AI Engine — Dual Mode: Google Gemini API (Cloud) or Local RAG / Ollama (Offline)
 * (services/aiEngine.js)
 *
 * Mode 1 (Cloud / Free Deployment):
 *   If GEMINI_API_KEY is present in process.env, it directly calls Google Gemini (gemini-3.8-flash / gemini-3.8-flash)
 *   Runs 100% in the cloud with zero heavy dependencies or local server requirements.
 *
 * Mode 2 (Local / Offline):
 *   If GEMINI_API_KEY is omitted, it falls back to the local Python RAG service (Ollama + Phi-3).
 */

import axios from 'axios';
import { GoogleGenAI } from '@google/genai';

// ── Configuration ─────────────────────────────────────────────────────────────
const GEMINI_API_KEY   = process.env.GEMINI_API_KEY || '';
const GEMINI_MODEL     = process.env.GEMINI_MODEL || 'gemini-3.8-flash';
const RAG_SERVICE_RAW  = process.env.VERCEL_SERVICE_RAG_SERVICE_URL || process.env.RAG_SERVICE_URL || 'http://127.0.0.1:5001';
const RAG_SERVICE_URL  = RAG_SERVICE_RAW.replace(/\/$/, '');
const RAG_TIMEOUT_MS   = parseInt(process.env.RAG_TIMEOUT_MS || '300000', 10);
const OLLAMA_MODEL_LOG = process.env.OLLAMA_MODEL || 'phi3';

// Initialize Gemini client if key is provided
let aiClient = null;
if (GEMINI_API_KEY) {
  aiClient = new GoogleGenAI({ apiKey: GEMINI_API_KEY });
}

// ── Safe default result ───────────────────────────────────────────────────────
const SAFE_FALLBACK = (vulnerabilities = []) => ({
  risk_score:        vulnerabilities.some(v => v.severity === 'Critical') ? 8.5 :
                     vulnerabilities.some(v => v.severity === 'High')     ? 6.5 : 4.0,
  risk_label:        vulnerabilities.some(v => v.severity === 'Critical') ? 'Critical' :
                     vulnerabilities.some(v => v.severity === 'High')     ? 'High' : 'Medium',
  executive_summary: `${vulnerabilities.length} vulnerabilities detected. ` +
                     'AI analysis service is unavailable. Review the detected vulnerabilities manually.',
  vulnerabilities:      Array.isArray(vulnerabilities) ? vulnerabilities : [],
  attack_paths:         [],
  vulnerability_chains: [],
  fixes:                [],
  defensive_recommendations: {
    immediate_actions: [
      'Review all detected vulnerabilities against OWASP Top-10 guidelines',
      'Verify that GEMINI_API_KEY is set or local Ollama is active',
    ],
    security_controls: ['Implement input validation and safe output encoding'],
    monitoring_alerts: ['Enable security event logging on all endpoints'],
  },
});

// ── RAG service health check (for local mode) ─────────────────────────────────
export async function checkRAGServiceHealth() {
  if (GEMINI_API_KEY) {
    return { ok: true, detail: 'Using Google Gemini Cloud API' };
  }
  try {
    const response = await axios.get(`${RAG_SERVICE_URL}/health`, { timeout: 5000 });
    const data = response.data;
    return {
      ok:     data.status === 'ok',
      detail: JSON.stringify(data),
    };
  } catch (err) {
    return {
      ok:     false,
      detail: `Cannot reach RAG service at ${RAG_SERVICE_URL}: ${err.message}`,
    };
  }
}

// ── Main exported function ────────────────────────────────────────────────────
export async function runAIAnalysis({
  vulnerabilities,
  target,
  targetType,
  goal,
  persona     = 'advanced',
  explainMode = 'developer',
}) {
  const safeVulns = Array.isArray(vulnerabilities) ? vulnerabilities : [];
  if (safeVulns.length === 0) {
    return SAFE_FALLBACK([]);
  }

  // ── Mode 1: Google Gemini API (if key configured) ──────────────────────────
  if (GEMINI_API_KEY) {
    try {
      console.log(`[AI Engine] Analyzing with Google Gemini (${GEMINI_MODEL}) for ${safeVulns.length} vulns...`);
      const geminiResult = await runGeminiAnalysis({
        vulnerabilities: safeVulns,
        target,
        targetType,
        goal: goal || 'gain unauthorized access',
        persona,
        explainMode,
      });
      return normalizeResult(geminiResult, safeVulns);
    } catch (geminiErr) {
      console.error(`[AI Engine] Gemini API error: ${geminiErr.message}. Attempting local fallback...`);
    }
  }

  // ── Mode 2: Local Python RAG / Ollama ──────────────────────────────────────
  const health = await checkRAGServiceHealth();
  if (!health.ok) {
    console.error(`[AI Engine] Local RAG service unavailable: ${health.detail}`);
    return SAFE_FALLBACK(safeVulns);
  }

  try {
    console.log(`[AI Engine] Calling local RAG service (${OLLAMA_MODEL_LOG}) for ${safeVulns.length} vulns...`);

    const response = await axios.post(
      `${RAG_SERVICE_URL}/analyze`,
      {
        vulnerabilities: safeVulns,
        target,
        targetType,
        goal:        goal || 'gain unauthorized access',
        persona,
        explainMode,
      },
      {
        timeout: RAG_TIMEOUT_MS,
        headers: { 'Content-Type': 'application/json' },
      }
    );

    const result = response.data;
    if (!result || typeof result !== 'object') {
      console.error('[AI Engine] RAG service returned non-object response');
      return SAFE_FALLBACK(safeVulns);
    }

    return normalizeResult(result, safeVulns);
  } catch (err) {
    console.error('[AI Engine] RAG service call failed:', err.message);
    return SAFE_FALLBACK(safeVulns);
  }
}

// ── Google Gemini Cloud Analyzer ──────────────────────────────────────────────
async function runGeminiAnalysis({ vulnerabilities, target, targetType, goal, persona, explainMode }) {
  const client = aiClient || new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

  const prompt = `You are an AI Security Analysis Engine.
Analyze these security findings and return an in-depth intelligence report.

TARGET: ${target}
TARGET TYPE: ${targetType}
ATTACKER GOAL: "${goal}"
ATTACKER PERSONA: ${persona}
EXPLAIN MODE: ${explainMode}

DETECTED VULNERABILITIES:
${JSON.stringify(vulnerabilities, null, 2)}

CRITICAL: Return ONLY valid JSON matching this schema:
{
  "risk_score": 8.5,
  "risk_label": "Critical|High|Medium|Low",
  "executive_summary": "summary here",
  "vulnerabilities": [
    {
      "id": "matching original id",
      "name": "string",
      "type": "OWASP Category",
      "severity": "Critical|High|Medium|Low|Info",
      "cvss_score": 8.5,
      "cwe_id": "CWE-xx",
      "explanation": "explanation",
      "real_world_impact": "concrete impact",
      "evidence": "evidence string",
      "location": "location string"
    }
  ],
  "attack_paths": [
    {
      "goal": "string",
      "success_probability": 80,
      "complexity": "Low|Medium|High",
      "detection_risk": "Low|Medium|High",
      "steps": [
        { "step_number": 1, "action": "action", "technique": "technique", "vulnerability_used": "id", "outcome": "outcome" }
      ],
      "chained_vulnerabilities": ["id"],
      "prerequisites": "string"
    }
  ],
  "vulnerability_chains": [
    {
      "title": "chain title",
      "vulnerabilities": ["id"],
      "combined_severity": "Critical|High|Medium",
      "explanation": "explanation",
      "combined_cvss": 9.0
    }
  ],
  "fixes": [
    {
      "vulnerability_id": "id",
      "priority": "Immediate|Short-term|Long-term",
      "fix_summary": "summary",
      "implementation_steps": ["step 1"],
      "secure_code_example": "code or null",
      "estimated_effort": "Hours|Days",
      "references": ["url"]
    }
  ],
  "defensive_recommendations": {
    "immediate_actions": ["action"],
    "security_controls": ["control"],
    "monitoring_alerts": ["alert"]
  }
}`;

  const candidateModels = [
    process.env.GEMINI_MODEL,
    'gemini-3.8-flash',
    'gemini-3.1-flash-lite-preview',
    'gemini-flash-latest',
    'gemini-2.5-pro'
  ].filter(Boolean);

  let lastErr = null;
  for (const model of candidateModels) {
    try {
      const response = await client.models.generateContent({
        model,
        contents: prompt,
        config: {
          responseMimeType: 'application/json',
          temperature: 0.2,
        },
      });

      const text = response.text ? response.text.trim() : '';
      if (text) {
        return JSON.parse(text);
      }
    } catch (err) {
      lastErr = err;
      console.warn(`[AI Engine] Attempt with ${model} failed (${err.message}). Trying fallback...`);
    }
  }

  throw lastErr || new Error('All Gemini model candidates failed');
}

// ── Normalizer ────────────────────────────────────────────────────────────────
function normalizeResult(raw, originalVulns) {
  const rec = raw.defensive_recommendations || {};
  return {
    risk_score:        typeof raw.risk_score === 'number' ? raw.risk_score : 5.0,
    risk_label:        typeof raw.risk_label === 'string' ? raw.risk_label : 'Medium',
    executive_summary: typeof raw.executive_summary === 'string' ? raw.executive_summary : '',

    vulnerabilities:      Array.isArray(raw.vulnerabilities)      ? raw.vulnerabilities      : originalVulns,
    attack_paths:         Array.isArray(raw.attack_paths)         ? raw.attack_paths         : [],
    vulnerability_chains: Array.isArray(raw.vulnerability_chains) ? raw.vulnerability_chains : [],
    fixes:                Array.isArray(raw.fixes)                ? raw.fixes                : [],

    defensive_recommendations: {
      immediate_actions: Array.isArray(rec.immediate_actions) ? rec.immediate_actions : [],
      security_controls: Array.isArray(rec.security_controls) ? rec.security_controls : [],
      monitoring_alerts: Array.isArray(rec.monitoring_alerts) ? rec.monitoring_alerts : [],
    },
  };
}
