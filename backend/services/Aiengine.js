/**
 * AI Engine — Free Local RAG Version (services/Aiengine.js)
 *
 * Replaces the paid Anthropic Claude API with a fully local stack:
 * ┌─────────────────────────────────────────────────────────┐
 * │  Node.js backend  →  Python RAG service (localhost:5001) │
 * │                                                           │
 * │  RAG Service:                                             │
 * │    sentence-transformers (all-MiniLM-L6-v2)  — embeddings│
 * │    FAISS                                     — vector DB  │
 * │    Ollama + llama3                           — local LLM  │
 * └─────────────────────────────────────────────────────────┘
 *
 * The Python service runs at http://127.0.0.1:5001 and exposes:
 * POST /analyze  — full RAG analysis
 * GET  /health   — liveness check
 * POST /retrieve — raw retrieval (for debugging)
 *
 * Zero paid APIs. Runs 100% offline.
 */

import axios from 'axios';

// ── Configuration ─────────────────────────────────────────────────────────────
const RAG_SERVICE_URL  = process.env.RAG_SERVICE_URL || 'http://127.0.0.1:5001';
const RAG_TIMEOUT_MS   = parseInt(process.env.RAG_TIMEOUT_MS || '120000', 10); // 2 min timeout
const OLLAMA_MODEL_LOG = process.env.OLLAMA_MODEL || 'llama3';

// ── Safe default result ───────────────────────────────────────────────────────
/**
 * Returned any time the RAG service is unavailable or returns malformed data.
 * Ensures the frontend never crashes regardless of backend state.
 */
const SAFE_FALLBACK = (vulnerabilities = []) => ({
  risk_score:        vulnerabilities.some(v => v.severity === 'Critical') ? 8.5 :
                     vulnerabilities.some(v => v.severity === 'High')     ? 6.5 : 4.0,
  risk_label:        vulnerabilities.some(v => v.severity === 'Critical') ? 'Critical' :
                     vulnerabilities.some(v => v.severity === 'High')     ? 'High' : 'Medium',
  executive_summary: `${vulnerabilities.length} vulnerabilities detected. ` +
                     'AI analysis service is starting up or unreachable — ensure Ollama is running ' +
                     '(`ollama serve`) and the RAG service is active (`python rag_service.py server`).',
  vulnerabilities:      Array.isArray(vulnerabilities) ? vulnerabilities : [],
  attack_paths:         [],
  vulnerability_chains: [],
  fixes:                [],
  defensive_recommendations: {
    immediate_actions: [
      'Start the RAG service: cd rag_service && python rag_service.py server',
      'Ensure Ollama is running: ollama serve',
      `Pull the model if needed: ollama pull ${OLLAMA_MODEL_LOG}`,
    ],
    security_controls: ['Review vulnerabilities against OWASP Top-10 guidelines'],
    monitoring_alerts: ['Enable security event logging on all endpoints'],
  },
});

// ── RAG service health check ──────────────────────────────────────────────────

/**
 * Check whether the Python RAG service is reachable and healthy.
 * Called before each analysis to provide useful error messages.
 * @returns {Promise<{ ok: boolean, detail: string }>}
 */
export async function checkRAGServiceHealth() {
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

/**
 * Run full AI security analysis using local RAG pipeline.
 *
 * @param {object} params
 * @param {Array}  params.vulnerabilities  - Raw vulnerabilities from the scanner
 * @param {string} params.target           - URL / filename / endpoint
 * @param {string} params.targetType       - 'url' | 'code' | 'api'
 * @param {string} [params.goal]           - Attacker goal
 * @param {string} [params.persona]        - 'beginner' | 'insider' | 'advanced'
 * @param {string} [params.explainMode]    - 'beginner' | 'developer' | 'expert'
 * @returns {Promise<object>}              - Normalized analysis result
 */
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

  // ── Check RAG service health ──────────────────────────────────────────────
  const health = await checkRAGServiceHealth();
  if (!health.ok) {
    console.error(`[AI Engine] RAG service unavailable: ${health.detail}`);
    return SAFE_FALLBACK(safeVulns);
  }

  // ── Call Python RAG service ───────────────────────────────────────────────
  try {
    console.log(`[AI Engine] Calling RAG service (${OLLAMA_MODEL_LOG}) for ${safeVulns.length} vulns...`);

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

    // Normalize to ensure all fields are present and correctly typed
    return normalizeResult(result, safeVulns);

  } catch (err) {
    if (err.code === 'ECONNABORTED') {
      console.error('[AI Engine] RAG service timed out — LLM inference took too long');
    } else if (err.response) {
      console.error(`[AI Engine] RAG service returned HTTP ${err.response.status}:`, err.response.data);
    } else {
      console.error('[AI Engine] RAG service call failed:', err.message);
    }
    return SAFE_FALLBACK(safeVulns);
  }
}

// ── Normalizer ────────────────────────────────────────────────────────────────

/**
 * Ensure every field the frontend expects exists with the correct type.
 * This protects against any field the LLM might have omitted.
 */
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

// ── Quick single-vulnerability explainer ──────────────────────────────────────

/**
 * Explain a single vulnerability using the local RAG retrieval (no LLM).
 * Uses pure FAISS retrieval for quick, offline explanations.
 * @param {string} vulnType
 * @param {string} context
 * @param {string} mode
 * @returns {Promise<string>}
 */
export async function explainVulnerability(vulnType, context = '', mode = 'developer') {
  try {
    const response = await axios.post(
      `${RAG_SERVICE_URL}/retrieve`,
      { query: `${vulnType} ${context}`, k: 2 },
      { timeout: 10000 }
    );

    const docs = response.data?.results || [];
    if (docs.length === 0) {
      return `No local knowledge found for "${vulnType}". Ensure the RAG service is running.`;
    }

    const modePrefix = {
      beginner:  'In simple terms',
      developer: 'Technically',
      expert:    'In-depth security analysis',
    }[mode] || 'Technically';

    const top = docs[0];
    return [
      `${modePrefix}: ${top.title || vulnType}`,
      `Category: ${top.category || 'Unknown'}`,
      `CWE: ${(top.cwe || []).join(', ')}`,
      `Description: ${top.description || ''}`,
      `Fix: ${top.fix || ''}`,
    ].join('\n');

  } catch (err) {
    return `Explanation unavailable (RAG service offline): ${err.message}`;
  }
}