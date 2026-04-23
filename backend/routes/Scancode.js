/**
 * Route: POST /api/scan-code  (routes/scanCode.js)
 *
 * 1. Validates the submitted code
 * 2. Runs static analysis (17 CWE-mapped security rules)
 * 3. Optionally analyses package.json / requirements.txt dependencies
 * 4. Calls the AI engine for natural-language explanations and fixes
 * 5. Returns a fully normalised response
 *
 * Bug fixes applied:
 *  1. Raw `analysis` was passed directly to res.json() without normalization —
 *     frontend crashed when fields like vulnerability_chains were missing
 *  2. Added null-check on analysis before accessing its properties
 *  3. Removed the pointless secure_code = null mutation (AI engine handles this)
 *  4. Added buildSafeResponse() for consistent output shape
 *  5. Improved error logging
 */

import express from 'express';
import { scanCode, analyzeManifest } from '../services/codeScanner.js';
import { runAIAnalysis }              from '../services/aiEngine.js';

export const codeScanRouter = express.Router();

/** Helper: build a safe, fully-populated response object */
function buildSafeResponse(partial = {}) {
  return {
    risk_score:        partial.risk_score        ?? 0,
    risk_label:        partial.risk_label        ?? 'Unknown',
    executive_summary: partial.executive_summary ?? '',

    vulnerabilities:      Array.isArray(partial.vulnerabilities)      ? partial.vulnerabilities      : [],
    attack_paths:         Array.isArray(partial.attack_paths)         ? partial.attack_paths         : [],
    vulnerability_chains: Array.isArray(partial.vulnerability_chains) ? partial.vulnerability_chains : [],
    fixes:                Array.isArray(partial.fixes)                ? partial.fixes                : [],

    defensive_recommendations: {
      immediate_actions: Array.isArray(partial.defensive_recommendations?.immediate_actions)
        ? partial.defensive_recommendations.immediate_actions : [],
      security_controls: Array.isArray(partial.defensive_recommendations?.security_controls)
        ? partial.defensive_recommendations.security_controls : [],
      monitoring_alerts: Array.isArray(partial.defensive_recommendations?.monitoring_alerts)
        ? partial.defensive_recommendations.monitoring_alerts : [],
    },
  };
}

codeScanRouter.post('/', async (req, res, next) => {
  try {
    const {
      code,
      filename    = '',
      goal,
      persona     = 'advanced',
      explainMode = 'developer',
    } = req.body;

    if (!code || typeof code !== 'string' || code.trim().length < 10) {
      return res.status(400).json({
        error: 'code is required and must be at least 10 characters',
      });
    }

    const cleanFilename = typeof filename === 'string' ? filename.trim() : '';
    console.log(`[Code Scan] Analysing ${cleanFilename || 'unnamed'} (${code.length} chars)`);

    // ── Static analysis ──────────────────────────────────────────────────────
    let rawVulns = scanCode(code, cleanFilename);
    if (!Array.isArray(rawVulns)) rawVulns = [];

    // Supplement with dependency scan for manifest files
    if (
      cleanFilename.endsWith('package.json') ||
      cleanFilename.endsWith('requirements.txt')
    ) {
      const manifestType = cleanFilename.endsWith('package.json') ? 'package.json' : 'requirements.txt';
      const manifestVulns = analyzeManifest(code, manifestType);
      if (Array.isArray(manifestVulns)) {
        rawVulns = [...rawVulns, ...manifestVulns];
      }
    }

    // ── No findings — return safe clean result ───────────────────────────────
    if (rawVulns.length === 0) {
      return res.json(buildSafeResponse({
        risk_score: 1.0,
        risk_label: 'Low',
        executive_summary:
          'No obvious security patterns were detected by static analysis. ' +
          'Manual code review by a security expert is still recommended.',
        defensive_recommendations: {
          immediate_actions: ['Run SAST tools (SonarQube, Semgrep)', 'Conduct manual code review'],
          security_controls: ['Implement input validation', 'Add output encoding'],
          monitoring_alerts: ['Enable runtime application self-protection (RASP)'],
        },
      }));
    }

    // ── AI analysis with RAG context ─────────────────────────────────────────
    const analysis = await runAIAnalysis({
      vulnerabilities: rawVulns,
      target:          cleanFilename || 'submitted code',
      targetType:      'code',
      goal,
      persona,
      explainMode,
    });

    // Normalise before sending — guards against any missing fields from AI
    return res.json(buildSafeResponse(analysis));

  } catch (err) {
    console.error(`[Code Scan] Unhandled error: ${err.message}`);
    next(err);
  }
});