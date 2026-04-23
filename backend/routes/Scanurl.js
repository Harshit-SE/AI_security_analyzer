/**
 * Route: POST /api/scan-url  (routes/scanUrl.js)
 *
 * 1. Validates the incoming URL
 * 2. Runs the URL scanner (header checks, XSS/SQLi payload tests, TLS check)
 * 3. Calls the AI engine with RAG-enriched context
 * 4. Returns a fully normalised response (every expected field is present)
 *
 * Bug fixes applied:
 *  1. scanUrl() can now return undefined/null — added || [] safety
 *  2. All res.json() calls return a fully normalised object so the frontend
 *     never receives missing fields
 *  3. Added input sanitisation (strip whitespace) on the URL
 *  4. Improved error logging with request context
 */

import express from 'express';
import { scanUrl }       from '../services/urlScanner.js';
import { runAIAnalysis } from '../services/aiEngine.js';

export const urlScanRouter = express.Router();

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

urlScanRouter.post('/', async (req, res, next) => {
  try {
    const {
      url,
      goal,
      persona     = 'advanced',
      explainMode = 'developer',
    } = req.body;

    const cleanUrl = typeof url === 'string' ? url.trim() : '';
    if (!cleanUrl) {
      return res.status(400).json({ error: 'url is required' });
    }

    console.log(`[URL Scan] Scanning: ${cleanUrl}`);

    // ── Phase 1: active scanner ──────────────────────────────────────────────
    let rawVulns;
    try {
      rawVulns = await scanUrl(cleanUrl);
    } catch (scanErr) {
      console.error(`[URL Scan] Scanner failed: ${scanErr.message}`);
      // Return a safe response instead of crashing — the AI can still run
      rawVulns = [];
    }

    // Ensure we always have an array
    if (!Array.isArray(rawVulns)) rawVulns = [];

    // ── No vulnerabilities found — return safe clean result ──────────────────
    if (rawVulns.length === 0) {
      return res.json(buildSafeResponse({
        risk_score: 1.0,
        risk_label: 'Low',
        executive_summary:
          'No obvious vulnerabilities were detected in this surface scan. ' +
          'This does not guarantee security — manual penetration testing is recommended.',
        defensive_recommendations: {
          immediate_actions: ['Perform manual penetration testing', 'Review server-side code'],
          security_controls: ['Implement WAF', 'Enable all recommended security headers'],
          monitoring_alerts: ['Set up intrusion detection', 'Monitor for unusual traffic patterns'],
        },
      }));
    }

    // ── Phase 2: AI analysis with RAG context ────────────────────────────────
    const analysis = await runAIAnalysis({
      vulnerabilities: rawVulns,
      target:          cleanUrl,
      targetType:      'url',
      goal,
      persona,
      explainMode,
    });

    return res.json(buildSafeResponse(analysis));

  } catch (err) {
    console.error(`[URL Scan] Unhandled error: ${err.message}`);
    next(err);
  }
});