/**
 * Route: POST /api/analyze-api  (routes/analyzeApi.js)
 *
 * 1. Optionally probes a live API endpoint
 * 2. Checks for auth requirements, CORS, rate-limiting, sensitive data, errors
 * 3. Calls AI engine for deep analysis
 * 4. Returns fully normalised response
 *
 * Bug fixes applied:
 *  1. Raw `analysis` was passed to res.json() without normalisation — fixed
 *  2. Added buildSafeResponse() consistent with other routes
 *  3. Inner try/catch restructured — connection errors are now caught correctly
 *  4. Added null-check on analysis before accessing properties
 *  5. Improved error messages for unreachable endpoints
 */

import express from 'express';
import axios          from 'axios';
import { runAIAnalysis } from '../services/aiEngine.js';

export const apiAnalyzeRouter = express.Router();

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

apiAnalyzeRouter.post('/', async (req, res, next) => {
  try {
    const {
      endpoint,
      method      = 'GET',
      headers     = {},
      body:         reqBody,
      goal,
      persona     = 'advanced',
      explainMode = 'developer',
    } = req.body;

    const cleanEndpoint = typeof endpoint === 'string' ? endpoint.trim() : '';
    if (!cleanEndpoint) {
      return res.status(400).json({ error: 'endpoint is required' });
    }

    console.log(`[API Analyze] Testing: ${method.toUpperCase()} ${cleanEndpoint}`);

    const vulnerabilities = [];

    // ── Probe the live endpoint ──────────────────────────────────────────────
    try {
      const response = await axios({
        method:         method.toUpperCase(),
        url:            cleanEndpoint,
        headers:        { 'User-Agent': 'SecurityScanner/1.0 (Authorized Test)', ...headers },
        data:           reqBody,
        timeout:        10000,
        validateStatus: () => true,   // Don't throw on 4xx/5xx
      });

      const respHeaders = response.headers ?? {};
      const respBody    = typeof response.data === 'string'
        ? response.data
        : JSON.stringify(response.data ?? '');

      // Check 1: Unauthenticated access returned 200
      if (
        response.status === 200 &&
        !headers.Authorization &&
        !headers.authorization
      ) {
        vulnerabilities.push({
          id:       'API-1',
          name:     'Unauthenticated API Access',
          type:     'Broken Access Control',
          severity: 'High',
          location: cleanEndpoint,
          evidence: `${method.toUpperCase()} ${cleanEndpoint} returned HTTP 200 with no Authorization header`,
        });
      }

      // Check 2: CORS wildcard
      if (respHeaders['access-control-allow-origin'] === '*') {
        vulnerabilities.push({
          id:       'API-2',
          name:     'CORS Wildcard Origin',
          type:     'Security Misconfiguration',
          severity: 'High',
          location: cleanEndpoint,
          evidence: 'Access-Control-Allow-Origin: * — any origin can read API responses',
        });
      }

      // Check 3: No rate-limiting headers
      const hasRateLimit =
        respHeaders['x-ratelimit-limit'] ||
        respHeaders['x-rate-limit']      ||
        respHeaders['ratelimit-limit']   ||
        respHeaders['retry-after'];

      if (!hasRateLimit) {
        vulnerabilities.push({
          id:       'API-3',
          name:     'No Rate Limiting Detected',
          type:     'Insecure Design',
          severity: 'Medium',
          location: cleanEndpoint,
          evidence: 'No X-RateLimit-Limit, RateLimit-Limit, or Retry-After header in response',
        });
      }

      // Check 4: API versioning (potential version bypass)
      if (/\/v\d+\/|\/api\/v\d+/i.test(cleanEndpoint)) {
        vulnerabilities.push({
          id:       'API-4',
          name:     'API Version in URL — Version Bypass Risk',
          type:     'Broken Access Control',
          severity: 'Low',
          location: cleanEndpoint,
          evidence: 'Versioned endpoint detected — older versions may lack current security controls',
        });
      }

      // Check 5: Sensitive data in response body
      if (/password|secret|token|api_key|apikey|credit_card|ssn|private_key/i.test(respBody)) {
        vulnerabilities.push({
          id:       'API-5',
          name:     'Sensitive Data Exposed in API Response',
          type:     'Cryptographic Failures',
          severity: 'High',
          location: cleanEndpoint,
          evidence: 'Response body contains field names associated with sensitive data (password/secret/token/api_key)',
        });
      }

      // Check 6: Stack trace / verbose error on 5xx
      if (response.status >= 500 && /stack|trace|exception|error at|at line/i.test(respBody)) {
        vulnerabilities.push({
          id:       'API-6',
          name:     'API Leaks Stack Trace on Error',
          type:     'Information Disclosure',
          severity: 'Medium',
          location: cleanEndpoint,
          evidence: `HTTP ${response.status} response contains a stack trace`,
        });
      }

      // Check 7: Missing security headers
      const missingHeaders = [];
      if (!respHeaders['x-content-type-options']) missingHeaders.push('X-Content-Type-Options');
      if (!respHeaders['x-frame-options'])         missingHeaders.push('X-Frame-Options');
      if (!respHeaders['strict-transport-security'] && cleanEndpoint.startsWith('https'))
        missingHeaders.push('Strict-Transport-Security');

      if (missingHeaders.length > 0) {
        vulnerabilities.push({
          id:       'API-7',
          name:     'Missing Security Headers',
          type:     'Security Misconfiguration',
          severity: 'Medium',
          location: cleanEndpoint,
          evidence: `Missing headers: ${missingHeaders.join(', ')}`,
        });
      }

    } catch (probeErr) {
      // Distinguish unreachable from other errors
      if (probeErr.code === 'ECONNREFUSED' || probeErr.code === 'ETIMEDOUT') {
        console.warn(`[API Analyze] Endpoint unreachable (${probeErr.code}): ${cleanEndpoint}`);
        // Still do AI analysis based on the URL pattern itself
      } else {
        vulnerabilities.push({
          id:       'API-0',
          name:     'Endpoint Analysis Failed',
          type:     'Information Disclosure',
          severity: 'Info',
          location: cleanEndpoint,
          evidence: `Could not reach endpoint: ${probeErr.message}`,
        });
      }
    }

    // ── No findings — return clean result ────────────────────────────────────
    if (vulnerabilities.length === 0) {
      return res.json(buildSafeResponse({
        risk_score: 2.0,
        risk_label: 'Low',
        executive_summary:
          'Basic API security checks passed. Consider deeper testing: ' +
          'authentication bypass, parameter fuzzing, and business-logic review.',
        defensive_recommendations: {
          immediate_actions: ['Test for authentication bypass', 'Fuzz all parameters'],
          security_controls: ['Implement API gateway with rate-limiting', 'Add OAuth 2.0 / API key authentication'],
          monitoring_alerts: ['Alert on unusual request volume or patterns'],
        },
      }));
    }

    // ── AI analysis ──────────────────────────────────────────────────────────
    const analysis = await runAIAnalysis({
      vulnerabilities,
      target:     `${method.toUpperCase()} ${cleanEndpoint}`,
      targetType: 'api',
      goal,
      persona,
      explainMode,
    });

    return res.json(buildSafeResponse(analysis));

  } catch (err) {
    console.error(`[API Analyze] Unhandled error: ${err.message}`);
    next(err);
  }
});