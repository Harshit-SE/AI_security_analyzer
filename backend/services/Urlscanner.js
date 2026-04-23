/**
 * URL Scanner Service  (services/urlScanner.js)
 *
 * Implements:
 *  1. Web crawler — discovers forms, input fields, links
 *  2. Payload tester — XSS, SQLi probes
 *  3. Header analyser — security headers, CORS, cookie flags
 *  4. Response analyser — error disclosure, stack traces, secrets
 *  5. TLS check — HTTP vs HTTPS
 *
 * IMPORTANT: This is a passive / active scanner for authorised testing only.
 *
 * Bug fixes applied:
 *  1. crawlAndTest() re-threw non-response errors, which could crash the
 *     Promise.allSettled branch — now all errors are caught and logged
 *  2. analyzeHeaders() had a dangling ECONNREFUSED re-throw — changed to
 *     return empty array so allSettled still marks it fulfilled
 *  3. Added null/undefined checks on response data before operations
 *  4. pageText.toString() is now guarded — response.data may not be a string
 *  5. scanUrl() ensures it always returns an array, never undefined/null
 */

import axios   from 'axios';
import * as cheerio from 'cheerio';
import { URL } from 'url';

// ── Payload sets ──────────────────────────────────────────────────────────────

const XSS_PAYLOADS = [
  '<script>alert(1)</script>',
  '"><img src=x onerror=alert(1)>',
  "<svg/onload=alert(1)>",
  '${7*7}',   // Template-injection probe
];

const SQLI_PAYLOADS = [
  "'",
  "' OR '1'='1",
  "' OR '1'='1' --",
  "admin'--",
];

const SQL_ERROR_PATTERNS = [
  /SQL syntax.*MySQL/i,
  /Warning.*mysql_/i,
  /valid MySQL result/i,
  /MySqlClient\./i,
  /PostgreSQL.*ERROR/i,
  /Warning.*pg_/i,
  /ORA-\d{5}/i,
  /Oracle.*Driver/i,
  /Microsoft.*ODBC.*SQL Server/i,
  /Unclosed quotation mark/i,
  /syntax error.*SQL/i,
  /sqlite3\.OperationalError/i,
];

const REQUIRED_SECURITY_HEADERS = {
  'x-content-type-options': 'nosniff',
  'x-frame-options':        ['DENY', 'SAMEORIGIN'],
  'strict-transport-security': null,
  'content-security-policy':   null,
  'x-xss-protection':          null,
  'referrer-policy':            null,
};

// Patterns that indicate a secret is embedded in the page source
const SECRET_PATTERNS = [
  { pattern: /api[_-]?key\s*=\s*['"][^'"]{16,}['"]/i,          name: 'API Key Exposed in Source'    },
  { pattern: /secret\s*=\s*['"][^'"]{8,}['"]/i,                name: 'Secret Key in Source'         },
  { pattern: /password\s*=\s*['"][^'"]{4,}['"]/i,              name: 'Password in Source Code'      },
  { pattern: /Bearer\s+[A-Za-z0-9\-_.]+\.[A-Za-z0-9\-_.]+\.[A-Za-z0-9\-_.]+/, name: 'JWT Token Exposed' },
  { pattern: /AIza[0-9A-Za-z\-_]{35}/,                         name: 'Google API Key Exposed'       },
  { pattern: /sk-[a-zA-Z0-9]{48}/,                             name: 'OpenAI API Key Exposed'       },
  { pattern: /AKIA[0-9A-Z]{16}/,                               name: 'AWS Access Key Exposed'       },
];

// ── Main exported function ────────────────────────────────────────────────────

/**
 * Scan a URL for security vulnerabilities.
 * Always returns an array (never null / undefined).
 *
 * @param {string} url  Target URL
 * @returns {Promise<Array>} Found vulnerabilities
 */
export async function scanUrl(url) {
  const vulnerabilities = [];

  // Normalise and validate
  const normalizedUrl = typeof url === 'string' && url.startsWith('http')
    ? url
    : `https://${url}`;

  try {
    new URL(normalizedUrl);
  } catch {
    throw new Error('Invalid URL format — please include the protocol (https://)');
  }

  // Run all checks in parallel; individual failures are handled inside each function
  const [headerVulns, crawlResult, tlsVulns] = await Promise.allSettled([
    analyzeHeaders(normalizedUrl),
    crawlAndTest(normalizedUrl),
    analyzeTLS(normalizedUrl),
  ]);

  if (headerVulns.status === 'fulfilled' && Array.isArray(headerVulns.value)) {
    vulnerabilities.push(...headerVulns.value);
  } else if (headerVulns.status === 'rejected') {
    console.warn('[URL Scanner] Header analysis failed:', headerVulns.reason?.message);
  }

  if (crawlResult.status === 'fulfilled' && Array.isArray(crawlResult.value)) {
    vulnerabilities.push(...crawlResult.value);
  } else if (crawlResult.status === 'rejected') {
    console.warn('[URL Scanner] Crawl failed:', crawlResult.reason?.message);
  }

  if (tlsVulns.status === 'fulfilled' && Array.isArray(tlsVulns.value)) {
    vulnerabilities.push(...tlsVulns.value);
  }

  // Assign stable IDs
  return vulnerabilities.map((v, i) => ({ ...v, id: `URL-${i + 1}` }));
}

// ── Header analysis ───────────────────────────────────────────────────────────

async function analyzeHeaders(url) {
  const vulnerabilities = [];

  try {
    const response = await axios.get(url, {
      timeout:        10000,
      validateStatus: () => true,
      headers:        { 'User-Agent': 'SecurityScanner/1.0 (Authorized Test)' },
      maxRedirects:   5,
    });

    const headers = response.headers ?? {};

    // Missing / misconfigured security headers
    for (const [header, expected] of Object.entries(REQUIRED_SECURITY_HEADERS)) {
      if (!headers[header]) {
        const severity =
          header === 'strict-transport-security' ? 'High' :
          header === 'content-security-policy'   ? 'High' : 'Medium';
        vulnerabilities.push({
          name:     `Missing ${header.split('-').map(w => w[0].toUpperCase() + w.slice(1)).join('-')} Header`,
          type:     'Security Misconfiguration',
          severity,
          location: 'HTTP Response Headers',
          evidence: `Header "${header}" is absent from the response`,
        });
      } else if (Array.isArray(expected) && !expected.includes(headers[header])) {
        vulnerabilities.push({
          name:     `Misconfigured ${header} Header`,
          type:     'Security Misconfiguration',
          severity: 'Low',
          location: 'HTTP Response Headers',
          evidence: `${header}: ${headers[header]} (expected: ${expected.join(' or ')})`,
        });
      }
    }

    // CORS wildcard
    if (headers['access-control-allow-origin'] === '*') {
      vulnerabilities.push({
        name:     'CORS Wildcard Origin',
        type:     'Security Misconfiguration',
        severity: 'High',
        location: 'HTTP Response Headers',
        evidence: 'Access-Control-Allow-Origin: * — any domain can read responses',
      });
    }

    // Server version disclosure
    const serverHeader = headers['server'] || headers['x-powered-by'];
    if (serverHeader && /\d+\.\d+/.test(serverHeader)) {
      vulnerabilities.push({
        name:     'Server Version Disclosure',
        type:     'Information Disclosure',
        severity: 'Low',
        location: 'HTTP Response Headers',
        evidence: `Server: ${serverHeader} — version information exposed`,
      });
    }

    // Stack trace in error response
    if (response.status >= 400 && response.data) {
      const body = typeof response.data === 'string'
        ? response.data
        : JSON.stringify(response.data);
      if (/stack trace|at .*line \d+|exception in|traceback/i.test(body)) {
        vulnerabilities.push({
          name:     'Stack Trace / Error Disclosure',
          type:     'Information Disclosure',
          severity: 'Medium',
          location: url,
          evidence: `HTTP ${response.status} response contains a stack trace`,
        });
      }
    }

  } catch (err) {
    // Log but don't re-throw — let Promise.allSettled mark this as fulfilled
    console.warn(`[URL Scanner] Header analysis error for ${url}: ${err.message}`);
  }

  return vulnerabilities;
}

// ── Crawl and test ────────────────────────────────────────────────────────────

async function crawlAndTest(url) {
  const vulnerabilities = [];

  try {
    const response = await axios.get(url, {
      timeout:        15000,
      validateStatus: () => true,
      headers:        { 'User-Agent': 'SecurityScanner/1.0 (Authorized Test)' },
      maxRedirects:   5,
    });

    // Safely convert response body to string
    const pageText =
      typeof response.data === 'string'   ? response.data :
      Buffer.isBuffer(response.data)      ? response.data.toString('utf8') :
      response.data != null               ? JSON.stringify(response.data) : '';

    const $ = cheerio.load(pageText);
    const forms = [];

    // Extract all forms with at least one named input
    $('form').each((_, form) => {
      const rawAction = $(form).attr('action') || url;
      const method    = ($(form).attr('method') || 'GET').toUpperCase();
      const formInputs = [];

      $(form).find('input, textarea, select').each((_, el) => {
        const name = $(el).attr('name');
        const type = $(el).attr('type') || 'text';
        if (name) formInputs.push({ name, type });
      });

      if (formInputs.length > 0) {
        const action = rawAction.startsWith('http')
          ? rawAction
          : (() => {
              try { return new URL(rawAction, url).href; } catch { return url; }
            })();
        forms.push({ action, method, inputs: formInputs });
      }
    });

    // Look for secrets / tokens in page source
    for (const { pattern, name } of SECRET_PATTERNS) {
      if (pattern.test(pageText)) {
        vulnerabilities.push({
          name,
          type:     'Cryptographic Failures',
          severity: 'Critical',
          location: url,
          evidence: `Pattern "${pattern.source.substring(0, 60)}" matched in page source`,
        });
      }
    }

    // Test up to 5 forms for XSS and SQLi
    for (const form of forms.slice(0, 5)) {
      const xssVulns  = await testXSS(form);
      const sqliVulns = await testSQLi(form);
      vulnerabilities.push(...xssVulns, ...sqliVulns);
    }

    // Directory listing
    if (/<title>Index of\//i.test(pageText)) {
      vulnerabilities.push({
        name:     'Directory Listing Enabled',
        type:     'Security Misconfiguration',
        severity: 'Medium',
        location: url,
        evidence: 'Web server returns a directory listing — file structure is exposed',
      });
    }

    // Sensitive keywords in HTML comments
    const htmlComments = pageText.match(/<!--[\s\S]*?-->/g) ?? [];
    for (const comment of htmlComments) {
      if (/password|secret|key|token|api|admin|debug|todo/i.test(comment)) {
        vulnerabilities.push({
          name:     'Sensitive Keywords in HTML Comments',
          type:     'Information Disclosure',
          severity: 'Low',
          location: url,
          evidence: `HTML comment: "${comment.substring(0, 120)}..."`,
        });
        break; // Report once
      }
    }

  } catch (err) {
    // Log and return what we have — don't let this crash the scanner
    console.warn(`[URL Scanner] Crawl error for ${url}: ${err.message}`);
  }

  return vulnerabilities;
}

// ── XSS test ──────────────────────────────────────────────────────────────────

async function testXSS(form) {
  const vulnerabilities = [];
  const testInput = form.inputs.find(i => i.type !== 'hidden') ?? form.inputs[0];
  if (!testInput) return [];

  for (const payload of XSS_PAYLOADS.slice(0, 3)) {
    try {
      const data = {};
      form.inputs.forEach(inp => {
        data[inp.name] = inp.name === testInput.name ? payload : 'test';
      });

      const response = form.method === 'POST'
        ? await axios.post(form.action, data, {
            timeout: 8000, validateStatus: () => true,
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          })
        : await axios.get(`${form.action}?${new URLSearchParams(data)}`, {
            timeout: 8000, validateStatus: () => true,
          });

      const body = typeof response.data === 'string'
        ? response.data
        : JSON.stringify(response.data ?? '');

      if (body.includes(payload) && !body.includes('&lt;script&gt;')) {
        vulnerabilities.push({
          name:     'Reflected Cross-Site Scripting (XSS)',
          type:     'Injection',
          severity: 'High',
          location: `${form.action} (field: ${testInput.name})`,
          evidence: `Payload reflected unescaped: "${payload.substring(0, 50)}"`,
        });
        break;
      }
    } catch {
      // Payload request failed — try next payload
    }
  }
  return vulnerabilities;
}

// ── SQLi test ─────────────────────────────────────────────────────────────────

async function testSQLi(form) {
  const vulnerabilities = [];
  const testInput = form.inputs.find(i => i.type !== 'hidden') ?? form.inputs[0];
  if (!testInput) return [];

  for (const payload of SQLI_PAYLOADS.slice(0, 3)) {
    try {
      const data = {};
      form.inputs.forEach(inp => {
        data[inp.name] = inp.name === testInput.name ? payload : '1';
      });

      const response = form.method === 'POST'
        ? await axios.post(form.action, data, {
            timeout: 8000, validateStatus: () => true,
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          })
        : await axios.get(`${form.action}?${new URLSearchParams(data)}`, {
            timeout: 8000, validateStatus: () => true,
          });

      const body = typeof response.data === 'string'
        ? response.data
        : JSON.stringify(response.data ?? '');

      if (SQL_ERROR_PATTERNS.some(p => p.test(body))) {
        vulnerabilities.push({
          name:     'SQL Injection',
          type:     'Injection',
          severity: 'Critical',
          location: `${form.action} (field: ${testInput.name})`,
          evidence: `SQL error pattern in response for payload: "${payload}"`,
        });
        break;
      }
    } catch {
      // Payload request failed — try next payload
    }
  }
  return vulnerabilities;
}

// ── TLS check ─────────────────────────────────────────────────────────────────

async function analyzeTLS(url) {
  const vulnerabilities = [];
  try {
    const { protocol } = new URL(url);
    if (protocol === 'http:') {
      vulnerabilities.push({
        name:     'No HTTPS — Unencrypted Connection',
        type:     'Cryptographic Failures',
        severity: 'High',
        location: url,
        evidence: 'Site uses HTTP — all traffic is transmitted in plaintext',
      });
    }
  } catch {
    // Invalid URL — already caught in scanUrl()
  }
  return vulnerabilities;
}