/**
 * RAG Service — Retrieval-Augmented Generation (services/ragService.js)
 *
 * Implements a keyword-scored knowledge retrieval system backed by a curated
 * OWASP Top-10 2021 knowledge base.
 *
 * In production, replace this with:
 *   - Embeddings via text-embedding-3-small
 *   - FAISS (local) or Pinecone (cloud) for cosine-similarity search
 *   - NVD CVE feed for real vulnerability data
 *
 * The returned string is injected directly into the AI analysis prompt,
 * giving the model authoritative OWASP context for each finding.
 *
 * Bug fixes applied:
 *  1. retrieveKnowledge is async (was already fine) — kept consistent
 *  2. Added null-safety: vulnType and vulnName are coerced to strings
 *  3. Added try/catch so a bad lookup never crashes the AI engine
 *  4. Added 'injection' keyword to catch generic injection categories
 *  5. VULN_TYPE_MAP extended with more real-world aliases
 */

// ── OWASP Top-10 2021 Knowledge Base ─────────────────────────────────────────
// Each entry: description, attack examples, related CWEs, real-world breach, fix
const KNOWLEDGE_BASE = {
  'A01:2021': {
    name: 'Broken Access Control',
    description:
      'Access control enforces policy so users cannot act outside their intended permissions. ' +
      'Failures lead to unauthorized disclosure, modification, or destruction of data, or performing business functions outside the user\'s limit.',
    examples: [
      'Bypassing access-control checks by modifying the URL, internal application state, or HTML page',
      'Permitting viewing or editing someone else\'s account by providing its unique identifier (IDOR)',
      'Acting as a user without being logged in, or as an admin when logged in as a regular user',
      'Force-browsing to authenticated pages as an unauthenticated user',
    ],
    cwe: ['CWE-22', 'CWE-284', 'CWE-285', 'CWE-639', 'CWE-548'],
    real_world: 'In 2019, Facebook had an access-control bug that allowed any third-party app to access private user photos.',
    fix: 'Deny by default. Enforce server-side authorization checks. Apply RBAC or ABAC. Log access-control failures.',
  },

  'A02:2021': {
    name: 'Cryptographic Failures',
    description:
      'Failures related to cryptography (or its absence). Data is transmitted in cleartext, ' +
      'weak/deprecated algorithms are used, keys are hardcoded, or sensitive data is stored unencrypted.',
    examples: [
      'Passwords stored with MD5 or SHA-1 without salt',
      'HTTP used instead of HTTPS',
      'Weak TLS configurations (SSLv3, TLS 1.0)',
      'Hardcoded cryptographic keys or secrets in source code',
      'Predictable IV/nonce in symmetric encryption',
    ],
    cwe: ['CWE-261', 'CWE-296', 'CWE-310', 'CWE-319', 'CWE-321', 'CWE-326', 'CWE-327'],
    real_world: 'The LinkedIn breach (2012) exposed 117M passwords hashed with unsalted SHA-1.',
    fix: 'Use bcrypt/Argon2id for passwords. Enforce TLS 1.2+. Use AES-256-GCM. Store keys in a secrets manager. Never hardcode credentials.',
  },

  'A03:2021': {
    name: 'Injection',
    description:
      'User-supplied data is sent to an interpreter as part of a command or query. ' +
      'SQL, NoSQL, OS, LDAP, and template injection can result in data theft, corruption, or remote code execution.',
    examples: [
      'SQL injection via unsanitised login form',
      'OS command injection through a filename parameter',
      'LDAP injection via a search filter',
      'Server-side template injection (SSTI)',
      'eval() called with user-controlled input',
    ],
    cwe: ['CWE-89', 'CWE-78', 'CWE-77', 'CWE-90', 'CWE-94', 'CWE-79'],
    real_world: 'The Equifax breach (2017) exploited an Apache Struts injection (CVE-2017-5638) to steal 147M records.',
    fix: 'Use parameterised queries / prepared statements. Validate and allowlist all input. Use ORMs with safe query APIs. Escape output for the target context.',
  },

  'A04:2021': {
    name: 'Insecure Design',
    description:
      'Missing or ineffective security controls at the design stage. ' +
      'Threat modelling was not performed; business-logic flaws enable attacks that purely technical controls cannot prevent.',
    examples: [
      'No rate limiting on the login endpoint (brute-force)',
      'Password-reset tokens that are guessable or reusable',
      'Shopping-cart logic that allows negative item quantities',
      'Workflow that can be skipped by manipulating a hidden field',
    ],
    cwe: ['CWE-209', 'CWE-256', 'CWE-501', 'CWE-522', 'CWE-654'],
    real_world: 'Instagram (2019) allowed unlimited password guessing on the mobile login endpoint with no rate limiting.',
    fix: 'Threat model during design. Apply secure design principles and design patterns. Implement and test business-logic controls.',
  },

  'A05:2021': {
    name: 'Security Misconfiguration',
    description:
      'Improperly configured permissions, unnecessary features enabled, default accounts unchanged, ' +
      'verbose error messages, or missing security hardening.',
    examples: [
      'Directory listing enabled on a web server',
      'Default credentials (admin/admin) left unchanged',
      'Verbose error messages revealing stack traces',
      'CORS configured with a wildcard origin',
      'Unnecessary HTTP methods (PUT, DELETE) left enabled',
    ],
    cwe: ['CWE-16', 'CWE-611', 'CWE-732'],
    real_world: 'The Capital One breach (2019) resulted from a misconfigured WAF that exposed AWS credentials via SSRF.',
    fix: 'Disable all unnecessary features. Change all default credentials. Suppress verbose errors in production. Regularly review security configuration.',
  },

  'A06:2021': {
    name: 'Vulnerable and Outdated Components',
    description:
      'Using components (libraries, frameworks, OSes) with known vulnerabilities, ' +
      'missing security updates, or with more privileges than needed.',
    examples: [
      'Log4Shell — Apache Log4j RCE (CVE-2021-44228)',
      'Heartbleed — OpenSSL memory disclosure (CVE-2014-0160)',
      'Struts2 RCE (CVE-2017-5638)',
      'Prototype-pollution in lodash < 4.17.21',
    ],
    cwe: ['CWE-1104'],
    real_world: 'Equifax (2017) was breached because Apache Struts was not patched within two months of CVE-2017-5638 disclosure.',
    fix: 'Track all dependencies. Subscribe to security advisories (GitHub Dependabot, Snyk). Automate dependency scanning in CI. Update promptly.',
  },

  'A07:2021': {
    name: 'Identification and Authentication Failures',
    description:
      'Weak authentication schemes, credential exposure, broken session management, ' +
      'or missing MFA allow attackers to impersonate users or bypass authentication entirely.',
    examples: [
      'Weak password policy (min 4 chars, no complexity)',
      'No MFA on admin or privileged accounts',
      'Sessions not invalidated on logout',
      'Credential-stuffing not rate-limited or blocked',
      'JWT signed with a weak or hardcoded secret',
    ],
    cwe: ['CWE-255', 'CWE-259', 'CWE-287', 'CWE-288', 'CWE-290', 'CWE-294'],
    real_world: 'The Twitter hack (2020) used social engineering to compromise admin tools — MFA was absent for internal staff.',
    fix: 'Enforce MFA. Use secure, server-side session management. Set password complexity requirements. Rate-limit and alert on repeated login failures.',
  },

  'A08:2021': {
    name: 'Software and Data Integrity Failures',
    description:
      'Code and infrastructure that does not protect against integrity violations: ' +
      'insecure deserialization, unverified software updates, or CI/CD pipeline attacks.',
    examples: [
      'Deserialising untrusted pickled Python objects (RCE)',
      'npm packages with supply-chain malware (e.g. event-stream incident)',
      'Software updates delivered over HTTP without signature verification',
      'Insecure CI/CD pipelines with write access to production',
    ],
    cwe: ['CWE-494', 'CWE-502', 'CWE-829'],
    real_world: 'The SolarWinds attack (2020) injected a backdoor into signed software builds, affecting 18,000+ organisations.',
    fix: 'Verify digital signatures on all updates. Use an SBOM. Secure CI/CD pipelines with least-privilege. Validate data before deserialisation.',
  },

  'A09:2021': {
    name: 'Security Logging and Monitoring Failures',
    description:
      'Insufficient logging, monitoring, and incident-response capability allows attackers ' +
      'to operate undetected for extended periods and prevents forensic investigation.',
    examples: [
      'Login failures and high-value transactions not logged',
      'No alerting on brute-force or account-takeover attempts',
      'Logs stored locally and clearable by an attacker who gains access',
      'No SIEM or centralised log aggregation',
    ],
    cwe: ['CWE-117', 'CWE-223', 'CWE-532', 'CWE-778'],
    real_world: 'IBM\'s 2023 Cost of a Data Breach report found the average attacker dwell time before detection is 207 days.',
    fix: 'Log all authentication events, privilege changes, and API calls. Use centralised, tamper-proof log storage. Set up automated alerting. Test incident-response plans regularly.',
  },

  'A10:2021': {
    name: 'Server-Side Request Forgery (SSRF)',
    description:
      'SSRF flaws occur when a web application fetches a remote resource using ' +
      'a user-supplied URL without proper validation, allowing access to internal or cloud-metadata services.',
    examples: [
      'Fetching the AWS metadata endpoint (http://169.254.169.254/) via a URL parameter',
      'Port-scanning the internal network through the application',
      'Accessing internal admin interfaces (http://localhost:8080/admin)',
      'Bypassing IP allowlists by using DNS rebinding',
    ],
    cwe: ['CWE-918'],
    real_world: 'Capital One (2019): SSRF on a misconfigured WAF led to AWS credential theft and 100M+ record exposure.',
    fix: 'Validate and allowlist all user-supplied URLs. Block requests to internal IP ranges (RFC 1918). Disable HTTP redirects in outbound fetches. Use an egress proxy.',
  },
};

// ── Keyword → OWASP category mapping ─────────────────────────────────────────
// Longer keywords rank higher (more specific match wins)
const VULN_TYPE_MAP = {
  // Injection family
  'sql injection':            'A03:2021',
  'sqli':                     'A03:2021',
  'command injection':        'A03:2021',
  'os command injection':     'A03:2021',
  'ldap injection':           'A03:2021',
  'xpath injection':          'A03:2021',
  'template injection':       'A03:2021',
  'ssti':                     'A03:2021',
  'cross-site scripting':     'A03:2021',
  'xss':                      'A03:2021',
  'xxe':                      'A03:2021',
  'code injection':           'A03:2021',
  'injection':                'A03:2021',

  // Broken access control
  'broken access control':    'A01:2021',
  'idor':                     'A01:2021',
  'insecure direct object':   'A01:2021',
  'path traversal':           'A01:2021',
  'directory traversal':      'A01:2021',
  'csrf':                     'A01:2021',
  'cross-site request':       'A01:2021',
  'privilege escalation':     'A01:2021',
  'access control':           'A01:2021',

  // Cryptographic failures
  'cryptographic failure':    'A02:2021',
  'cryptographic':            'A02:2021',
  'hardcoded password':       'A02:2021',
  'hardcoded secret':         'A02:2021',
  'hardcoded':                'A02:2021',
  'weak encryption':          'A02:2021',
  'weak hashing':             'A02:2021',
  'md5':                      'A02:2021',
  'sha-1':                    'A02:2021',
  'sha1':                     'A02:2021',
  'plaintext':                'A02:2021',
  'unencrypted':              'A02:2021',
  'no https':                 'A02:2021',

  // Insecure design
  'insecure design':          'A04:2021',
  'rate limit':               'A04:2021',
  'no rate limit':            'A04:2021',
  'business logic':           'A04:2021',
  'missing captcha':          'A04:2021',

  // Security misconfiguration
  'security misconfiguration':'A05:2021',
  'misconfiguration':         'A05:2021',
  'cors':                     'A05:2021',
  'default credential':       'A05:2021',
  'default password':         'A05:2021',
  'debug mode':               'A05:2021',
  'directory listing':        'A05:2021',
  'verbose error':            'A05:2021',
  'stack trace':              'A05:2021',
  'information disclosure':   'A05:2021',

  // Vulnerable components
  'vulnerable component':     'A06:2021',
  'outdated component':       'A06:2021',
  'outdated':                 'A06:2021',
  'dependency':               'A06:2021',
  'known vulnerability':      'A06:2021',
  'cve':                      'A06:2021',

  // Auth failures
  'authentication failure':   'A07:2021',
  'authentication':           'A07:2021',
  'session':                  'A07:2021',
  'jwt':                      'A07:2021',
  'weak password':            'A07:2021',
  'brute force':              'A07:2021',
  'credential stuffing':      'A07:2021',
  'missing mfa':              'A07:2021',

  // Integrity failures
  'deserialization':          'A08:2021',
  'unsafe deserialization':   'A08:2021',
  'supply chain':             'A08:2021',
  'integrity failure':        'A08:2021',

  // Logging
  'logging failure':          'A09:2021',
  'logging':                  'A09:2021',
  'monitoring':               'A09:2021',
  'no logging':               'A09:2021',

  // SSRF
  'server-side request forgery': 'A10:2021',
  'ssrf':                        'A10:2021',
  'request forgery':             'A10:2021',
};

// ── Main exported function ────────────────────────────────────────────────────

/**
 * Retrieve the most relevant OWASP knowledge for a given vulnerability.
 *
 * @param {string} vulnType  Vulnerability category (e.g. 'Injection', 'XSS')
 * @param {string} vulnName  Full vulnerability name (e.g. 'SQL Injection via String Concatenation')
 * @returns {Promise<string>} Formatted OWASP context string for injection into the AI prompt
 */
export async function retrieveKnowledge(vulnType, vulnName) {
  try {
    // Coerce to string and normalise
    const searchTerm = `${String(vulnType ?? '')} ${String(vulnName ?? '')}`.toLowerCase().trim();

    let bestCategory = null;
    let bestScore    = 0;

    // Score each keyword by length (longer = more specific)
    for (const [keyword, category] of Object.entries(VULN_TYPE_MAP)) {
      if (searchTerm.includes(keyword)) {
        const score = keyword.length;
        if (score > bestScore) {
          bestScore    = score;
          bestCategory = category;
        }
      }
    }

    // Fallback heuristics when no keyword matched
    if (!bestCategory) {
      if (/inject|script|sqli|xss|eval/.test(searchTerm))    bestCategory = 'A03:2021';
      else if (/auth|login|session|jwt|password/.test(searchTerm)) bestCategory = 'A07:2021';
      else if (/crypto|hash|encrypt|ssl|tls/.test(searchTerm))     bestCategory = 'A02:2021';
      else if (/ssrf|request forgery/.test(searchTerm))            bestCategory = 'A10:2021';
      else if (/access|idor|traversal|privilege/.test(searchTerm)) bestCategory = 'A01:2021';
      else                                                          bestCategory = 'A05:2021'; // default
    }

    const knowledge = KNOWLEDGE_BASE[bestCategory];
    if (!knowledge) return '';

    // Build a concise but information-rich context string for the prompt
    return [
      `OWASP Category: ${bestCategory} — ${knowledge.name}`,
      `Description: ${knowledge.description}`,
      `Common Examples: ${knowledge.examples.slice(0, 3).join('; ')}`,
      `Related CWEs: ${knowledge.cwe.join(', ')}`,
      `Real-World Breach: ${knowledge.real_world}`,
      `Standard Fix: ${knowledge.fix}`,
    ].join('\n');

  } catch (err) {
    console.warn('[RAG] retrieveKnowledge error:', err.message);
    return '';  // Return empty string so the AI prompt still works
  }
}

/**
 * Return the full knowledge base (used by a frontend "Knowledge Explorer" page).
 * @returns {object}
 */
export function getAllKnowledge() {
  return KNOWLEDGE_BASE;
}