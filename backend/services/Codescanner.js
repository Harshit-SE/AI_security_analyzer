/**
 * Code Scanner Service - Static Security Analysis
 * 
 * Performs pattern-based static analysis to detect:
 * - Injection vulnerabilities (SQL, OS, LDAP, XPath)
 * - Hardcoded secrets (API keys, passwords, tokens)
 * - Insecure functions (eval, exec, system)
 * - Cryptographic weaknesses (MD5, SHA1, DES, hardcoded keys)
 * - Missing security controls (input validation, output encoding)
 * - Insecure dependencies (known CVEs in imports)
 * - Authentication/session issues
 * - File handling vulnerabilities
 */

/**
 * Security rule definitions
 * Each rule: { id, name, type, severity, pattern, languages, description, cwe }
 */
const SECURITY_RULES = [
  // ===== INJECTION =====
  {
    id: 'SQLI-001',
    name: 'SQL Injection via String Concatenation',
    type: 'Injection',
    severity: 'Critical',
    pattern: /(?:execute|exec|query|run|cursor\.execute)\s*\(\s*['"]\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER).*?\+|f['"]\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)/gi,
    languages: ['python', 'javascript', 'php', 'ruby', 'java'],
    description: 'User-controlled data concatenated directly into SQL query string',
    cwe: 'CWE-89'
  },
  {
    id: 'SQLI-002',
    name: 'Raw SQL Execution',
    type: 'Injection',
    severity: 'High',
    pattern: /\.raw\s*\(|execute\s*\(\s*f['"]/g,
    languages: ['python', 'javascript'],
    description: 'Raw SQL query execution that may bypass ORM protections',
    cwe: 'CWE-89'
  },
  {
    id: 'CMDI-001',
    name: 'OS Command Injection',
    type: 'Injection',
    severity: 'Critical',
    pattern: /(?:exec|system|popen|subprocess\.run|os\.system|child_process\.exec)\s*\([^)]*(?:req\.|request\.|input\.|params\.|query\.)/g,
    languages: ['python', 'javascript', 'php', 'ruby'],
    description: 'User input passed directly to OS command execution function',
    cwe: 'CWE-78'
  },
  {
    id: 'EVAL-001',
    name: 'Dangerous eval() Usage',
    type: 'Injection',
    severity: 'Critical',
    pattern: /\beval\s*\([^)]*(?:req\.|request\.|input\.|params\.|query\.|user|untrusted)/g,
    languages: ['javascript', 'python', 'php'],
    description: 'eval() called with user-controlled input enables code execution',
    cwe: 'CWE-94'
  },
  {
    id: 'EVAL-002',
    name: 'eval() Usage Detected',
    type: 'Injection',
    severity: 'Medium',
    pattern: /\beval\s*\(/g,
    languages: ['javascript', 'python', 'php'],
    description: 'eval() is inherently risky and should be avoided',
    cwe: 'CWE-95'
  },

  // ===== CRYPTOGRAPHIC FAILURES =====
  {
    id: 'CRYPTO-001',
    name: 'Hardcoded Password or Secret',
    type: 'Cryptographic Failures',
    severity: 'Critical',
    pattern: /(?:password|passwd|secret|api_key|apikey|token|auth)\s*=\s*['"][^'"]{4,}['"]/gi,
    languages: ['python', 'javascript', 'java', 'php', 'ruby', 'go'],
    description: 'Credentials hardcoded in source code',
    cwe: 'CWE-798'
  },
  {
    id: 'CRYPTO-002',
    name: 'Weak Hashing Algorithm (MD5)',
    type: 'Cryptographic Failures',
    severity: 'High',
    pattern: /(?:md5|MD5)\s*\(|hashlib\.md5|MessageDigest\.getInstance\s*\(\s*['"]MD5['"]/g,
    languages: ['python', 'javascript', 'java', 'php'],
    description: 'MD5 is cryptographically broken and unsuitable for security purposes',
    cwe: 'CWE-327'
  },
  {
    id: 'CRYPTO-003',
    name: 'Weak Hashing Algorithm (SHA-1)',
    type: 'Cryptographic Failures',
    severity: 'High',
    pattern: /(?:sha1|SHA1|sha_1)\s*\(|hashlib\.sha1|MessageDigest\.getInstance\s*\(\s*['"]SHA-1['"]/g,
    languages: ['python', 'javascript', 'java', 'php'],
    description: 'SHA-1 is deprecated for security-sensitive operations',
    cwe: 'CWE-327'
  },
  {
    id: 'CRYPTO-004',
    name: 'Random Number Generator Not Cryptographically Secure',
    type: 'Cryptographic Failures',
    severity: 'Medium',
    pattern: /Math\.random\s*\(\)|random\.random\s*\(\)|rand\s*\(\)/g,
    languages: ['javascript', 'python', 'php'],
    description: 'Non-cryptographic random number generator used in security context',
    cwe: 'CWE-338'
  },

  // ===== XSS =====
  {
    id: 'XSS-001',
    name: 'Potential DOM-based XSS (innerHTML)',
    type: 'Injection',
    severity: 'High',
    pattern: /\.innerHTML\s*=\s*(?!['"])/g,
    languages: ['javascript'],
    description: 'innerHTML assignment with dynamic content enables XSS',
    cwe: 'CWE-79'
  },
  {
    id: 'XSS-002',
    name: 'document.write() with Dynamic Content',
    type: 'Injection',
    severity: 'High',
    pattern: /document\.write\s*\([^)]*(?:req\.|location\.|param|input|user)/gi,
    languages: ['javascript'],
    description: 'document.write() with user-controlled content causes XSS',
    cwe: 'CWE-79'
  },

  // ===== AUTHENTICATION/SESSION =====
  {
    id: 'AUTH-001',
    name: 'JWT with Weak Secret',
    type: 'Identification and Authentication Failures',
    severity: 'High',
    pattern: /jwt\.sign|jwt\.verify\s*\([^,]+,\s*['"](secret|password|key|123|test|dev)['"]/gi,
    languages: ['javascript'],
    description: 'JWT signed with weak or default secret',
    cwe: 'CWE-330'
  },
  {
    id: 'AUTH-002',
    name: 'Insecure Cookie (Missing HttpOnly or Secure flag)',
    type: 'Identification and Authentication Failures',
    severity: 'Medium',
    pattern: /(?:Set-Cookie|setCookie|cookie\.set)[^;]+(?!httponly)(?!secure)/gi,
    languages: ['python', 'javascript', 'php'],
    description: 'Session cookies without HttpOnly/Secure flags are vulnerable to theft',
    cwe: 'CWE-614'
  },
  {
    id: 'AUTH-003',
    name: 'Timing Attack in Password Comparison',
    type: 'Identification and Authentication Failures',
    severity: 'Medium',
    pattern: /password\s*===?\s*|(?:!=|!==)\s*password/g,
    languages: ['javascript', 'python'],
    description: 'Direct string comparison of passwords is vulnerable to timing attacks',
    cwe: 'CWE-208'
  },

  // ===== PATH TRAVERSAL =====
  {
    id: 'PATH-001',
    name: 'Path Traversal / Directory Traversal',
    type: 'Broken Access Control',
    severity: 'High',
    pattern: /(?:open|readFile|include|require|fopen|file_get_contents)\s*\([^)]*(?:req\.|request\.|params\.|input\.|query\.)/g,
    languages: ['javascript', 'python', 'php'],
    description: 'User input used to construct file path without sanitization',
    cwe: 'CWE-22'
  },

  // ===== SSRF =====
  {
    id: 'SSRF-001',
    name: 'Server-Side Request Forgery (SSRF)',
    type: 'Server-Side Request Forgery',
    severity: 'High',
    pattern: /(?:axios\.get|fetch|requests\.get|urllib\.request|http\.get)\s*\([^)]*(?:req\.|request\.|params\.|input\.|query\.)/g,
    languages: ['javascript', 'python'],
    description: 'HTTP request made with user-controlled URL without validation',
    cwe: 'CWE-918'
  },

  // ===== DESERIALIZATION =====
  {
    id: 'DESER-001',
    name: 'Unsafe Deserialization',
    type: 'Software and Data Integrity Failures',
    severity: 'Critical',
    pattern: /pickle\.loads|yaml\.load\s*\([^)]+,\s*Loader=yaml\.Loader\)|JSON\.parse.*eval|unserialize\s*\(/g,
    languages: ['python', 'javascript', 'php'],
    description: 'Deserializing untrusted data can lead to remote code execution',
    cwe: 'CWE-502'
  },

  // ===== INFORMATION DISCLOSURE =====
  {
    id: 'INFO-001',
    name: 'Debug Mode Enabled in Production Code',
    type: 'Security Misconfiguration',
    severity: 'Medium',
    pattern: /debug\s*=\s*True|DEBUG\s*=\s*True|app\.run\s*\([^)]*debug\s*=\s*True/g,
    languages: ['python'],
    description: 'Debug mode enabled exposes stack traces and sensitive info',
    cwe: 'CWE-94'
  },
  {
    id: 'INFO-002',
    name: 'Console.log with Sensitive Data',
    type: 'Information Disclosure',
    severity: 'Low',
    pattern: /console\.log\s*\([^)]*(?:password|secret|token|key|auth|credential)/gi,
    languages: ['javascript'],
    description: 'Sensitive data logged to console may be exposed',
    cwe: 'CWE-532'
  },

  // ===== INPUT VALIDATION =====
  {
    id: 'VALID-001',
    name: 'Missing Input Validation',
    type: 'Insecure Design',
    severity: 'Medium',
    pattern: /req\.body\.\w+|req\.query\.\w+|req\.params\.\w+(?!.*(?:validate|sanitize|escape|trim|check|parseInt|parseFloat))/g,
    languages: ['javascript'],
    description: 'Request input used without apparent validation or sanitization',
    cwe: 'CWE-20'
  },

  // ===== DEPENDENCY VULNERABILITIES =====
  {
    id: 'DEP-001',
    name: 'Known Vulnerable Package Import',
    type: 'Vulnerable and Outdated Components',
    severity: 'High',
    pattern: /require\s*\(\s*['"](?:serialize-javascript@[0-2]\.|lodash@[0-3]\.|moment@2\.[0-9]\.|log4j)['"]/g,
    languages: ['javascript'],
    description: 'Import of known vulnerable package version detected',
    cwe: 'CWE-1104'
  }
];

/**
 * Detect programming language from code content
 */
function detectLanguage(code) {
  const indicators = {
    python: [/def \w+\(|import \w+|from \w+ import|print\(|if __name__|\.py|:$/m],
    javascript: [/const |let |var |=>|require\(|import .* from|module\.exports|\.js/],
    php: [/<\?php|echo |->|\$\w+/],
    java: [/public class|import java\.|System\.out|void main/],
    ruby: [/def \w+|require '|puts |\.rb$/],
    go: [/func \w+|import \(|package main|\.go$/]
  };

  for (const [lang, patterns] of Object.entries(indicators)) {
    if (patterns.some(p => p.test(code))) return lang;
  }
  return 'javascript'; // Default
}

/**
 * Main code scanning function
 * @param {string} code - Source code to analyze
 * @param {string} filename - Optional filename for language detection
 * @returns {Array} Found vulnerabilities
 */
export function scanCode(code, filename = '') {
  const vulnerabilities = [];
  const language = detectLanguage(code + ' ' + filename);
  const lines = code.split('\n');

  for (const rule of SECURITY_RULES) {
    // Skip rules that don't apply to this language
    if (rule.languages && !rule.languages.includes(language)) continue;

    let match;
    const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
    
    while ((match = regex.exec(code)) !== null) {
      // Find line number for the match
      const precedingCode = code.substring(0, match.index);
      const lineNumber = precedingCode.split('\n').length;
      const lineContent = lines[lineNumber - 1]?.trim() || '';
      
      // Skip if line is a comment
      if (/^\s*(#|\/\/|\/\*|\*)/.test(lineContent)) continue;
      
      // Skip duplicate findings for same rule/line
      const isDuplicate = vulnerabilities.some(v => 
        v.ruleId === rule.id && v.lineNumber === lineNumber
      );
      if (isDuplicate) continue;

      vulnerabilities.push({
        id: `CODE-${vulnerabilities.length + 1}`,
        ruleId: rule.id,
        name: rule.name,
        type: rule.type,
        severity: rule.severity,
        location: `Line ${lineNumber}${filename ? ` in ${filename}` : ''}`,
        lineNumber,
        evidence: `Code: \`${lineContent.substring(0, 120)}\``,
        description: rule.description,
        cwe: rule.cwe,
        language
      });

      // Prevent infinite loops on zero-length matches
      if (match.index === regex.lastIndex) regex.lastIndex++;
    }
  }

  // Sort by severity
  const severityOrder = { 'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4 };
  return vulnerabilities.sort((a, b) => 
    (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5)
  );
}

/**
 * Analyze package.json or requirements.txt for known vulnerable packages
 */
export function analyzeManifest(content, type = 'package.json') {
  const vulnerabilities = [];
  
  // Known vulnerable packages (simplified - in production use OSV/Snyk API)
  const KNOWN_VULNERABLE = {
    'lodash': { below: '4.17.21', cve: 'CVE-2021-23337', severity: 'High' },
    'moment': { below: '2.29.4', cve: 'CVE-2022-24785', severity: 'High' },
    'axios': { below: '0.21.2', cve: 'CVE-2021-3749', severity: 'Medium' },
    'express': { below: '4.17.3', cve: 'CVE-2022-24999', severity: 'Medium' },
  };
  
  try {
    if (type === 'package.json') {
      const pkg = JSON.parse(content);
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      
      for (const [name, version] of Object.entries(deps)) {
        if (KNOWN_VULNERABLE[name]) {
          vulnerabilities.push({
            id: `DEP-${vulnerabilities.length + 1}`,
            name: `Vulnerable Dependency: ${name}`,
            type: 'Vulnerable and Outdated Components',
            severity: KNOWN_VULNERABLE[name].severity,
            location: 'package.json',
            evidence: `${name}@${version} has known vulnerability ${KNOWN_VULNERABLE[name].cve}`,
            cwe: 'CWE-1104'
          });
        }
      }
    }
  } catch {
    // Not valid JSON, skip manifest analysis
  }
  
  return vulnerabilities;
}