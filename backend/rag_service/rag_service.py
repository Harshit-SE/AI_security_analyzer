"""
RAG Service — Free Local AI Engine
===================================
Implements full Retrieval-Augmented Generation using:
  - sentence-transformers (all-MiniLM-L6-v2)  — FREE embeddings
  - FAISS                                       — FREE vector database
  - Ollama + phi3                               — FREE local LLM (Memory Optimized)

NO paid APIs. No OpenAI. No Claude. Runs 100% locally.

Architecture:
  1. KnowledgeBase   — loads JSON, generates embeddings, builds FAISS index
  2. OllamaClient    — sends prompts to local Ollama instance
  3. RAGPipeline     — retrieves context + calls LLM + parses JSON output
  4. run_ai_analysis — main function called by Node.js via HTTP or subprocess
"""

import json
import os
import re
import sys
import time
import logging
import hashlib
from pathlib import Path
from typing import Optional

import numpy as np
import faiss
import requests
from sentence_transformers import SentenceTransformer

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("rag_service")

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent.parent
KB_PATH    = BASE_DIR / "knowledge_base" / "owasp_knowledge.json"
INDEX_PATH = BASE_DIR / "knowledge_base" / "faiss_index.bin"
META_PATH  = BASE_DIR / "knowledge_base" / "faiss_meta.json"

# ── Constants ─────────────────────────────────────────────────────────────────
EMBED_MODEL  = "all-MiniLM-L6-v2"   # 384-dim, ~80MB, free from HuggingFace
OLLAMA_URL   = os.getenv("OLLAMA_URL", "http://localhost:11434")
# UPDATED: Using phi3 instead of llama3 to prevent 500 Out of Memory Errors
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "phi3")
TOP_K        = 4          # number of documents to retrieve per vulnerability
MAX_TOKENS   = 4096


# ══════════════════════════════════════════════════════════════════════════════
#  KNOWLEDGE BASE — loads documents and builds FAISS index
# ══════════════════════════════════════════════════════════════════════════════

class KnowledgeBase:
    """
    Loads the OWASP knowledge JSON, converts each document into a dense
    embedding using sentence-transformers, and stores them in a FAISS L2 index.

    The index is cached to disk so subsequent startups are instant.
    Cache is invalidated when the source JSON changes (hash comparison).
    """

    def __init__(self):
        logger.info(f"Loading embedding model: {EMBED_MODEL}")
        self.embedder = SentenceTransformer(EMBED_MODEL)
        self.documents: list[dict] = []
        self.texts: list[str] = []
        self.index: Optional[faiss.IndexFlatL2] = None
        self._load()

    # ── Public API ──────────────────────────────────────────────────────────

    def retrieve(self, query: str, k: int = TOP_K) -> list[dict]:
        """
        Embed the query and return the top-k most relevant documents.
        Returns a list of knowledge-base document dicts.
        """
        if self.index is None or len(self.documents) == 0:
            logger.warning("FAISS index is empty — returning no context")
            return []

        query_vec = self.embedder.encode([query], convert_to_numpy=True)
        query_vec = query_vec.astype("float32")

        actual_k = min(k, len(self.documents))
        distances, indices = self.index.search(query_vec, actual_k)

        results = []
        for dist, idx in zip(distances[0], indices[0]):
            if idx == -1:
                continue
            doc = self.documents[idx].copy()
            doc["_similarity_score"] = float(1.0 / (1.0 + dist))  # normalise distance
            results.append(doc)

        return results

    def format_context(self, docs: list[dict]) -> str:
        """Format retrieved documents into a concise context string for the LLM prompt."""
        if not docs:
            return "No specific OWASP context retrieved."

        parts = []
        for doc in docs:
            part = (
                f"[{doc.get('category', 'Unknown')}] {doc.get('title', 'Unknown')}\n"
                f"CWE: {', '.join(doc.get('cwe', []))}\n"
                f"Description: {doc.get('description', '')}\n"
                f"Attack Vectors: {'; '.join(doc.get('attack_vectors', [])[:3])}\n"
                f"Fix: {doc.get('fix', '')}\n"
            )
            parts.append(part)

        return "\n---\n".join(parts)

    # ── Private helpers ─────────────────────────────────────────────────────

    def _load(self):
        """Load documents and build or restore the FAISS index."""
        if not KB_PATH.exists():
            raise FileNotFoundError(f"Knowledge base not found at {KB_PATH}")

        raw = KB_PATH.read_text(encoding="utf-8")
        self.documents = json.loads(raw)
        logger.info(f"Loaded {len(self.documents)} documents from knowledge base")

        # Build a single text string per document for embedding
        self.texts = [self._doc_to_text(d) for d in self.documents]

        # Try to restore cached index (avoids re-embedding on every startup)
        current_hash = hashlib.sha256(raw.encode()).hexdigest()
        if self._try_load_cache(current_hash):
            logger.info("FAISS index restored from cache")
            return

        logger.info("Building FAISS index (first run or knowledge base changed)...")
        self._build_index(current_hash)

    def _doc_to_text(self, doc: dict) -> str:
        """Create a rich text representation of a document for embedding."""
        parts = [
            doc.get("title", ""),
            doc.get("category", ""),
            doc.get("description", ""),
            " ".join(doc.get("tags", [])),
            " ".join(doc.get("cwe", [])),
            " ".join(doc.get("attack_vectors", [])),
            doc.get("fix", ""),
        ]
        return " ".join(p for p in parts if p)

    def _build_index(self, kb_hash: str):
        """Generate embeddings and build a FAISS FlatL2 index."""
        embeddings = self.embedder.encode(
            self.texts,
            batch_size=16,
            show_progress_bar=True,
            convert_to_numpy=True,
        )
        embeddings = embeddings.astype("float32")

        dim = embeddings.shape[1]
        self.index = faiss.IndexFlatL2(dim)
        self.index.add(embeddings)
        logger.info(f"FAISS index built: {self.index.ntotal} vectors, dim={dim}")

        # Cache to disk
        try:
            INDEX_PATH.parent.mkdir(parents=True, exist_ok=True)
            faiss.write_index(self.index, str(INDEX_PATH))
            META_PATH.write_text(json.dumps({"hash": kb_hash, "dim": dim}))
            logger.info(f"FAISS index cached to {INDEX_PATH}")
        except Exception as e:
            logger.warning(f"Could not cache FAISS index: {e}")

    def _try_load_cache(self, current_hash: str) -> bool:
        """Restore FAISS index from disk if the knowledge base hasn't changed."""
        if not INDEX_PATH.exists() or not META_PATH.exists():
            return False
        try:
            meta = json.loads(META_PATH.read_text())
            if meta.get("hash") != current_hash:
                logger.info("Knowledge base changed — rebuilding FAISS index")
                return False
            self.index = faiss.read_index(str(INDEX_PATH))
            return True
        except Exception as e:
            logger.warning(f"Cache load failed: {e}")
            return False


# ══════════════════════════════════════════════════════════════════════════════
#  OLLAMA CLIENT — talks to the local Ollama instance
# ══════════════════════════════════════════════════════════════════════════════

class OllamaClient:
    """
    Thin HTTP client for the Ollama /api/generate endpoint.
    Handles retry logic, streaming aggregation, and connection errors.
    """

    def __init__(self, base_url: str = OLLAMA_URL, model: str = OLLAMA_MODEL):
        self.base_url = base_url.rstrip("/")
        self.model    = model

    def is_available(self) -> bool:
        """Check that Ollama is running and the model is pulled."""
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if r.status_code != 200:
                return False
            models = [m["name"].split(":")[0] for m in r.json().get("models", [])]
            if self.model not in models:
                logger.error(
                    f"Model '{self.model}' not found in Ollama. "
                    f"Run: ollama pull {self.model}"
                )
                return False
            return True
        except requests.exceptions.ConnectionError:
            logger.error(
                f"Cannot connect to Ollama at {self.base_url}. "
                "Is Ollama running? Run: ollama serve"
            )
            return False

    def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = MAX_TOKENS,
        retries: int = 2,
    ) -> str:
        """
        Send a prompt to Ollama and return the complete response text.
        Uses non-streaming mode for simplicity.
        temperature=0.2 keeps output deterministic enough for JSON parsing.
        """
        payload = {
            "model":  self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",  # <--- FORCES PERFECT JSON SYNTAX
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
                "num_ctx": 8192,
                "top_p": 0.9,
                "repeat_penalty": 1.1,
            },
        }
        if system:
            payload["system"] = system

        for attempt in range(retries + 1):
            try:
                response = requests.post(
                    f"{self.base_url}/api/generate",
                    json=payload,
                    timeout=300,   # Extended to 5 minutes to prevent premature timeouts
                )
                response.raise_for_status()
                data = response.json()
                return data.get("response", "").strip()

            except requests.exceptions.Timeout:
                logger.warning(f"Ollama timeout on attempt {attempt + 1}")
                if attempt == retries:
                    raise RuntimeError("Ollama timed out after multiple attempts")
                time.sleep(2)

            except requests.exceptions.RequestException as e:
                raise RuntimeError(f"Ollama request failed: {e}") from e

        return ""


# ══════════════════════════════════════════════════════════════════════════════
#  VULNERABILITY CHAINING — combines low-severity issues into critical paths
# ══════════════════════════════════════════════════════════════════════════════

SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}

# Known dangerous combinations with reason and combined severity
CHAIN_RULES = [
    {
        "id": "CHAIN-001",
        "requires": ["Injection", "Security Misconfiguration"],
        "title": "SQLi + Verbose Errors = Accelerated DB Extraction",
        "explanation": (
            "Verbose error messages disclose database structure, table names, and column types. "
            "Combined with an SQL injection point, an attacker can rapidly map and dump the "
            "entire database without blind guessing."
        ),
        "combined_severity": "Critical",
        "boost": 2.5,
    },
    {
        "id": "CHAIN-002",
        "requires": ["Injection", "Identification and Authentication Failures"],
        "title": "XSS + Session Theft = Account Takeover",
        "explanation": (
            "Cross-site scripting can steal session cookies or JWTs from victims. "
            "If session management is weak (no HttpOnly, long-lived tokens), the stolen "
            "credential is immediately usable to fully take over the account."
        ),
        "combined_severity": "Critical",
        "boost": 2.0,
    },
    {
        "id": "CHAIN-003",
        "requires": ["Broken Access Control", "Cryptographic Failures"],
        "title": "IDOR + Sensitive Data = Mass Data Exfiltration",
        "explanation": (
            "Insecure direct object references allow iteration over all user records. "
            "When those records contain sensitive data stored in plaintext or weakly "
            "encrypted, the attacker can extract the full dataset in a single scripted run."
        ),
        "combined_severity": "Critical",
        "boost": 2.0,
    },
    {
        "id": "CHAIN-004",
        "requires": ["Server-Side Request Forgery", "Security Misconfiguration"],
        "title": "SSRF + Cloud Misconfiguration = Credential Theft",
        "explanation": (
            "SSRF targeting the cloud metadata service (169.254.169.254) combined with "
            "an overly permissive IAM role can yield temporary AWS/GCP/Azure credentials. "
            "Those credentials can then access all cloud resources the role is attached to."
        ),
        "combined_severity": "Critical",
        "boost": 3.0,
    },
    {
        "id": "CHAIN-005",
        "requires": ["Identification and Authentication Failures", "Insecure Design"],
        "title": "Weak Auth + No Rate Limiting = Credential Brute Force",
        "explanation": (
            "Weak password requirements or predictable session tokens, combined with "
            "the complete absence of rate limiting on the authentication endpoint, "
            "enable fully automated credential stuffing and brute-force attacks."
        ),
        "combined_severity": "High",
        "boost": 1.5,
    },
    {
        "id": "CHAIN-006",
        "requires": ["Vulnerable and Outdated Components", "Injection"],
        "title": "Unpatched CVE + Injection = Unauthenticated RCE",
        "explanation": (
            "Using a library with a known deserialization or injection CVE alongside "
            "an application-level injection vulnerability provides multiple independent "
            "paths to remote code execution, making exploitation trivial."
        ),
        "combined_severity": "Critical",
        "boost": 2.5,
    },
]


def detect_vulnerability_chains(vulnerabilities: list[dict]) -> list[dict]:
    """
    Analyse the list of found vulnerabilities against known chain rules.
    Returns a list of activated chain objects with participating vuln IDs.
    """
    chains = []
    vuln_types = {v.get("type", "") for v in vulnerabilities}
    vuln_by_type: dict[str, list[str]] = {}

    for v in vulnerabilities:
        t = v.get("type", "")
        vuln_by_type.setdefault(t, []).append(v.get("id", ""))

    for rule in CHAIN_RULES:
        required = rule["requires"]
        # Check if all required types are present (exact match or word-level boundary)
        if not all(any(req == t or req.lower() in t.lower() for t in vuln_types) for req in required):
            continue

        # Gather participating vuln IDs
        participating = []
        for req in required:
            for t, ids in vuln_by_type.items():
                if req == t or req.lower() in t.lower():
                    participating.extend(ids)

        # Calculate combined CVSS — take highest individual score of matching vulns and apply boost
        matching_scores = [
            float(v.get("cvss_score") or 5.0)
            for v in vulnerabilities
            if any(req == v.get("type", "") or req.lower() in v.get("type", "").lower() for req in required)
        ]
        max_cvss = max(matching_scores) if matching_scores else 5.0
        combined_cvss = min(10.0, max_cvss + rule["boost"])

        chains.append({
            "id": rule["id"],
            "title": rule["title"],
            "vulnerabilities": list(set(participating)),
            "combined_severity": rule["combined_severity"],
            "explanation": rule["explanation"],
            "combined_cvss": round(combined_cvss, 1),
        })

    return chains


# ══════════════════════════════════════════════════════════════════════════════
#  RAG PIPELINE — retrieval + augmentation + generation
# ══════════════════════════════════════════════════════════════════════════════

class RAGPipeline:
    """
    Orchestrates the full RAG workflow:
      1. For each vulnerability, retrieve the most relevant OWASP docs from FAISS
      2. Format the retrieved context into the LLM prompt
      3. Call Ollama to generate a structured JSON analysis
      4. Parse and normalize the output
    """

    def __init__(self):
        self.kb     = KnowledgeBase()
        self.llm    = OllamaClient()

    def run(
        self,
        vulnerabilities: list[dict],
        target: str,
        target_type: str,
        goal: Optional[str] = None,
        persona: str = "advanced",
        explain_mode: str = "developer",
    ) -> dict:
        """
        Full RAG analysis. Returns a normalized result dict ready for the frontend.
        Falls back gracefully if Ollama is unavailable.
        """
        safe_vulns = [v for v in vulnerabilities if isinstance(v, dict)]

        if not safe_vulns:
            return _safe_fallback(safe_vulns)

        # ── Step 1: Retrieve context for each vulnerability ──────────────────
        enriched = self._enrich_with_rag(safe_vulns)

        # ── Step 2: Detect vulnerability chains (pre-LLM, deterministic) ────
        chains = detect_vulnerability_chains(safe_vulns)

        # ── Step 3: Build prompts ────────────────────────────────────────────
        system_prompt = _build_system_prompt(persona, explain_mode)
        user_prompt   = _build_user_prompt(
            enriched_vulns=enriched,
            target=target,
            target_type=target_type,
            goal=goal or "gain unauthorized access",
            persona=persona,
            explain_mode=explain_mode,
            pre_detected_chains=chains,
        )

        # ── Step 4: Call local LLM ───────────────────────────────────────────
        if not self.llm.is_available():
            logger.warning("Ollama unavailable — returning static analysis only")
            return _build_static_fallback(safe_vulns, chains)

        logger.info(f"Sending prompt to Ollama ({OLLAMA_MODEL})...")
        try:
            raw_text = self.llm.generate(prompt=user_prompt, system=system_prompt)
        except RuntimeError as e:
            logger.error(f"LLM generation failed: {e}")
            return _build_static_fallback(safe_vulns, chains)

        # ── Step 5: Parse JSON response ──────────────────────────────────────
        result = _parse_llm_response(raw_text, safe_vulns)

        # ── Step 6: Merge pre-detected chains (trust deterministic logic) ───
        if chains and not result.get("vulnerability_chains"):
            result["vulnerability_chains"] = chains
        elif chains:
            # Merge any new chains not already returned by LLM
            existing_ids = {c.get("id", "") for c in result["vulnerability_chains"]}
            for c in chains:
                if c["id"] not in existing_ids:
                    result["vulnerability_chains"].append(c)

        return result

    def _enrich_with_rag(self, vulnerabilities: list[dict]) -> list[dict]:
        """Attach retrieved OWASP context to each vulnerability."""
        enriched = []
        for vuln in vulnerabilities:
            query = f"{vuln.get('type', '')} {vuln.get('name', '')} {vuln.get('evidence', '')}"
            docs  = self.kb.retrieve(query, k=TOP_K)
            ctx   = self.kb.format_context(docs)

            enriched.append({
                **vuln,
                "owasp_context": ctx,
            })
        return enriched


# ══════════════════════════════════════════════════════════════════════════════
#  PROMPT BUILDERS
# ══════════════════════════════════════════════════════════════════════════════

def _build_system_prompt(persona: str, explain_mode: str) -> str:
    personas = {
        "beginner": (
            "You are simulating a BEGINNER attacker (script kiddie): uses public exploits, "
            "automated tools (SQLMap, Nikto), noisy patterns, cannot chain vulnerabilities. "
            "Success rate is low — only trivially exploitable issues succeed."
        ),
        "insider": (
            "You are simulating an INSIDER THREAT: has legitimate internal access, abuses "
            "privileges to escalate or exfiltrate, knows internal topology, operates stealthily "
            "over a long period. High success on access-control vulnerabilities."
        ),
        "advanced": (
            "You are simulating an ADVANCED attacker (APT/nation-state): chains multiple "
            "low-severity issues into critical paths, uses WAF/IDS evasion, custom exploits, "
            "low-and-slow techniques. Very high success probability."
        ),
    }
    explain_styles = {
        "beginner":  "Use plain language, real-world analogies, no technical jargon.",
        "developer": "Use technical terms, show code-level fixes, reference CWE/OWASP.",
        "expert":    "Deep security reasoning: CVSS vectors, bypass techniques, defence-in-depth.",
    }
    return (
        f"You are an AI Security Analysis Engine.\n"
        f"Attacker simulation: {personas.get(persona, personas['advanced'])}\n"
        f"Explanation style: {explain_styles.get(explain_mode, explain_styles['developer'])}\n\n"
        "CRITICAL: Respond with VALID JSON ONLY. "
        "Zero prose before or after. No markdown fences. "
        "DO NOT output placeholder brackets like < or > in your final JSON values. "
        "All array fields must be JSON arrays, never null."
    )


def _build_user_prompt(
    enriched_vulns: list[dict],
    target: str,
    target_type: str,
    goal: str,
    persona: str,
    explain_mode: str,
    pre_detected_chains: list[dict],
) -> str:
    # Compact representation of vulns with RAG context for the prompt
    vuln_block = json.dumps(
        [{
            "id":            v.get("id"),
            "name":          v.get("name"),
            "type":          v.get("type"),
            "severity":      v.get("severity"),
            "evidence":      v.get("evidence"),
            "location":      v.get("location"),
            "owasp_context": v.get("owasp_context", "")[:600],  # truncate for token budget
        } for v in enriched_vulns],
        indent=2,
    )

    chains_hint = ""
    if pre_detected_chains:
        chains_hint = (
            f"\nPRE-DETECTED VULNERABILITY CHAINS (include these in your response):\n"
            f"{json.dumps(pre_detected_chains, indent=2)}\n"
        )

    return f"""Analyse these security scan results and produce a full intelligence report.

TARGET: {target}
TARGET TYPE: {target_type}
ATTACKER GOAL: "{goal}"
ATTACKER PERSONA: {persona}
EXPLAIN MODE: {explain_mode}
{chains_hint}
DETECTED VULNERABILITIES WITH OWASP CONTEXT:
{vuln_block}

Respond with ONLY this JSON structure (no other text):
{{
  "risk_score": 8,
  "risk_label": "Critical|High|Medium|Low",
  "executive_summary": "Write a 2-3 sentence summary for {explain_mode} audience here.",
  "vulnerabilities": [
    {{
      "id": "same as input",
      "name": "string",
      "type": "OWASP category",
      "severity": "Critical|High|Medium|Low|Info",
      "cvss_score": 8.5,
      "cwe_id": "e.g. CWE-89",
      "explanation": "tailored explanation for {explain_mode}",
      "real_world_impact": "concrete example",
      "evidence": "what was found",
      "location": "where"
    }}
  ],
  "attack_paths": [
    {{
      "goal": "objective",
      "success_probability": 85,
      "complexity": "Low|Medium|High",
      "detection_risk": "Low|Medium|High",
      "steps": [
        {{"step_number": 1, "action": "action", "technique": "name", "vulnerability_used": "id", "outcome": "result"}}
      ],
      "chained_vulnerabilities": ["id"],
      "prerequisites": "string"
    }}
  ],
  "vulnerability_chains": [
    {{
      "title": "descriptive title",
      "vulnerabilities": ["id"],
      "combined_severity": "Critical|High|Medium",
      "explanation": "why worse",
      "combined_cvss": 9.0
    }}
  ],
  "fixes": [
    {{
      "vulnerability_id": "id",
      "priority": "Immediate|Short-term|Long-term",
      "fix_summary": "string",
      "implementation_steps": ["step"],
      "secure_code_example": "code or null",
      "estimated_effort": "Hours|Days|Weeks",
      "references": ["url"]
    }}
  ],
  "defensive_recommendations": {{
    "immediate_actions": ["action"],
    "security_controls": ["control"],
    "monitoring_alerts": ["alert"]
  }}
}}"""


# ══════════════════════════════════════════════════════════════════════════════
#  RESPONSE PARSING & NORMALIZATION
# ══════════════════════════════════════════════════════════════════════════════

def _parse_llm_response(raw_text: str, original_vulns: list[dict]) -> dict:
    """
    Attempt to extract valid JSON from the LLM output.
    Tries three extraction strategies before falling back.
    """
    strategies = [
        # 1. ```json ... ``` block
        lambda t: re.search(r"```json\s*([\s\S]*?)\s*```", t, re.IGNORECASE),
        # 2. ``` ... ``` block (no language tag)
        lambda t: re.search(r"```\s*([\s\S]*?)\s*```", t),
        # 3. First { ... } in the text (find outermost JSON object)
        lambda t: _find_json_object(t),
    ]

    for strategy in strategies:
        match = strategy(raw_text)
        if match is None:
            continue
        candidate = match.group(1) if hasattr(match, "group") else match
        if not candidate:
            continue
        try:
            parsed = json.loads(candidate)
            logger.info("Successfully parsed LLM JSON response")
            return _normalize(parsed, original_vulns)
        except json.JSONDecodeError:
            continue

    logger.error(f"All JSON extraction strategies failed. Raw text snippet:\n{raw_text[:400]}")
    return _safe_fallback(original_vulns)


def _find_json_object(text: str) -> Optional[object]:
    """Find the outermost JSON object in free-form text."""
    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    in_string = False
    escape_next = False

    for i, ch in enumerate(text[start:], start):
        if escape_next:
            escape_next = False
            continue
        if ch == "\\" and in_string:
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
        if not in_string:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[start:i + 1]
                    # Return a fake match-like object
                    class _Fake:
                        def __init__(self, s): self._s = s
                        def group(self, n=0): return self._s
                    return _Fake(candidate)
    return None


def _normalize(parsed: dict, original_vulns: list[dict]) -> dict:
    """Ensure the parsed result contains all required fields with correct types."""
    rec = parsed.get("defensive_recommendations") or {}
    return {
        "risk_score": float(parsed.get("risk_score") or 5.0),
        "risk_label": str(parsed.get("risk_label") or "Medium"),
        "executive_summary": str(parsed.get("executive_summary") or ""),
        "vulnerabilities":      parsed.get("vulnerabilities")      if isinstance(parsed.get("vulnerabilities"),      list) else original_vulns,
        "attack_paths":         parsed.get("attack_paths")         if isinstance(parsed.get("attack_paths"),         list) else [],
        "vulnerability_chains": parsed.get("vulnerability_chains") if isinstance(parsed.get("vulnerability_chains"), list) else [],
        "fixes":                parsed.get("fixes")                if isinstance(parsed.get("fixes"),                list) else [],
        "defensive_recommendations": {
            "immediate_actions": rec.get("immediate_actions") if isinstance(rec.get("immediate_actions"), list) else [],
            "security_controls": rec.get("security_controls") if isinstance(rec.get("security_controls"), list) else [],
            "monitoring_alerts": rec.get("monitoring_alerts") if isinstance(rec.get("monitoring_alerts"), list) else [],
        },
    }


def _safe_fallback(vulnerabilities: list[dict]) -> dict:
    """Return a safe, complete result when the LLM fails."""
    severities = [v.get("severity", "Medium") for v in vulnerabilities]
    score = (
        9.0 if "Critical" in severities else
        7.0 if "High"     in severities else
        5.0 if "Medium"   in severities else 3.0
    )
    chains = detect_vulnerability_chains(vulnerabilities)
    return {
        "risk_score": score,
        "risk_label": "Critical" if score >= 9 else "High" if score >= 7 else "Medium",
        "executive_summary": (
            f"{len(vulnerabilities)} vulnerabilities detected. "
            "Local LLM analysis unavailable — review findings manually."
        ),
        "vulnerabilities": vulnerabilities,
        "attack_paths": [],
        "vulnerability_chains": chains,
        "fixes": [],
        "defensive_recommendations": {
            "immediate_actions": [
                "Review all detected vulnerabilities immediately",
                "Ensure Ollama is running: ollama serve && ollama pull phi3",
            ],
            "security_controls": ["Apply OWASP Top-10 mitigations for each finding"],
            "monitoring_alerts": ["Enable security event logging"],
        },
    }


def _build_static_fallback(vulnerabilities: list[dict], chains: list[dict]) -> dict:
    """Richer fallback that includes deterministic chain analysis."""
    result = _safe_fallback(vulnerabilities)
    result["vulnerability_chains"] = chains
    return result


# ══════════════════════════════════════════════════════════════════════════════
#  HTTP SERVER — Node.js calls this via REST
# ══════════════════════════════════════════════════════════════════════════════

def run_http_server(host: str = "127.0.0.1", port: int = 5001):
    """
    Lightweight Flask HTTP server so Node.js can call the RAG service
    over localhost without subprocess overhead.
    """
    from flask import Flask, request, jsonify

    app = Flask(__name__)
    pipeline = RAGPipeline()  # loaded once at startup

    @app.route("/health", methods=["GET"])
    def health():
        ollama_ok = pipeline.llm.is_available()
        return jsonify({
            "status": "ok",
            "ollama": ollama_ok,
            "model":  OLLAMA_MODEL,
            "docs_indexed": pipeline.kb.index.ntotal if pipeline.kb.index else 0,
        })

    @app.route("/analyze", methods=["POST"])
    def analyze():
        body = request.get_json(force=True)
        if not body:
            return jsonify({"error": "Empty request body"}), 400

        result = pipeline.run(
            vulnerabilities = body.get("vulnerabilities", []),
            target          = body.get("target", "unknown"),
            target_type     = body.get("targetType", "unknown"),
            goal            = body.get("goal"),
            persona         = body.get("persona", "advanced"),
            explain_mode    = body.get("explainMode", "developer"),
        )
        return jsonify(result)

    @app.route("/retrieve", methods=["POST"])
    def retrieve():
        """Quick endpoint to test RAG retrieval without LLM."""
        body = request.get_json(force=True)
        query = body.get("query", "")
        # Bound k to prevent DoS via huge FAISS searches
        MAX_K = 20
        k = min(int(body.get("k", TOP_K)), MAX_K)
        if k < 1:
            k = 1
        docs  = pipeline.kb.retrieve(query, k=k)
        return jsonify({"query": query, "results": docs})

    logger.info(f"RAG HTTP service starting on http://{host}:{port}")
    app.run(host=host, port=port, debug=False, threaded=True)


# ══════════════════════════════════════════════════════════════════════════════
#  CLI ENTRY POINT — run as subprocess or HTTP server
# ══════════════════════════════════════════════════════════════════════════════

def main():
    """
    Usage:
      # Start HTTP server (recommended — Node.js calls /analyze)
      python rag_service.py server

      # One-shot analysis via stdin JSON (for subprocess integration)
      echo '{"vulnerabilities": [...], "target": "example.com"}' | python rag_service.py analyze

      # Test retrieval
      python rag_service.py retrieve "sql injection"
    """
    if len(sys.argv) < 2:
        print("Usage: python rag_service.py [server|analyze|retrieve <query>]")
        sys.exit(1)

    command = sys.argv[1]

    if command == "server":
        host = os.getenv("RAG_HOST", "127.0.0.1")
        port = int(os.getenv("RAG_PORT", "5001"))
        run_http_server(host, port)

    elif command == "analyze":
        pipeline = RAGPipeline()
        input_data = json.loads(sys.stdin.read())
        result = pipeline.run(
            vulnerabilities = input_data.get("vulnerabilities", []),
            target          = input_data.get("target", "unknown"),
            target_type     = input_data.get("targetType", "unknown"),
            goal            = input_data.get("goal"),
            persona         = input_data.get("persona", "advanced"),
            explain_mode    = input_data.get("explainMode", "developer"),
        )
        print(json.dumps(result, indent=2))

    elif command == "retrieve":
        query = " ".join(sys.argv[2:]) if len(sys.argv) > 2 else "sql injection"
        kb    = KnowledgeBase()
        docs  = kb.retrieve(query, k=3)
        for doc in docs:
            print(f"\n[{doc['category']}] {doc['title']} (score: {doc['_similarity_score']:.3f})")
            print(f"  CWE: {', '.join(doc.get('cwe', []))}")
            print(f"  Fix: {doc.get('fix', '')[:120]}...")

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()