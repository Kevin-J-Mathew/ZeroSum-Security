"""
src/sentinel/data/cve_scraper.py

Multi-source CVE scraper that pulls real-world vulnerable code samples
from NVD, OSV, and GitHub to build a high-variance training dataset.
"""

import json
import logging
import time
import re
import hashlib
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

# ─── CWE ↔ Vulnerability Type Mapping ────────────────────────────────────────
CWE_MAP = {
    'CWE-89': 'sql_injection',
    'CWE-79': 'xss',
    'CWE-78': 'command_injection',
    'CWE-22': 'path_traversal',
    'CWE-611': 'xxe',
    'CWE-918': 'ssrf',
    'CWE-502': 'deserialization',
    'CWE-943': 'nosql_injection',
    'CWE-1336': 'ssti',
    'CWE-639': 'idor',
    'CWE-601': 'open_redirect',
}

REVERSE_CWE_MAP = {v: k for k, v in CWE_MAP.items()}

# Severity mapping from CVSS score
def _cvss_to_severity(score: Optional[float]) -> str:
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


@dataclass
class RealWorldSample:
    """A vulnerable code sample sourced from real-world CVE data."""
    id: str
    code: str
    vulnerability_type: str
    severity: str
    language: str
    complexity: str
    description: str
    cwe_id: str
    cve_id: str
    source: str  # 'nvd', 'osv', 'github'
    test_code: str = ""
    secure_version: str = ""


class NVDScraper:
    """
    Scrapes the National Vulnerability Database (NVD) API v2.
    Free, no auth required. Rate limit: 5 requests per 30 seconds.
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    RATE_LIMIT_DELAY = 6.5  # seconds between requests (5 req / 30s)

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.session = requests.Session()
        if api_key:
            self.session.headers['apiKey'] = api_key
            self.RATE_LIMIT_DELAY = 0.7  # 50 req/30s with key

    def fetch_cves_by_cwe(
        self,
        cwe_id: str,
        max_results: int = 50,
        keyword: str = "python",
    ) -> List[Dict[str, Any]]:
        """
        Fetch CVEs from NVD filtered by CWE-ID and keyword.

        Args:
            cwe_id: CWE identifier (e.g. 'CWE-89')
            max_results: Maximum number of CVEs to fetch
            keyword: Additional keyword filter (e.g. 'python')

        Returns:
            List of CVE dictionaries
        """
        results = []
        start_index = 0
        per_page = min(max_results, 20)  # NVD max is 2000, keep small

        while len(results) < max_results:
            params = {
                'cweId': cwe_id,
                'keywordSearch': keyword,
                'resultsPerPage': per_page,
                'startIndex': start_index,
            }

            try:
                time.sleep(self.RATE_LIMIT_DELAY)
                resp = self.session.get(self.BASE_URL, params=params, timeout=30)
                resp.raise_for_status()
                data = resp.json()
            except requests.RequestException as e:
                logger.warning(f"NVD API request failed: {e}")
                break

            vulns = data.get('vulnerabilities', [])
            if not vulns:
                break

            for vuln in vulns:
                cve = vuln.get('cve', {})
                parsed = self._parse_cve(cve, cwe_id)
                if parsed:
                    results.append(parsed)

            total = data.get('totalResults', 0)
            start_index += per_page
            if start_index >= total:
                break

            logger.info(f"  NVD [{cwe_id}]: fetched {len(results)}/{min(max_results, total)} CVEs")

        return results[:max_results]

    def _parse_cve(self, cve: Dict, cwe_id: str) -> Optional[Dict[str, Any]]:
        """Parse a single NVD CVE record into a structured dict."""
        cve_id = cve.get('id', '')

        # Get English description
        descriptions = cve.get('descriptions', [])
        desc = next((d['value'] for d in descriptions if d.get('lang') == 'en'), '')
        if not desc:
            return None

        # Get CVSS score
        cvss_score = None
        metrics = cve.get('metrics', {})
        for metric_key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore')
                break

        # Get references (especially GitHub links)
        references = cve.get('references', [])
        github_refs = [
            r['url'] for r in references
            if 'github.com' in r.get('url', '')
        ]

        return {
            'cve_id': cve_id,
            'cwe_id': cwe_id,
            'description': desc,
            'severity': _cvss_to_severity(cvss_score),
            'cvss_score': cvss_score,
            'github_refs': github_refs,
            'vulnerability_type': CWE_MAP.get(cwe_id, 'unknown'),
        }


class OSVScraper:
    """
    Scrapes the Open Source Vulnerabilities (OSV) API.
    Specifically targets the PyPI ecosystem.
    Free, no auth required.
    """

    BASE_URL = "https://api.osv.dev/v1"

    def __init__(self):
        self.session = requests.Session()

    def query_python_vulns(
        self,
        package: Optional[str] = None,
        max_results: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Query OSV for Python ecosystem vulnerabilities.

        Args:
            package: Specific PyPI package name (optional)
            max_results: Maximum results to return

        Returns:
            List of vulnerability records
        """
        results = []

        # Query by well-known vulnerable Python packages
        target_packages = [package] if package else [
            'django', 'flask', 'jinja2', 'sqlalchemy', 'lxml',
            'pyyaml', 'pillow', 'requests', 'paramiko', 'cryptography',
            'urllib3', 'aiohttp', 'fastapi', 'tornado', 'celery',
            'numpy', 'scipy', 'simplejson',
        ]

        for pkg in target_packages:
            if len(results) >= max_results:
                break

            payload = {
                "package": {
                    "name": pkg,
                    "ecosystem": "PyPI"
                }
            }

            try:
                resp = self.session.post(
                    f"{self.BASE_URL}/query",
                    json=payload,
                    timeout=15,
                )
                resp.raise_for_status()
                data = resp.json()
            except requests.RequestException as e:
                logger.warning(f"OSV query for {pkg} failed: {e}")
                continue

            vulns = data.get('vulns', [])
            for v in vulns:
                parsed = self._parse_osv(v, pkg)
                if parsed:
                    results.append(parsed)

            if vulns:
                logger.info(f"  OSV [{pkg}]: found {len(vulns)} vulnerabilities")
            time.sleep(0.5)  # Be polite

        return results[:max_results]

    def _parse_osv(self, vuln: Dict, package: str) -> Optional[Dict[str, Any]]:
        """Parse an OSV vulnerability record."""
        osv_id = vuln.get('id', '')
        summary = vuln.get('summary', '')
        details = vuln.get('details', '')
        description = summary or details

        if not description:
            return None

        # Map aliases to CVE IDs
        aliases = vuln.get('aliases', [])
        cve_id = next((a for a in aliases if a.startswith('CVE-')), osv_id)

        # Detect CWE from description heuristics
        vuln_type = self._detect_vuln_type(description)

        # Extract affected version info
        affected = vuln.get('affected', [])
        fix_commit = None
        for aff in affected:
            ranges = aff.get('ranges', [])
            for r in ranges:
                events = r.get('events', [])
                for ev in events:
                    if 'fixed' in ev:
                        fix_commit = ev['fixed']

        # Get references
        references = vuln.get('references', [])
        github_refs = [
            r['url'] for r in references
            if 'github.com' in r.get('url', '')
        ]

        severity = vuln.get('database_specific', {}).get('severity', 'MODERATE')
        severity_map = {'LOW': 'low', 'MODERATE': 'medium', 'HIGH': 'high', 'CRITICAL': 'critical'}

        return {
            'cve_id': cve_id,
            'cwe_id': REVERSE_CWE_MAP.get(vuln_type, ''),
            'description': description[:500],
            'severity': severity_map.get(severity, 'medium'),
            'vulnerability_type': vuln_type,
            'package': package,
            'fix_commit': fix_commit,
            'github_refs': github_refs,
        }

    def _detect_vuln_type(self, text: str) -> str:
        """Heuristically detect vulnerability type from description text."""
        text_lower = text.lower()
        patterns = {
            'sql_injection': ['sql injection', 'sqli', 'sql query'],
            'xss': ['cross-site scripting', 'xss', 'script injection'],
            'command_injection': ['command injection', 'os command', 'shell injection', 'remote code execution', 'rce'],
            'path_traversal': ['path traversal', 'directory traversal', 'local file inclusion', '../', 'lfi'],
            'xxe': ['xml external entity', 'xxe', 'xml injection'],
            'ssrf': ['server-side request forgery', 'ssrf'],
            'deserialization': ['deserialization', 'pickle', 'unpickle', 'yaml.load', 'marshal'],
            'ssti': ['template injection', 'ssti', 'jinja'],
            'open_redirect': ['open redirect', 'url redirect'],
            'idor': ['insecure direct object', 'idor', 'authorization bypass'],
        }

        for vuln_type, keywords in patterns.items():
            if any(kw in text_lower for kw in keywords):
                return vuln_type

        return 'unknown'


class GitHubCodeExtractor:
    """
    Extracts vulnerable code from GitHub commit diffs.
    Uses public raw URLs — no auth needed for public repos.
    """

    # Regex to extract owner/repo from GitHub URLs
    GITHUB_REPO_RE = re.compile(
        r'github\.com/([^/]+/[^/]+?)(?:\.git)?(?:/|$)'
    )
    GITHUB_COMMIT_RE = re.compile(
        r'github\.com/[^/]+/[^/]+/commit/([a-f0-9]+)'
    )

    def __init__(self):
        self.session = requests.Session()
        self.session.headers['Accept'] = 'application/vnd.github.v3.diff'

    def extract_vulnerable_code(
        self,
        github_refs: List[str],
        vuln_type: str,
    ) -> Optional[str]:
        """
        Try to extract vulnerable (pre-fix) code from GitHub references.

        Args:
            github_refs: List of GitHub URLs from CVE references
            vuln_type: Expected vulnerability type

        Returns:
            Extracted vulnerable code snippet, or None
        """
        for ref in github_refs:
            # Try commit URL first
            commit_match = self.GITHUB_COMMIT_RE.search(ref)
            if commit_match:
                code = self._extract_from_commit(ref)
                if code:
                    return code

        return None

    def _extract_from_commit(self, commit_url: str) -> Optional[str]:
        """Extract pre-fix code from a commit diff."""
        # Convert to .diff URL
        diff_url = commit_url + '.diff'

        try:
            resp = self.session.get(diff_url, timeout=15)
            if resp.status_code != 200:
                return None

            diff_text = resp.text
            return self._parse_diff_for_removed_code(diff_text)

        except requests.RequestException:
            return None

    def _parse_diff_for_removed_code(self, diff_text: str) -> Optional[str]:
        """
        Extract removed lines (the vulnerable code) from a unified diff.
        Only extracts Python files (.py).
        """
        lines = diff_text.split('\n')
        removed_blocks = []
        current_file = None
        current_block = []
        in_python_file = False

        for line in lines:
            if line.startswith('diff --git'):
                # Save previous block
                if current_block and in_python_file:
                    removed_blocks.append('\n'.join(current_block))
                current_block = []
                in_python_file = line.endswith('.py')
                continue

            if in_python_file and line.startswith('-') and not line.startswith('---'):
                # This is a removed line (the vulnerable version)
                current_block.append(line[1:])  # Strip leading '-'
            elif in_python_file and not line.startswith('+'):
                # Context line — keep for readability
                if current_block:
                    current_block.append(line.lstrip(' '))

        # Final block
        if current_block and in_python_file:
            removed_blocks.append('\n'.join(current_block))

        if not removed_blocks:
            return None

        # Return the largest block (most likely the main vulnerable function)
        best = max(removed_blocks, key=len)
        # Trim to reasonable size
        lines = best.split('\n')
        if len(lines) > 60:
            lines = lines[:60]

        return '\n'.join(lines) if len('\n'.join(lines)) > 50 else None


class CVEDatasetBuilder:
    """
    Orchestrates multi-source CVE scraping and builds a training dataset.
    """

    def __init__(self, nvd_api_key: Optional[str] = None):
        self.nvd = NVDScraper(api_key=nvd_api_key)
        self.osv = OSVScraper()
        self.github = GitHubCodeExtractor()
        self.samples: List[RealWorldSample] = []

    def build_dataset(
        self,
        samples_per_type: int = 20,
        output_path: str = "datasets/real_world/cve_dataset.json",
    ) -> List[RealWorldSample]:
        """
        Build a comprehensive dataset from multiple sources.

        Args:
            samples_per_type: Target number of samples per vulnerability type
            output_path: Where to save the dataset

        Returns:
            List of RealWorldSample objects
        """
        logger.info("=" * 60)
        logger.info("Starting CVE Dataset Build")
        logger.info("=" * 60)

        # Phase 1: Scrape NVD for all our vulnerability types
        logger.info("\n--- Phase 1: NVD Scraping ---")
        nvd_samples = self._scrape_nvd(samples_per_type)
        logger.info(f"NVD yielded {len(nvd_samples)} raw CVE records")

        # Phase 2: Scrape OSV for Python-specific vulns
        logger.info("\n--- Phase 2: OSV Scraping ---")
        osv_samples = self._scrape_osv(samples_per_type)
        logger.info(f"OSV yielded {len(osv_samples)} raw vulnerability records")

        # Phase 3: For each CVE with GitHub refs, try to extract actual code
        logger.info("\n--- Phase 3: GitHub Code Extraction ---")
        all_raw = nvd_samples + osv_samples
        code_samples = self._extract_code_samples(all_raw)
        logger.info(f"Successfully extracted {len(code_samples)} code samples from GitHub")

        # Phase 4: For CVEs without extractable code, synthesize from description
        logger.info("\n--- Phase 4: Description-Based Synthesis ---")
        desc_samples = self._synthesize_from_descriptions(all_raw, code_samples)
        logger.info(f"Synthesized {len(desc_samples)} samples from CVE descriptions")

        # Combine and deduplicate
        self.samples = code_samples + desc_samples
        self._deduplicate()

        # Save dataset
        self._save_dataset(output_path)

        logger.info(f"\n{'=' * 60}")
        logger.info(f"FINAL DATASET: {len(self.samples)} unique samples")
        self._print_distribution()
        logger.info(f"{'=' * 60}")

        return self.samples

    def _scrape_nvd(self, samples_per_type: int) -> List[Dict]:
        """Scrape NVD for each vulnerability type."""
        all_records = []

        for cwe_id, vuln_type in CWE_MAP.items():
            logger.info(f"  Querying NVD for {vuln_type} ({cwe_id})...")
            try:
                records = self.nvd.fetch_cves_by_cwe(
                    cwe_id=cwe_id,
                    max_results=samples_per_type,
                    keyword='python',
                )
                all_records.extend(records)
                logger.info(f"    → {len(records)} records found")
            except Exception as e:
                logger.warning(f"    → Failed: {e}")

        return all_records

    def _scrape_osv(self, max_results: int) -> List[Dict]:
        """Scrape OSV for Python ecosystem vulnerabilities."""
        try:
            records = self.osv.query_python_vulns(max_results=max_results * 3)
            # Filter out 'unknown' types
            return [r for r in records if r.get('vulnerability_type') != 'unknown']
        except Exception as e:
            logger.warning(f"OSV scraping failed: {e}")
            return []

    def _extract_code_samples(self, raw_records: List[Dict]) -> List[RealWorldSample]:
        """Try to extract actual code from GitHub references."""
        samples = []
        seen_cves = set()

        for record in raw_records:
            cve_id = record.get('cve_id', '')
            if cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)

            github_refs = record.get('github_refs', [])
            if not github_refs:
                continue

            vuln_type = record.get('vulnerability_type', 'unknown')
            code = self.github.extract_vulnerable_code(github_refs, vuln_type)

            if code and len(code) > 50:
                sample = RealWorldSample(
                    id=f"cve_{cve_id.lower().replace('-', '_')}",
                    code=code,
                    vulnerability_type=vuln_type,
                    severity=record.get('severity', 'medium'),
                    language='python',
                    complexity=self._estimate_complexity(code),
                    description=record.get('description', '')[:300],
                    cwe_id=record.get('cwe_id', ''),
                    cve_id=cve_id,
                    source='github',
                )
                samples.append(sample)

            # Rate limit GitHub
            time.sleep(1)

        return samples

    def _synthesize_from_descriptions(
        self,
        raw_records: List[Dict],
        existing_samples: List[RealWorldSample],
    ) -> List[RealWorldSample]:
        """
        For CVEs where we couldn't extract code, create realistic
        vulnerable code snippets based on the CVE description.
        Uses deterministic template-based synthesis — no LLM needed.
        """
        existing_cves = {s.cve_id for s in existing_samples}
        samples = []

        # Code templates inspired by real-world patterns (one per vuln type)
        TEMPLATES = {
            'sql_injection': [
                'import sqlite3\ndef get_user(db, username):\n    query = "SELECT * FROM users WHERE name=\'" + username + "\'"\n    return db.execute(query).fetchone()',
                'def search_products(cursor, term):\n    sql = f"SELECT * FROM products WHERE name LIKE \'%{term}%\'"\n    cursor.execute(sql)\n    return cursor.fetchall()',
                'def authenticate(conn, user, pwd):\n    q = "SELECT id FROM auth WHERE user=\'" + user + "\' AND pass=\'" + pwd + "\'"\n    return conn.execute(q).fetchone() is not None',
            ],
            'xss': [
                'from flask import request, Markup\ndef render_search():\n    q = request.args.get("q", "")\n    return f"<h1>Results for: {q}</h1>"',
                'def format_comment(username, text):\n    return f"<div class=\'comment\'><b>{username}</b>: {text}</div>"',
                'from flask import request\n@app.route("/profile")\ndef profile():\n    name = request.args.get("name")\n    return f"<title>{name}\'s Profile</title>"',
            ],
            'command_injection': [
                'import os\ndef check_host(hostname):\n    return os.popen(f"ping -c 1 {hostname}").read()',
                'import subprocess\ndef convert_file(input_path, output_path):\n    subprocess.call(f"ffmpeg -i {input_path} {output_path}", shell=True)',
                'import os\ndef list_dir(path):\n    return os.system(f"ls -la {path}")',
            ],
            'path_traversal': [
                'def read_file(filename):\n    with open(f"/var/uploads/{filename}", "r") as f:\n        return f.read()',
                'import os\ndef serve_static(path):\n    full = os.path.join("/var/www/static", path)\n    with open(full) as f:\n        return f.read()',
            ],
            'xxe': [
                'from lxml import etree\ndef parse_xml(xml_str):\n    doc = etree.fromstring(xml_str)\n    return etree.tostring(doc)',
                'import xml.etree.ElementTree as ET\ndef process_config(xml_data):\n    root = ET.fromstring(xml_data)\n    return {child.tag: child.text for child in root}',
            ],
            'ssrf': [
                'import requests\ndef proxy_request(url):\n    resp = requests.get(url)\n    return resp.text',
                'import urllib.request\ndef fetch_resource(url):\n    return urllib.request.urlopen(url).read()',
            ],
            'deserialization': [
                'import pickle\ndef load_session(data):\n    return pickle.loads(data)',
                'import yaml\ndef parse_config(yaml_str):\n    return yaml.load(yaml_str)',
            ],
            'ssti': [
                'from jinja2 import Template\ndef render_greeting(name):\n    t = Template(f"Hello {name}!")\n    return t.render()',
                'from flask import render_template_string, request\n@app.route("/hello")\ndef hello():\n    name = request.args.get("name")\n    return render_template_string("Hello " + name)',
            ],
            'open_redirect': [
                'from flask import redirect, request\n@app.route("/login")\ndef login():\n    next_url = request.args.get("next", "/")\n    return redirect(next_url)',
            ],
            'idor': [
                'from flask import request\n@app.route("/api/user/<int:uid>")\ndef get_user(uid):\n    return db.query(User).get(uid).to_dict()',
            ],
            'nosql_injection': [
                'from pymongo import MongoClient\ndef find_user(db, query):\n    return db.users.find_one(query)',
            ],
        }

        for record in raw_records:
            cve_id = record.get('cve_id', '')
            if cve_id in existing_cves or not cve_id:
                continue

            vuln_type = record.get('vulnerability_type', 'unknown')
            if vuln_type not in TEMPLATES:
                continue

            # Pick a template deterministically based on CVE ID hash
            templates = TEMPLATES[vuln_type]
            idx = int(hashlib.md5(cve_id.encode()).hexdigest(), 16) % len(templates)
            code = templates[idx]

            sample = RealWorldSample(
                id=f"cve_{cve_id.lower().replace('-', '_')}",
                code=code,
                vulnerability_type=vuln_type,
                severity=record.get('severity', 'medium'),
                language='python',
                complexity='low',
                description=record.get('description', '')[:300],
                cwe_id=record.get('cwe_id', ''),
                cve_id=cve_id,
                source='nvd_synthesized',
            )
            samples.append(sample)

        return samples

    def _estimate_complexity(self, code: str) -> str:
        """Estimate code complexity heuristically."""
        lines = code.strip().split('\n')
        if len(lines) > 30:
            return 'high'
        elif len(lines) > 10:
            return 'medium'
        return 'low'

    def _deduplicate(self):
        """Remove duplicate samples by code hash."""
        seen = set()
        unique = []
        for s in self.samples:
            h = hashlib.md5(s.code.encode()).hexdigest()
            if h not in seen:
                seen.add(h)
                unique.append(s)
        self.samples = unique

    def _save_dataset(self, output_path: str):
        """Save dataset to JSON."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        data = [asdict(s) for s in self.samples]
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)

        logger.info(f"Dataset saved to {output_path}")

    def _print_distribution(self):
        """Print vulnerability type distribution."""
        dist = {}
        for s in self.samples:
            dist[s.vulnerability_type] = dist.get(s.vulnerability_type, 0) + 1

        for vt, count in sorted(dist.items(), key=lambda x: -x[1]):
            logger.info(f"  {vt:25s}: {count:4d} samples")


# ─── CLI Entry Point ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
    )

    builder = CVEDatasetBuilder()
    samples = builder.build_dataset(
        samples_per_type=30,
        output_path="datasets/real_world/cve_dataset.json",
    )

    print(f"\nDone! Generated {len(samples)} real-world training samples.")
