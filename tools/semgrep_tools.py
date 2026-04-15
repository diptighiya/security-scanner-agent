"""Semgrep integration tools for static analysis."""

from __future__ import annotations

import subprocess
import json
import logging
import shutil
from pathlib import Path
from typing import Optional

from scanner_types import SemgrepFinding

logger = logging.getLogger(__name__)


# Semgrep rule sets to run — ordered by relevance to security
SEMGREP_RULESETS = [
    "p/owasp-top-ten",
    "p/security-audit",
    "p/secrets",
    "p/sql-injection",
    "p/xss",
    "p/command-injection",
    "p/java",
    "p/python",
    "p/javascript",
]

# Language-specific rulesets
LANGUAGE_RULESETS = {
    "java": ["p/java", "p/spring-security"],
    "python": ["p/python", "p/flask", "p/django"],
    "javascript": ["p/javascript", "p/nodejs", "p/react"],
    "typescript": ["p/typescript", "p/react"],
    "ruby": ["p/ruby", "p/rails"],
    "go": ["p/golang"],
    "php": ["p/php"],
}


def is_semgrep_available() -> bool:
    """Check if semgrep is installed and accessible."""
    return shutil.which("semgrep") is not None


def run_semgrep(
    repo_path: str,
    languages: Optional[list[str]] = None,
    timeout: int = 300,
) -> list[SemgrepFinding]:
    """
    Run semgrep against a repository and return structured findings.

    Args:
        repo_path: Path to the repository to scan.
        languages: List of languages detected in the repo.
        timeout: Timeout in seconds for semgrep execution.

    Returns:
        List of SemgrepFinding objects.
    """
    if not is_semgrep_available():
        logger.warning("Semgrep not found. Skipping static analysis.")
        return []

    rulesets = _select_rulesets(languages or [])
    all_findings: list[SemgrepFinding] = []

    for ruleset in rulesets:
        findings = _run_semgrep_ruleset(repo_path, ruleset, timeout)
        all_findings.extend(findings)

    # Deduplicate findings by (rule_id, file_path, line_number)
    seen = set()
    unique_findings = []
    for f in all_findings:
        key = (f.rule_id, f.file_path, f.line_number)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    logger.info(f"Semgrep found {len(unique_findings)} unique findings across {len(rulesets)} rulesets")
    return unique_findings


def _select_rulesets(languages: list[str]) -> list[str]:
    """Select appropriate rulesets based on detected languages."""
    # Always include core security rulesets
    selected = {"p/owasp-top-ten", "p/security-audit", "p/secrets"}

    for lang in languages:
        lang_lower = lang.lower()
        if lang_lower in LANGUAGE_RULESETS:
            selected.update(LANGUAGE_RULESETS[lang_lower])

    return list(selected)


def _run_semgrep_ruleset(
    repo_path: str,
    ruleset: str,
    timeout: int,
) -> list[SemgrepFinding]:
    """Run a single semgrep ruleset and parse results."""
    cmd = [
        "semgrep",
        "--config", ruleset,
        "--json",
        "--no-git-ignore",
        "--timeout", str(timeout),
        "--max-memory", "2000",
        repo_path,
    ]

    logger.info(f"Running semgrep with ruleset: {ruleset}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 30,
        )

        if result.returncode not in (0, 1):  # 0 = no findings, 1 = findings found
            logger.warning(
                f"Semgrep exited with code {result.returncode} for ruleset {ruleset}: "
                f"{result.stderr[:500]}"
            )

        if not result.stdout.strip():
            return []

        return _parse_semgrep_output(result.stdout, repo_path)

    except subprocess.TimeoutExpired:
        logger.warning(f"Semgrep timed out for ruleset {ruleset}")
        return []
    except Exception as e:
        logger.error(f"Semgrep execution failed for ruleset {ruleset}: {e}")
        return []


def _parse_semgrep_output(json_output: str, repo_path: str) -> list[SemgrepFinding]:
    """Parse semgrep JSON output into SemgrepFinding objects."""
    findings = []

    try:
        data = json.loads(json_output)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse semgrep JSON output: {e}")
        return []

    results = data.get("results", [])
    repo_path_normalized = str(Path(repo_path))

    for result in results:
        try:
            file_path = result.get("path", "")
            # Make path relative to repo root
            if file_path.startswith(repo_path_normalized):
                file_path = file_path[len(repo_path_normalized):].lstrip("/\\")

            start = result.get("start", {})
            line_number = start.get("line", 0)
            column = start.get("col", 0)

            extra = result.get("extra", {})
            message = extra.get("message", "")
            severity = extra.get("severity", "WARNING").lower()
            lines = extra.get("lines", "")

            # Normalize severity
            severity_map = {
                "error": "high",
                "warning": "medium",
                "info": "low",
                "high": "high",
                "medium": "medium",
                "low": "low",
                "critical": "critical",
            }
            severity = severity_map.get(severity, "medium")

            metadata = extra.get("metadata", {})
            category = metadata.get("category", "")
            if not category:
                category = metadata.get("owasp", [""])[0] if isinstance(metadata.get("owasp"), list) else ""

            finding = SemgrepFinding(
                rule_id=result.get("check_id", "unknown"),
                file_path=file_path,
                line_number=line_number,
                column=column,
                message=message,
                severity=severity,
                code_snippet=lines.strip() if lines else "",
                category=str(category),
            )
            findings.append(finding)

        except Exception as e:
            logger.debug(f"Failed to parse semgrep result entry: {e}")
            continue

    return findings


def run_semgrep_on_file(
    file_path: str,
    rules: str = "p/security-audit",
    timeout: int = 60,
) -> list[SemgrepFinding]:
    """Run semgrep on a single file."""
    return _run_semgrep_ruleset(file_path, rules, timeout)


def semgrep_findings_to_dict(findings: list[SemgrepFinding]) -> list[dict]:
    """Convert SemgrepFinding list to serializable dicts."""
    return [
        {
            "rule_id": f.rule_id,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "column": f.column,
            "message": f.message,
            "severity": f.severity,
            "code_snippet": f.code_snippet,
            "category": f.category,
        }
        for f in findings
    ]
