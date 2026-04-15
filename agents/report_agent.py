"""
Agent 3 — Remediation Report Agent

Takes findings from Agent 2 and produces a professional Markdown
security report with executive summary, findings table, vulnerable/fixed
code snippets, risk score, and next steps.
"""

import json
import logging
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.file_tools import _read_file_safe, get_file_snippets
from tools.llm_client import LLMClient

logger = logging.getLogger(__name__)

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

RISK_SCORE_WEIGHTS = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}


class ReportAgent:
    """
    Remediation Report Agent: generates a professional Markdown security
    report from vulnerability findings.
    """

    def __init__(self, gemini_api_key: str, groq_api_key: str = ""):
        self.llm = LLMClient(gemini_api_key=gemini_api_key, groq_api_key=groq_api_key)
        logger.info("ReportAgent initialized")

    def run(self, analysis_results: dict, output_dir: str = ".") -> str:
        """
        Generate a Markdown security report.

        Args:
            analysis_results: Output dict from VulnerabilityAgent.
            output_dir: Directory to save the report.

        Returns:
            Path to the generated Markdown report file.
        """
        repo_url = analysis_results.get("repo_url", "Unknown Repository")
        repo_path = analysis_results.get("repo_path", "")
        findings = analysis_results.get("findings", [])
        severity_breakdown = analysis_results.get("severity_breakdown", {})
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        logger.info(f"[ReportAgent] Generating report for {repo_url} with {len(findings)} findings")

        # Sort findings by severity
        sorted_findings = sorted(
            findings,
            key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 5),
        )

        # Calculate risk score
        risk_score, risk_label = self._calculate_risk_score(severity_breakdown)

        # Generate executive summary via Gemini
        logger.info("[ReportAgent] Generating executive summary with Gemini...")
        executive_summary = self._generate_executive_summary(
            repo_url, sorted_findings, severity_breakdown, risk_score, risk_label
        )

        # Generate remediation advice for each finding via Gemini
        logger.info("[ReportAgent] Generating remediation advice for findings...")
        enriched_findings = self._enrich_findings_with_remediation(
            sorted_findings, repo_path
        )

        # Generate next steps via Gemini
        logger.info("[ReportAgent] Generating next steps...")
        next_steps = self._generate_next_steps(
            repo_url, enriched_findings, severity_breakdown
        )

        # Build the full Markdown report
        report_md = self._build_markdown_report(
            repo_url=repo_url,
            timestamp=timestamp,
            executive_summary=executive_summary,
            risk_score=risk_score,
            risk_label=risk_label,
            severity_breakdown=severity_breakdown,
            findings=enriched_findings,
            next_steps=next_steps,
            scan_stats=analysis_results,
        )

        # Save report
        timestamp_file = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"security-report-{timestamp_file}.md"
        output_path = Path(output_dir) / filename
        output_path.write_text(report_md, encoding="utf-8")
        logger.info(f"[ReportAgent] Report saved to: {output_path}")

        return str(output_path)

    # -------------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------------

    def _calculate_risk_score(self, severity_breakdown: dict) -> tuple:
        """Calculate an overall risk score (0-10) from severity breakdown."""
        total_weight = 0
        total_count = 0
        for sev, count in severity_breakdown.items():
            weight = RISK_SCORE_WEIGHTS.get(sev, 0)
            total_weight += weight * count
            total_count += count

        if total_count == 0:
            return 0.0, "None"

        max_possible = total_count * 10
        score = min(10.0, (total_weight / max(max_possible, 1)) * 10 * (1 + total_count * 0.05))
        score = round(min(score, 10.0), 1)

        if score >= 9.0:
            label = "Critical"
        elif score >= 7.0:
            label = "High"
        elif score >= 4.0:
            label = "Medium"
        elif score > 0:
            label = "Low"
        else:
            label = "None"

        return score, label

    def _generate_executive_summary(
        self,
        repo_url: str,
        findings: list,
        severity_breakdown: dict,
        risk_score: float,
        risk_label: str,
    ) -> str:
        """Generate an executive summary using Gemini."""
        top_findings = [
            {
                "title": f.get("title", ""),
                "severity": f.get("severity", ""),
                "description": f.get("description", "")[:150],
                "file_path": f.get("file_path", ""),
            }
            for f in findings[:10]
        ]

        prompt = f"""You are a senior security consultant writing an executive summary for a security audit report.

Repository audited: {repo_url}
Overall Risk Score: {risk_score}/10 ({risk_label})

Severity breakdown:
- Critical: {severity_breakdown.get('critical', 0)}
- High: {severity_breakdown.get('high', 0)}
- Medium: {severity_breakdown.get('medium', 0)}
- Low: {severity_breakdown.get('low', 0)}

Top findings:
{json.dumps(top_findings, indent=2)}

Write a professional executive summary (3-5 paragraphs) for a non-technical executive audience that:
1. States the overall security posture and risk level
2. Highlights the most critical findings and their business impact
3. Mentions any systemic issues (e.g., widespread injection vulnerabilities)
4. Briefly mentions the testing methodology used (automated SAST + AI-powered analysis)
5. Sets expectations for the detailed findings that follow

Write in plain English. Do not use bullet points. Do not include the heading "Executive Summary".
Keep it under 400 words. Return plain text only, no JSON."""

        try:
            return self.llm.generate(prompt)
        except Exception as e:
            logger.warning(f"Gemini executive summary failed: {e}")
            critical = severity_breakdown.get('critical', 0)
            high = severity_breakdown.get('high', 0)
            return (
                f"This security assessment of {repo_url} identified {len(findings)} vulnerabilities "
                f"with an overall risk score of {risk_score}/10 ({risk_label}). "
                f"The scan found {critical} critical and {high} high severity issues that require "
                f"immediate attention. A combination of Semgrep static analysis and AI-powered "
                f"vulnerability reasoning was used."
            )

    def _enrich_findings_with_remediation(
        self,
        findings: list,
        repo_path: str,
    ) -> list:
        """
        For each critical/high finding, use Gemini to generate:
        - The vulnerable code snippet (with context)
        - A fixed code snippet
        - A plain-English explanation
        """
        enriched = []
        priority_findings = [f for f in findings if f.get("severity") in ("critical", "high")]
        other_findings = [f for f in findings if f.get("severity") not in ("critical", "high")]

        # Enrich priority findings with Gemini (cap at 20 API calls)
        for finding in priority_findings[:20]:
            enriched_finding = self._enrich_single_finding(finding, repo_path)
            enriched.append(enriched_finding)

        # For remaining priority findings (beyond cap), pass through as-is
        for finding in priority_findings[20:]:
            finding.setdefault("fixed_code_snippet", "")
            finding.setdefault("explanation", finding.get("description", ""))
            enriched.append(finding)

        # For lower severity, just ensure code snippet is populated
        for finding in other_findings:
            if not finding.get("code_snippet") and finding.get("file_path") and finding.get("line_number"):
                finding["code_snippet"] = get_file_snippets(
                    repo_path, finding["file_path"], finding["line_number"], 5
                )
            finding.setdefault("fixed_code_snippet", "")
            finding.setdefault("explanation", finding.get("description", ""))
            enriched.append(finding)

        return enriched

    def _enrich_single_finding(self, finding: dict, repo_path: str) -> dict:
        """Use Gemini to generate fix for a single finding."""
        file_path = finding.get("file_path", "")
        line_number = finding.get("line_number")
        code_snippet = finding.get("code_snippet", "")

        # Try to get more context if we have a file and line
        if not code_snippet and file_path and line_number and repo_path:
            code_snippet = get_file_snippets(repo_path, file_path, line_number, 8)

        if not code_snippet:
            if file_path and line_number:
                code_snippet = f"(Code at {file_path}:{line_number})"

        prompt = f"""You are a security engineer providing remediation guidance.

## Vulnerability
Title: {finding.get('title', '')}
Severity: {finding.get('severity', '')}
File: {file_path}
Line: {line_number}
CWE: {finding.get('cwe_id', 'N/A')}
OWASP: {finding.get('owasp_category', 'N/A')}

## Description
{finding.get('description', '')}

## Attack Scenario
{finding.get('attack_scenario', '')}

## Vulnerable Code
```
{code_snippet}
```

Provide:
1. A brief explanation (2-3 sentences) of WHY this is vulnerable
2. A fixed version of the vulnerable code (only the changed lines, with context)
3. The key remediation principle

Respond ONLY in valid JSON:
{{
  "explanation": "...",
  "fixed_code_snippet": "...",
  "remediation_principle": "..."
}}"""

        try:
            data = self.llm.generate_json(prompt)
            finding["explanation"] = data.get("explanation", finding.get("description", ""))
            finding["fixed_code_snippet"] = data.get("fixed_code_snippet", "")
            finding["remediation_hint"] = data.get("remediation_principle", "")
            finding["code_snippet"] = code_snippet
        except Exception as e:
            logger.debug(f"Gemini enrichment failed for finding {finding.get('id')}: {e}")
            finding["explanation"] = finding.get("description", "")
            finding["fixed_code_snippet"] = ""
            finding["code_snippet"] = code_snippet

        return finding

    def _generate_next_steps(
        self,
        repo_url: str,
        findings: list,
        severity_breakdown: dict,
    ) -> list:
        """Generate prioritized next steps using Gemini."""
        top_titles = [f.get("title", "") for f in findings[:15]]

        prompt = f"""You are a security consultant. Based on the following security findings, provide 7-10 prioritized, actionable next steps for the development team.

Repository: {repo_url}
Critical findings: {severity_breakdown.get('critical', 0)}
High findings: {severity_breakdown.get('high', 0)}
Medium findings: {severity_breakdown.get('medium', 0)}

Top finding titles:
{chr(10).join(f'- {t}' for t in top_titles)}

Write actionable next steps as a JSON array of strings. Each step should be a single sentence starting with an action verb.
Example format: ["Immediately patch all SQL injection vulnerabilities by using parameterized queries", ...]

Respond ONLY with a valid JSON array of strings."""

        try:
            steps = self.llm.generate_json(prompt)
            if isinstance(steps, list):
                return [str(s) for s in steps]
        except Exception as e:
            logger.warning(f"Gemini next steps generation failed: {e}")

        return [
            "Remediate all critical severity findings immediately before next deployment.",
            "Address high severity findings within one sprint.",
            "Conduct a manual penetration test to validate and expand on automated findings.",
            "Implement a secure code review checklist for pull requests.",
            "Add SAST scanning (Semgrep) to your CI/CD pipeline.",
            "Provide security training to the development team focused on OWASP Top 10.",
            "Schedule quarterly security assessments to track remediation progress.",
        ]

    def _build_markdown_report(
        self,
        repo_url: str,
        timestamp: str,
        executive_summary: str,
        risk_score: float,
        risk_label: str,
        severity_breakdown: dict,
        findings: list,
        next_steps: list,
        scan_stats: dict,
    ) -> str:
        """Assemble the full Markdown report."""
        critical = severity_breakdown.get("critical", 0)
        high = severity_breakdown.get("high", 0)
        medium = severity_breakdown.get("medium", 0)
        low = severity_breakdown.get("low", 0)
        info = severity_breakdown.get("info", 0)
        total = len(findings)

        risk_badge = _risk_badge(risk_label)

        lines = [
            "# Security Assessment Report",
            "",
            f"**Repository:** {repo_url}  ",
            f"**Scan Date:** {timestamp}  ",
            f"**Report Generated By:** Multi-Agent Security Scanner  ",
            f"**Overall Risk Score:** {risk_score}/10 {risk_badge}",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            executive_summary,
            "",
            "---",
            "",
            "## Scan Statistics",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Total Files Scanned | {scan_stats.get('total_files', 'N/A')} |",
            f"| Total Findings | {total} |",
            f"| Semgrep Findings | {scan_stats.get('semgrep_finding_count', 0)} |",
            f"| AI-Powered Findings | {scan_stats.get('gemini_finding_count', 0)} |",
            f"| 🔴 Critical | {critical} |",
            f"| 🟠 High | {high} |",
            f"| 🟡 Medium | {medium} |",
            f"| 🔵 Low | {low} |",
            f"| ⚪ Info | {info} |",
            "",
            "---",
            "",
            "## Findings Summary",
            "",
            "| # | ID | Severity | Title | File | Line |",
            "|---|----|----------|-------|------|------|",
        ]

        for idx, finding in enumerate(findings, 1):
            sev = finding.get("severity", "info")
            emoji = SEVERITY_EMOJI.get(sev, "⚪")
            title = finding.get("title", "Unknown")
            fid = finding.get("id", "")
            fp = finding.get("file_path", "")
            ln = finding.get("line_number", "-")
            title_short = title[:70] + "..." if len(title) > 70 else title
            fp_short = fp[-50:] if len(fp) > 50 else fp
            lines.append(
                f"| {idx} | `{fid}` | {emoji} {sev.upper()} | {title_short} | `{fp_short}` | {ln} |"
            )

        lines += [
            "",
            "---",
            "",
            "## Detailed Findings",
            "",
        ]

        for idx, finding in enumerate(findings, 1):
            sev = finding.get("severity", "info")
            emoji = SEVERITY_EMOJI.get(sev, "⚪")
            title = finding.get("title", "Unknown")
            fid = finding.get("id", "")

            lines += [
                f"### {idx}. {emoji} {title}",
                "",
                "| Field | Value |",
                "|-------|-------|",
                f"| **ID** | `{fid}` |",
                f"| **Severity** | {sev.upper()} |",
                f"| **File** | `{finding.get('file_path', 'N/A')}` |",
                f"| **Line** | {finding.get('line_number', 'N/A')} |",
                f"| **CWE** | {finding.get('cwe_id', 'N/A')} |",
                f"| **OWASP** | {finding.get('owasp_category', 'N/A')} |",
                f"| **Source** | {finding.get('source', 'N/A')} |",
                "",
            ]

            description = finding.get("description") or finding.get("explanation", "")
            if description:
                lines += ["**Description**", "", description, ""]

            explanation = finding.get("explanation", "")
            if explanation and explanation != description:
                lines += ["**Why This Is Vulnerable**", "", explanation, ""]

            code_snippet = finding.get("code_snippet", "")
            if code_snippet:
                lang = _detect_lang_from_path(finding.get("file_path", ""))
                lines += [
                    "**Vulnerable Code**",
                    "",
                    f"```{lang}",
                    code_snippet,
                    "```",
                    "",
                ]

            fixed_snippet = finding.get("fixed_code_snippet", "")
            if fixed_snippet:
                lang = _detect_lang_from_path(finding.get("file_path", ""))
                lines += [
                    "**Fixed Code**",
                    "",
                    f"```{lang}",
                    fixed_snippet,
                    "```",
                    "",
                ]

            attack_scenario = finding.get("attack_scenario", "")
            if attack_scenario:
                lines += ["**Attack Scenario**", "", attack_scenario, ""]

            attack_chain = finding.get("attack_chain", "")
            if attack_chain:
                lines += [f"> **Attack Chain:** {attack_chain}", ""]

            remediation = finding.get("remediation_hint", "")
            if remediation:
                lines += ["**Remediation**", "", f"> {remediation}", ""]

            lines += ["---", ""]

        lines += ["## Recommended Next Steps", ""]
        for i, step in enumerate(next_steps, 1):
            lines.append(f"{i}. {step}")
        lines.append("")

        lines += [
            "---",
            "",
            "*Report generated by Multi-Agent Security Scanner*  ",
            "*Powered by Semgrep + Google Gemini 1.5 Flash*  ",
            f"*Timestamp: {timestamp}*",
            "",
        ]

        return "\n".join(lines)


# -------------------------------------------------------------------------
# Utility functions
# -------------------------------------------------------------------------

def _risk_badge(risk_label: str) -> str:
    badges = {
        "Critical": "🔴 **CRITICAL**",
        "High": "🟠 **HIGH**",
        "Medium": "🟡 **MEDIUM**",
        "Low": "🔵 **LOW**",
        "None": "🟢 **NONE**",
    }
    return badges.get(risk_label, f"**{risk_label}**")


def _detect_lang_from_path(file_path: str) -> str:
    ext_map = {
        ".py": "python",
        ".java": "java",
        ".js": "javascript",
        ".ts": "typescript",
        ".rb": "ruby",
        ".go": "go",
        ".php": "php",
        ".cs": "csharp",
        ".cpp": "cpp",
        ".c": "c",
        ".rs": "rust",
        ".kt": "kotlin",
        ".sql": "sql",
        ".xml": "xml",
        ".html": "html",
        ".sh": "bash",
    }
    ext = Path(file_path).suffix.lower()
    return ext_map.get(ext, "")
