"""Shared dataclasses and type definitions for the security scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List, Dict
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class DependencyInfo:
    name: str
    version: Optional[str] = None
    source_file: str = ""


@dataclass
class EntryPoint:
    file_path: str
    function_name: Optional[str] = None
    line_number: Optional[int] = None
    description: str = ""


@dataclass
class SensitiveArea:
    file_path: str
    area_type: str  # auth, database, file_handling, api_endpoint, crypto, etc.
    line_number: Optional[int] = None
    description: str = ""


@dataclass
class CodebaseMap:
    repo_url: str
    repo_path: str
    languages: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)
    dependencies: List[DependencyInfo] = field(default_factory=list)
    entry_points: List[EntryPoint] = field(default_factory=list)
    sensitive_areas: List[SensitiveArea] = field(default_factory=list)
    file_tree: List[str] = field(default_factory=list)
    total_files: int = 0
    total_lines: int = 0


@dataclass
class SemgrepFinding:
    rule_id: str
    file_path: str
    line_number: int
    column: int
    message: str
    severity: str
    code_snippet: str = ""
    category: str = ""


@dataclass
class VulnerabilityFinding:
    id: str
    title: str
    description: str
    severity: Severity
    file_path: str
    line_number: Optional[int]
    code_snippet: str
    attack_scenario: str
    attack_chain: Optional[str] = None  # how this combines with other findings
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation_hint: str = ""
    source: str = "gemini"  # "semgrep" or "gemini"
    related_finding_ids: List[str] = field(default_factory=list)


@dataclass
class SecurityReport:
    repo_url: str
    scan_timestamp: str
    executive_summary: str
    overall_risk_score: float  # 0.0 - 10.0
    overall_risk_label: str   # Critical / High / Medium / Low
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)
    scan_stats: dict = field(default_factory=dict)
