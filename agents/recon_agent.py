"""
Agent 1 — Reconnaissance Agent

Accepts a GitHub repo URL, clones the repo, and produces a structured
JSON codebase map covering languages, frameworks, dependencies, entry
points, and sensitive areas.
"""

import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Optional

# Add parent dir to path so relative imports work when running standalone
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner_types import CodebaseMap, DependencyInfo, EntryPoint, SensitiveArea
from tools.git_tools import (
    clone_repository,
    list_all_files,
    get_repo_metadata,
    count_lines_in_repo,
)
from tools.file_tools import (
    detect_languages,
    detect_frameworks,
    parse_dependencies,
    find_sensitive_areas,
    find_entry_points,
)
from tools.llm_client import LLMClient

logger = logging.getLogger(__name__)


class ReconAgent:
    """
    Reconnaissance Agent: maps a GitHub repository's structure,
    languages, frameworks, dependencies, and security-sensitive areas.
    """

    def __init__(self, gemini_api_key: str, groq_api_key: str = ""):
        self.llm = LLMClient(gemini_api_key=gemini_api_key, groq_api_key=groq_api_key)
        logger.info("ReconAgent initialized")

    def run(self, repo_url: str, existing_repo_path: Optional[str] = None) -> dict:
        """
        Run the reconnaissance agent on a GitHub repository.

        Args:
            repo_url: GitHub repository URL.
            existing_repo_path: If provided, skip cloning and use this path.

        Returns:
            A dictionary representing the CodebaseMap, suitable for JSON serialization.
        """
        logger.info(f"[ReconAgent] Starting reconnaissance on: {repo_url}")

        # Step 1: Clone the repository
        if existing_repo_path and os.path.isdir(existing_repo_path):
            repo_path = existing_repo_path
            logger.info(f"[ReconAgent] Using existing repo at: {repo_path}")
        else:
            logger.info("[ReconAgent] Cloning repository...")
            repo_path = clone_repository(repo_url)

        # Step 2: List all files
        logger.info("[ReconAgent] Listing files...")
        all_files = list_all_files(repo_path)
        logger.info(f"[ReconAgent] Found {len(all_files)} files")

        # Step 3: Detect languages
        logger.info("[ReconAgent] Detecting languages...")
        languages = detect_languages(all_files)
        logger.info(f"[ReconAgent] Languages detected: {languages}")

        # Step 4: Detect frameworks
        logger.info("[ReconAgent] Detecting frameworks...")
        frameworks = detect_frameworks(repo_path, all_files)
        logger.info(f"[ReconAgent] Frameworks detected: {frameworks}")

        # Step 5: Parse dependencies
        logger.info("[ReconAgent] Parsing dependencies...")
        dependencies = parse_dependencies(repo_path, all_files)
        logger.info(f"[ReconAgent] Found {len(dependencies)} dependencies")

        # Step 6: Find entry points
        logger.info("[ReconAgent] Finding entry points...")
        entry_points = find_entry_points(repo_path, all_files)
        logger.info(f"[ReconAgent] Found {len(entry_points)} entry points")

        # Step 7: Find sensitive areas
        logger.info("[ReconAgent] Scanning for sensitive areas...")
        sensitive_areas = find_sensitive_areas(repo_path, all_files)
        logger.info(f"[ReconAgent] Found {len(sensitive_areas)} sensitive code locations")

        # Step 8: Count total lines
        total_lines = count_lines_in_repo(repo_path, all_files[:500])

        # Step 9: Use Gemini to enhance the analysis
        logger.info("[ReconAgent] Asking Gemini to enhance codebase analysis...")
        gemini_insights = self._gemini_enhance_analysis(
            repo_url, all_files, languages, frameworks, dependencies, sensitive_areas
        )

        # Merge Gemini insights into the map
        if gemini_insights.get("additional_frameworks"):
            frameworks = list(set(frameworks + gemini_insights["additional_frameworks"]))
        if gemini_insights.get("additional_sensitive_areas"):
            for area_data in gemini_insights["additional_sensitive_areas"]:
                sensitive_areas.append(SensitiveArea(
                    file_path=area_data.get("file_path", ""),
                    area_type=area_data.get("area_type", "unknown"),
                    line_number=area_data.get("line_number"),
                    description=area_data.get("description", ""),
                ))

        # Build the result dict
        result = {
            "repo_url": repo_url,
            "repo_path": repo_path,
            "languages": languages,
            "frameworks": frameworks,
            "dependencies": [
                {"name": d.name, "version": d.version, "source_file": d.source_file}
                for d in dependencies
            ],
            "entry_points": [
                {
                    "file_path": e.file_path,
                    "function_name": e.function_name,
                    "line_number": e.line_number,
                    "description": e.description,
                }
                for e in entry_points[:50]
            ],
            "sensitive_areas": [
                {
                    "file_path": s.file_path,
                    "area_type": s.area_type,
                    "line_number": s.line_number,
                    "description": s.description,
                }
                for s in sensitive_areas[:200]
            ],
            "file_tree": all_files[:1000],
            "total_files": len(all_files),
            "total_lines": total_lines,
            "gemini_insights": gemini_insights.get("summary", ""),
            "repo_metadata": get_repo_metadata(repo_path),
        }

        logger.info("[ReconAgent] Reconnaissance complete.")
        return result

    def _gemini_enhance_analysis(
        self,
        repo_url: str,
        all_files: list,
        languages: list,
        frameworks: list,
        dependencies: list,
        sensitive_areas: list,
    ) -> dict:
        """
        Use Gemini to provide additional insights about the codebase structure
        and highlight any overlooked sensitive areas.
        """
        dep_names = [d.name for d in dependencies[:50]]
        sample_files = all_files[:100]
        sensitive_sample = [
            {"file": s.file_path, "type": s.area_type, "hint": s.description[:80]}
            for s in sensitive_areas[:30]
        ]

        prompt = f"""You are a security-focused code analyst. I have cloned a GitHub repository and done initial analysis.

Repository: {repo_url}
Languages detected: {', '.join(languages)}
Frameworks detected: {', '.join(frameworks) if frameworks else 'None detected'}
Number of files: {len(all_files)}
Sample of dependency names: {json.dumps(dep_names[:30])}

Sample of files in the repo (first 100):
{chr(10).join(f'  - {f}' for f in sample_files)}

Sensitive code areas already identified (sample):
{json.dumps(sensitive_sample, indent=2)}

Based on this information, please provide:
1. A 3-5 sentence summary of the codebase's purpose and architecture from a security perspective
2. Any additional frameworks or security-relevant libraries you can identify from the file names and dependency list
3. Any additional sensitive areas I might have missed (auth, DB, file handling, deserialization, etc.) based on the file names

Respond ONLY in valid JSON with this structure:
{{
  "summary": "...",
  "additional_frameworks": ["..."],
  "additional_sensitive_areas": [
    {{"file_path": "...", "area_type": "...", "description": "..."}}
  ],
  "security_observations": ["..."]
}}"""

        try:
            return self.llm.generate_json(prompt)
        except Exception as e:
            logger.warning(f"Gemini enhancement failed: {e}")
            return {
                "summary": "Gemini analysis unavailable.",
                "additional_frameworks": [],
                "additional_sensitive_areas": [],
            }
