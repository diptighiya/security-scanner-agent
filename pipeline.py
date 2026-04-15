"""
Pipeline — orchestrates all three agents in sequence.

Flow:
  1. ReconAgent   → codebase_map (dict)
  2. VulnerabilityAgent → analysis_results (dict)
  3. ReportAgent  → report_path (str)
"""

import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class SecurityScannerPipeline:
    """
    Orchestrates the three-agent security scanning pipeline.
    """

    def __init__(
        self,
        gemini_api_key: str,
        groq_api_key: str = "",
        output_dir: str = ".",
        save_intermediates: bool = True,
    ):
        """
        Args:
            gemini_api_key: Google Gemini API key.
            groq_api_key: Groq API key (used as fallback/round-robin).
            output_dir: Directory where reports and intermediate JSON are saved.
            save_intermediates: Whether to save intermediate JSON outputs per agent.
        """
        self.gemini_api_key = gemini_api_key
        self.groq_api_key = groq_api_key
        self.output_dir = output_dir
        self.save_intermediates = save_intermediates

        # Lazy imports to keep startup fast
        from agents.recon_agent import ReconAgent
        from agents.vulnerability_agent import VulnerabilityAgent
        from agents.report_agent import ReportAgent

        self.recon_agent = ReconAgent(gemini_api_key, groq_api_key)
        self.vulnerability_agent = VulnerabilityAgent(gemini_api_key, groq_api_key)
        self.report_agent = ReportAgent(gemini_api_key, groq_api_key)

        Path(output_dir).mkdir(parents=True, exist_ok=True)

    def run(
        self,
        repo_url: str,
        existing_repo_path: Optional[str] = None,
        cleanup_repo: bool = True,
    ) -> dict:
        """
        Run the full security scanning pipeline.

        Args:
            repo_url: GitHub repository URL to scan.
            existing_repo_path: Optional pre-cloned repo path (skips cloning).
            cleanup_repo: Whether to delete the cloned repo after scanning.

        Returns:
            A dict with keys: report_path, codebase_map, analysis_results.
        """
        start_time = datetime.utcnow()
        logger.info(f"[Pipeline] Starting security scan pipeline for: {repo_url}")
        logger.info(f"[Pipeline] Output directory: {self.output_dir}")

        try:
            # ----------------------------------------------------------------
            # Stage 1: Reconnaissance
            # ----------------------------------------------------------------
            logger.info("[Pipeline] === Stage 1: Reconnaissance ===")
            codebase_map = self.recon_agent.run(
                repo_url=repo_url,
                existing_repo_path=existing_repo_path,
            )

            if self.save_intermediates:
                self._save_json(codebase_map, "stage1_codebase_map.json")
                logger.info("[Pipeline] Saved stage1_codebase_map.json")

            repo_path = codebase_map["repo_path"]
            logger.info(
                f"[Pipeline] Stage 1 complete. "
                f"Languages: {codebase_map.get('languages', [])} | "
                f"Files: {codebase_map.get('total_files', 0)}"
            )

            # ----------------------------------------------------------------
            # Stage 2: Vulnerability Analysis
            # ----------------------------------------------------------------
            logger.info("[Pipeline] === Stage 2: Vulnerability Analysis ===")
            analysis_results = self.vulnerability_agent.run(codebase_map)

            if self.save_intermediates:
                self._save_json(analysis_results, "stage2_analysis_results.json")
                logger.info("[Pipeline] Saved stage2_analysis_results.json")

            total_findings = analysis_results.get("total_findings", 0)
            severity_breakdown = analysis_results.get("severity_breakdown", {})
            logger.info(
                f"[Pipeline] Stage 2 complete. "
                f"Total findings: {total_findings} | "
                f"Critical: {severity_breakdown.get('critical', 0)} | "
                f"High: {severity_breakdown.get('high', 0)}"
            )

            # ----------------------------------------------------------------
            # Stage 3: Report Generation
            # ----------------------------------------------------------------
            logger.info("[Pipeline] === Stage 3: Report Generation ===")
            report_path = self.report_agent.run(
                analysis_results=analysis_results,
                output_dir=self.output_dir,
            )

            elapsed = (datetime.utcnow() - start_time).total_seconds()
            logger.info(
                f"[Pipeline] Scan complete in {elapsed:.1f}s. "
                f"Report saved to: {report_path}"
            )

            return {
                "report_path": report_path,
                "codebase_map": codebase_map,
                "analysis_results": analysis_results,
                "elapsed_seconds": elapsed,
            }

        finally:
            # Clean up cloned repository if requested
            if cleanup_repo and not existing_repo_path:
                repo_path = codebase_map.get("repo_path") if "codebase_map" in dir() else None
                if repo_path and repo_path != existing_repo_path:
                    from tools.git_tools import cleanup_repository
                    logger.info(f"[Pipeline] Cleaning up cloned repo at {repo_path}")
                    cleanup_repository(repo_path)

    def _save_json(self, data: dict, filename: str) -> None:
        """Save a dict as JSON to the output directory."""
        path = Path(self.output_dir) / filename
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            logger.warning(f"Failed to save {filename}: {e}")
