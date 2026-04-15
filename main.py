"""
Main entry point for the Multi-Agent Security Vulnerability Scanner.

Usage:
    python main.py <github-repo-url> [options]

Examples:
    python main.py https://github.com/WebGoat/WebGoat
    python main.py https://github.com/django/django --output-dir ./reports
    python main.py https://github.com/juice-shop/juice-shop --no-cleanup
"""

import argparse
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

# Load .env file before anything else
load_dotenv()

# Configure logging
def _setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.StreamHandler(sys.stdout),
        ],
    )
    # Quiet down noisy third-party loggers
    logging.getLogger("git").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("google").setLevel(logging.WARNING)


def main():
    parser = argparse.ArgumentParser(
        description="Multi-Agent Security Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py https://github.com/WebGoat/WebGoat
  python main.py https://github.com/django/django --output-dir ./reports
  python main.py https://github.com/juice-shop/juice-shop --no-cleanup --verbose
  python main.py https://github.com/OWASP/NodeGoat --repo-path /tmp/existing_clone
        """,
    )

    parser.add_argument(
        "repo_url",
        help="GitHub repository URL to scan (e.g. https://github.com/owner/repo)",
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Directory to save reports and intermediate JSON (default: current directory)",
    )
    parser.add_argument(
        "--repo-path",
        default=None,
        help="Path to an already-cloned repository (skips git clone)",
    )
    parser.add_argument(
        "--no-cleanup",
        action="store_true",
        default=False,
        help="Do not delete the cloned repository after scanning",
    )
    parser.add_argument(
        "--no-intermediates",
        action="store_true",
        default=False,
        help="Do not save intermediate JSON files (stage1_codebase_map.json, etc.)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="Enable debug-level logging",
    )

    args = parser.parse_args()
    _setup_logging(verbose=args.verbose)
    logger = logging.getLogger(__name__)

    # Validate GitHub URL
    if not (args.repo_url.startswith("https://") or args.repo_url.startswith("git@")):
        logger.error("Invalid repository URL. Must start with https:// or git@")
        sys.exit(1)

    # Get API keys
    gemini_api_key = os.getenv("GEMINI_API_KEY")
    if not gemini_api_key:
        logger.error(
            "GEMINI_API_KEY not found. Set it in your .env file or as an environment variable."
        )
        sys.exit(1)

    groq_api_key = os.getenv("GROQ_API_KEY", "")

    # Ensure output directory exists
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 60)
    logger.info("  Multi-Agent Security Vulnerability Scanner")
    logger.info("=" * 60)
    logger.info(f"  Target:     {args.repo_url}")
    logger.info(f"  Output:     {output_dir.resolve()}")
    logger.info(f"  Cleanup:    {not args.no_cleanup}")
    logger.info("=" * 60)

    # Import and run pipeline
    from pipeline import SecurityScannerPipeline

    pipeline = SecurityScannerPipeline(
        gemini_api_key=gemini_api_key,
        groq_api_key=groq_api_key,
        output_dir=str(output_dir),
        save_intermediates=not args.no_intermediates,
    )

    try:
        result = pipeline.run(
            repo_url=args.repo_url,
            existing_repo_path=args.repo_path,
            cleanup_repo=not args.no_cleanup,
        )

        report_path = result["report_path"]
        analysis = result["analysis_results"]
        severity = analysis.get("severity_breakdown", {})

        print()
        print("=" * 60)
        print("  SCAN COMPLETE")
        print("=" * 60)
        print(f"  Report:       {report_path}")
        print(f"  Total findings: {analysis.get('total_findings', 0)}")
        print(f"  Critical:     {severity.get('critical', 0)}")
        print(f"  High:         {severity.get('high', 0)}")
        print(f"  Medium:       {severity.get('medium', 0)}")
        print(f"  Low:          {severity.get('low', 0)}")
        print(f"  Elapsed:      {result.get('elapsed_seconds', 0):.1f}s")
        print("=" * 60)
        print()
        print(f"Open the report:  cat '{report_path}'")
        print()

    except KeyboardInterrupt:
        logger.info("Scan interrupted by user.")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=args.verbose)
        sys.exit(1)


if __name__ == "__main__":
    main()
