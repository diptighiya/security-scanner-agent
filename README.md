# Multi-Agent Security Vulnerability Scanner

A three-agent pipeline that autonomously scans GitHub repositories for security vulnerabilities and generates structured remediation reports.

## How It Works

The scanner uses three autonomous agents working in sequence:

**Agent 1 — Recon Agent**
Clones the target repository and maps the codebase: languages, frameworks, dependencies, entry points, and sensitive areas like authentication, database access, and API endpoints.

**Agent 2 — Vulnerability Analysis Agent**
Takes the codebase map, runs Semgrep static analysis, and uses LangChain tool calling with an LLM to reason about vulnerabilities beyond what pattern matching alone can catch. The LLM decides which tools to invoke and in what order, detecting attack chains where two lower-severity issues combine into a critical exploit.

**Agent 3 — Report Agent**
Takes the findings and generates a structured markdown report with an executive summary, severity breakdown, vulnerable code snippets, fixed code examples, attack scenarios, and recommended next steps.

## Architecture

```
GitHub URL
    │
    ▼
┌─────────────────┐
│   Recon Agent   │  ── maps codebase structure
└────────┬────────┘
         │ CodebaseMap (JSON)
         ▼
┌──────────────────────────┐
│  Vulnerability Agent     │  ── Semgrep + LangChain tool calling
│  (LangChain + Semgrep)   │  ── LLM reasons about attack chains
└────────┬─────────────────┘
         │ Findings (JSON)
         ▼
┌─────────────────┐
│  Report Agent   │  ── generates markdown report
└─────────────────┘
         │
         ▼
security-report-[timestamp].md
```

## Dual LLM Client

To avoid rate limiting during development, the scanner uses a dual LLM client that round-robins between Google Gemini and Groq APIs. If one provider returns a 429 rate limit error, it automatically switches to the other. If both are rate limited, it waits and retries.

## Sample Output

Running the scanner against [OWASP WebGoat](https://github.com/WebGoat/WebGoat) (a deliberately vulnerable Java application):

- **Overall Risk Score:** 10.0/10 CRITICAL
- **Total Findings:** 46
- **High Severity:** 14
- **Medium Severity:** 32

Findings include SQL injection vulnerabilities, path traversal, insecure deserialization, weak random number generation, missing cookie flags, and exposed Spring Boot actuator endpoints.

See [sample-report.md](reports/security-report-20260415_064247.md) for the full output.

## Installation

```bash
# Clone the repo
git clone https://github.com/diptighiya/security-scanner-agent
cd security-scanner-agent

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Configuration

Create a `.env` file in the root directory:

```
GEMINI_API_KEY=your_gemini_api_key
GROQ_API_KEY=your_groq_api_key
```

Get a free Gemini API key at [aistudio.google.com](https://aistudio.google.com)
Get a free Groq API key at [console.groq.com](https://console.groq.com)

## Usage

```bash
python main.py <github-repo-url>
```

Example:

```bash
python main.py https://github.com/WebGoat/WebGoat
```

The report is saved to the `reports/` directory as `security-report-[timestamp].md`.

## Tech Stack

- **Python** — agent orchestration and pipeline
- **LangChain** — tool calling agent for the vulnerability analysis step
- **Semgrep** — static analysis engine
- **Google Gemini API** — LLM provider (primary)
- **Groq API** — LLM provider (fallback)
- **GitPython** — repository cloning

## Project Structure

```
security-scanner-agent/
├── agents/
│   ├── recon_agent.py          # maps codebase structure
│   ├── vulnerability_agent.py  # LangChain + Semgrep analysis
│   └── report_agent.py         # generates markdown report
├── tools/
│   ├── llm_client.py           # dual LLM client with fallback
│   ├── git_tools.py            # repo cloning utilities
│   ├── semgrep_tools.py        # Semgrep integration
│   └── file_tools.py           # file reading and parsing
├── reports/                    # generated scan reports
├── pipeline.py                 # orchestrates all three agents
├── main.py                     # CLI entry point
├── scanner_types.py            # shared dataclasses
└── requirements.txt
```

## Limitations

- Semgrep rules cover common vulnerability patterns but cannot catch all application-specific logic flaws
- LLM-powered analysis may occasionally produce false positives
- Large repositories may take several minutes to scan due to API rate limits
- Currently supports public GitHub repositories only
