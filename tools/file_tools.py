"""File analysis tools for detecting languages, frameworks, and dependencies."""

from __future__ import annotations

import json
import re
import logging
from pathlib import Path
from typing import Optional

from scanner_types import DependencyInfo, EntryPoint, SensitiveArea

logger = logging.getLogger(__name__)


# Language detection by file extension
EXTENSION_TO_LANGUAGE = {
    ".py": "Python",
    ".java": "Java",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".jsx": "JavaScript",
    ".tsx": "TypeScript",
    ".rb": "Ruby",
    ".go": "Go",
    ".php": "PHP",
    ".cs": "C#",
    ".cpp": "C++",
    ".c": "C",
    ".rs": "Rust",
    ".kt": "Kotlin",
    ".scala": "Scala",
    ".swift": "Swift",
    ".sh": "Shell",
    ".bash": "Shell",
    ".html": "HTML",
    ".xml": "XML",
    ".yml": "YAML",
    ".yaml": "YAML",
    ".json": "JSON",
    ".sql": "SQL",
    ".pl": "Perl",
    ".r": "R",
}

# Framework detection patterns: (file_pattern, content_pattern, framework_name)
FRAMEWORK_PATTERNS = [
    # Python
    ("requirements.txt", r"django", "Django"),
    ("requirements.txt", r"flask", "Flask"),
    ("requirements.txt", r"fastapi", "FastAPI"),
    ("requirements.txt", r"tornado", "Tornado"),
    ("requirements.txt", r"pyramid", "Pyramid"),
    # JavaScript/Node
    ("package.json", r'"express"', "Express.js"),
    ("package.json", r'"react"', "React"),
    ("package.json", r'"vue"', "Vue.js"),
    ("package.json", r'"angular"', "Angular"),
    ("package.json", r'"next"', "Next.js"),
    ("package.json", r'"nestjs"', "NestJS"),
    ("package.json", r'"koa"', "Koa"),
    # Java
    ("pom.xml", r"spring-boot", "Spring Boot"),
    ("pom.xml", r"spring-framework", "Spring Framework"),
    ("pom.xml", r"struts", "Apache Struts"),
    ("build.gradle", r"spring-boot", "Spring Boot"),
    # Ruby
    ("Gemfile", r"rails", "Ruby on Rails"),
    ("Gemfile", r"sinatra", "Sinatra"),
    # PHP
    ("composer.json", r"laravel", "Laravel"),
    ("composer.json", r"symfony", "Symfony"),
]

# Sensitive area keywords mapped to area_type
SENSITIVE_PATTERNS = {
    "auth": [
        r"password", r"passwd", r"authentication", r"login", r"logout",
        r"session", r"token", r"jwt", r"oauth", r"credential", r"secret",
        r"api[_-]?key", r"auth[_-]?token", r"bearer",
    ],
    "database": [
        r"sql", r"query", r"execute", r"cursor", r"connection", r"jdbc",
        r"hibernate", r"orm", r"repository", r"dao", r"datasource",
        r"database", r"db\.", r"mysql", r"postgres", r"mongodb",
    ],
    "file_handling": [
        r"file\.read", r"file\.write", r"open\(", r"fopen", r"readfile",
        r"file_get_contents", r"upload", r"download", r"filepath",
        r"os\.path", r"pathlib", r"shutil", r"FileInputStream",
    ],
    "api_endpoint": [
        r"@app\.route", r"@router\.", r"@get\(", r"@post\(", r"@put\(",
        r"@delete\(", r"RequestMapping", r"GetMapping", r"PostMapping",
        r"app\.get\(", r"app\.post\(", r"router\.get\(", r"router\.post\(",
    ],
    "crypto": [
        r"encrypt", r"decrypt", r"hash", r"md5", r"sha1", r"aes",
        r"rsa", r"cipher", r"crypto", r"bcrypt", r"pbkdf2", r"hmac",
    ],
    "deserialization": [
        r"pickle\.loads", r"yaml\.load\b", r"json\.loads", r"deserializ",
        r"ObjectInputStream", r"readObject", r"fromJson", r"unmarshal",
    ],
    "command_execution": [
        r"os\.system", r"subprocess", r"exec\(", r"eval\(", r"shell=True",
        r"Runtime\.exec", r"ProcessBuilder", r"popen", r"system\(",
    ],
    "xml_processing": [
        r"xml\.etree", r"lxml", r"SAXParser", r"DocumentBuilder",
        r"XMLReader", r"parseXML", r"xpath",
    ],
}


def detect_languages(file_list: list[str]) -> list[str]:
    """Detect programming languages used in the repository."""
    lang_counts: dict[str, int] = {}

    for file_path in file_list:
        ext = Path(file_path).suffix.lower()
        if ext in EXTENSION_TO_LANGUAGE:
            lang = EXTENSION_TO_LANGUAGE[ext]
            lang_counts[lang] = lang_counts.get(lang, 0) + 1

    # Sort by frequency, filter out markup-only languages for primary list
    primary_langs = ["Python", "Java", "JavaScript", "TypeScript", "Ruby",
                     "Go", "PHP", "C#", "C++", "C", "Rust", "Kotlin", "Scala"]

    detected = sorted(lang_counts.keys(), key=lambda l: lang_counts[l], reverse=True)
    return detected


def detect_frameworks(repo_path: str, file_list: list[str]) -> list[str]:
    """Detect frameworks used in the repository."""
    frameworks = set()
    file_set = set(file_list)

    for file_pattern, content_pattern, framework_name in FRAMEWORK_PATTERNS:
        # Find matching files
        matching_files = [f for f in file_set if Path(f).name == file_pattern]
        for file_path in matching_files:
            full_path = Path(repo_path) / file_path
            try:
                content = full_path.read_text(encoding="utf-8", errors="replace")
                if re.search(content_pattern, content, re.IGNORECASE):
                    frameworks.add(framework_name)
            except Exception:
                pass

    return sorted(frameworks)


def parse_dependencies(repo_path: str, file_list: list[str]) -> list[DependencyInfo]:
    """Parse dependency files and extract package information."""
    dependencies = []
    file_set = set(file_list)

    for file_path in file_list:
        filename = Path(file_path).name

        if filename == "requirements.txt":
            deps = _parse_requirements_txt(repo_path, file_path)
            dependencies.extend(deps)
        elif filename == "package.json":
            deps = _parse_package_json(repo_path, file_path)
            dependencies.extend(deps)
        elif filename == "pom.xml":
            deps = _parse_pom_xml(repo_path, file_path)
            dependencies.extend(deps)
        elif filename == "build.gradle":
            deps = _parse_build_gradle(repo_path, file_path)
            dependencies.extend(deps)
        elif filename == "Gemfile":
            deps = _parse_gemfile(repo_path, file_path)
            dependencies.extend(deps)
        elif filename == "composer.json":
            deps = _parse_composer_json(repo_path, file_path)
            dependencies.extend(deps)

    return dependencies


def _parse_requirements_txt(repo_path: str, file_path: str) -> list[DependencyInfo]:
    """Parse Python requirements.txt."""
    deps = []
    full_path = Path(repo_path) / file_path
    try:
        content = full_path.read_text(encoding="utf-8", errors="replace")
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Parse name==version, name>=version, etc.
            match = re.match(r"^([a-zA-Z0-9_\-\.]+)([><=!~^]+.*)?$", line)
            if match:
                name = match.group(1)
                version = match.group(2).strip() if match.group(2) else None
                deps.append(DependencyInfo(name=name, version=version, source_file=file_path))
    except Exception as e:
        logger.debug(f"Error parsing {file_path}: {e}")
    return deps


def _parse_package_json(repo_path: str, file_path: str) -> list[DependencyInfo]:
    """Parse Node.js package.json."""
    deps = []
    full_path = Path(repo_path) / file_path
    try:
        content = full_path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(content)
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            for name, version in data.get(section, {}).items():
                deps.append(DependencyInfo(name=name, version=str(version), source_file=file_path))
    except Exception as e:
        logger.debug(f"Error parsing {file_path}: {e}")
    return deps


def _parse_pom_xml(repo_path: str, file_path: str) -> list[DependencyInfo]:
    """Parse Maven pom.xml."""
    deps = []
    full_path = Path(repo_path) / file_path
    try:
        content = full_path.read_text(encoding="utf-8", errors="replace")
        # Simple regex-based parsing to avoid XML namespace issues
        dep_blocks = re.findall(
            r"<dependency>(.*?)</dependency>", content, re.DOTALL
        )
        for block in dep_blocks:
            group_id = re.search(r"<groupId>(.*?)</groupId>", block)
            artifact_id = re.search(r"<artifactId>(.*?)</artifactId>", block)
            version = re.search(r"<version>(.*?)</version>", block)
            if artifact_id:
                name = f"{group_id.group(1)}:{artifact_id.group(1)}" if group_id else artifact_id.group(1)
                ver = version.group(1) if version else None
                deps.append(DependencyInfo(name=name, version=ver, source_file=file_path))
    except Exception as e:
        logger.debug(f"Error parsing {file_path}: {e}")
    return deps


def _parse_build_gradle(repo_path: str, file_path: str) -> list[DependencyInfo]:
    """Parse Gradle build.gradle."""
    deps = []
    full_path = Path(repo_path) / file_path
    try:
        content = full_path.read_text(encoding="utf-8", errors="replace")
        # Match: implementation 'group:name:version' or implementation "group:name:version"
        matches = re.findall(
            r'(?:implementation|compile|testImplementation|api)\s+[\'"]([^\'"]+)[\'"]',
            content,
        )
        for match in matches:
            parts = match.split(":")
            name = ":".join(parts[:2]) if len(parts) >= 2 else match
            version = parts[2] if len(parts) >= 3 else None
            deps.append(DependencyInfo(name=name, version=version, source_file=file_path))
    except Exception as e:
        logger.debug(f"Error parsing {file_path}: {e}")
    return deps


def _parse_gemfile(repo_path: str, file_path: str) -> list[DependencyInfo]:
    """Parse Ruby Gemfile."""
    deps = []
    full_path = Path(repo_path) / file_path
    try:
        content = full_path.read_text(encoding="utf-8", errors="replace")
        for line in content.splitlines():
            match = re.match(r"^\s*gem\s+['\"]([^'\"]+)['\"](?:,\s*['\"]([^'\"]+)['\"])?", line)
            if match:
                deps.append(DependencyInfo(
                    name=match.group(1),
                    version=match.group(2),
                    source_file=file_path,
                ))
    except Exception as e:
        logger.debug(f"Error parsing {file_path}: {e}")
    return deps


def _parse_composer_json(repo_path: str, file_path: str) -> list[DependencyInfo]:
    """Parse PHP composer.json."""
    deps = []
    full_path = Path(repo_path) / file_path
    try:
        content = full_path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(content)
        for section in ("require", "require-dev"):
            for name, version in data.get(section, {}).items():
                if name != "php":
                    deps.append(DependencyInfo(name=name, version=str(version), source_file=file_path))
    except Exception as e:
        logger.debug(f"Error parsing {file_path}: {e}")
    return deps


def find_sensitive_areas(
    repo_path: str,
    file_list: list[str],
    max_files: int = 500,
) -> list[SensitiveArea]:
    """
    Scan files for sensitive code patterns (auth, DB access, file handling, etc.).
    Returns a list of SensitiveArea objects.
    """
    sensitive_areas = []
    source_extensions = {".py", ".java", ".js", ".ts", ".jsx", ".tsx",
                         ".rb", ".go", ".php", ".cs", ".cpp", ".c", ".rs", ".kt", ".scala"}

    # Compile patterns
    compiled_patterns: dict[str, list[re.Pattern]] = {}
    for area_type, patterns in SENSITIVE_PATTERNS.items():
        compiled_patterns[area_type] = [
            re.compile(p, re.IGNORECASE) for p in patterns
        ]

    processed = 0
    for file_path in file_list:
        if processed >= max_files:
            break
        if Path(file_path).suffix.lower() not in source_extensions:
            continue

        content = _read_file_safe(repo_path, file_path)
        if not content:
            continue

        processed += 1
        lines = content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            for area_type, patterns in compiled_patterns.items():
                for pattern in patterns:
                    if pattern.search(line):
                        sensitive_areas.append(SensitiveArea(
                            file_path=file_path,
                            area_type=area_type,
                            line_number=line_num,
                            description=line.strip()[:200],
                        ))
                        break  # one match per area_type per line is enough

    return sensitive_areas


def find_entry_points(repo_path: str, file_list: list[str]) -> list[EntryPoint]:
    """Find likely entry points (main functions, route handlers, etc.)."""
    entry_points = []

    # Patterns for entry points in various languages
    entry_patterns = [
        (r"if\s+__name__\s*==\s*['\"]__main__['\"]", "Python main block"),
        (r"def\s+main\s*\(", "Python main function"),
        (r"public\s+static\s+void\s+main\s*\(", "Java main method"),
        (r"func\s+main\s*\(\s*\)", "Go main function"),
        (r"app\.listen\s*\(", "Node.js server listen"),
        (r"app\.run\s*\(", "Flask/Express app run"),
        (r"@SpringBootApplication", "Spring Boot application"),
        (r"uvicorn\.run\s*\(", "FastAPI/uvicorn server"),
        (r"def\s+index\s*\(", "Index route handler"),
    ]

    source_extensions = {".py", ".java", ".js", ".ts", ".go", ".rb", ".php", ".cs", ".kt"}

    for file_path in file_list[:300]:  # Limit to first 300 files
        if Path(file_path).suffix.lower() not in source_extensions:
            continue

        content = _read_file_safe(repo_path, file_path)
        if not content:
            continue

        lines = content.splitlines()
        for line_num, line in enumerate(lines, start=1):
            for pattern, description in entry_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    entry_points.append(EntryPoint(
                        file_path=file_path,
                        line_number=line_num,
                        description=description,
                        function_name=line.strip()[:100],
                    ))

    return entry_points


def _read_file_safe(repo_path: str, file_path: str, max_bytes: int = 200_000) -> Optional[str]:
    """Safely read a file, returning None on error."""
    try:
        full_path = Path(repo_path) / file_path
        with open(full_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(max_bytes)
    except Exception:
        return None


def get_file_snippets(
    repo_path: str,
    file_path: str,
    line_number: int,
    context_lines: int = 5,
) -> str:
    """Extract a code snippet around a specific line number."""
    content = _read_file_safe(repo_path, file_path)
    if not content:
        return ""

    lines = content.splitlines()
    start = max(0, line_number - context_lines - 1)
    end = min(len(lines), line_number + context_lines)
    snippet_lines = []
    for i, line in enumerate(lines[start:end], start=start + 1):
        marker = ">>>" if i == line_number else "   "
        snippet_lines.append(f"{marker} {i:4d} | {line}")
    return "\n".join(snippet_lines)
