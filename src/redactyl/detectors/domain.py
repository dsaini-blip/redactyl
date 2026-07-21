import re

from redactyl.detectors.base import BaseDetector
from redactyl.models import Finding

# Strict DNS domain regex: Labels contain alphanumeric characters and hyphens only (NO UNDERSCORES)
DOMAIN_RE = re.compile(
    r"\b(?=.{1,253}\b)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}\b"
)

EXCLUDED_SUFFIXES = {
    "txt",
    "log",
    "json",
    "yaml",
    "yml",
    "env",
    "py",
    "md",
    "csv",
    "js",
    "ts",
    "html",
    "css",
    "java",
    "cpp",
    "c",
    "h",
    "go",
    "rs",
    "rb",
    "php",
    "sh",
    "bat",
    "ps1",
    "xml",
    "sql",
    "out",
    "result",
    "workspace",
    "class",
    "properties",
    "conf",
    "cfg",
    "bak",
    "tmp",
    "temp",
    "dat",
    "bin",
    "exe",
    "dll",
    "so",
    "dylib",
    "jar",
    "war",
    "ear",
    "add",
    "sort",
    "size",
    "getname",
    "filetype",
    "simpledateformat",
    "string",
    "object",
    "list",
    "map",
    "set",
    "get",
    "put",
    "push",
    "pop",
    "count",
    "length",
    "item",
    "node",
    "val",
    "value",
    "key",
    "name",
    "path",
    "url",
    "uri",
    "id",
    "type",
    "info",
    "debug",
    "error",
    "warn",
    "warning",
    "fatal",
    "trace",
    "print",
}

# Standard realistic public & internal domain TLDs
VALID_TLDS = {
    # Generic & popular gTLDs
    "com", "org", "net", "edu", "gov", "mil", "int", "io", "co", "ai", "dev", "app",
    "xyz", "info", "biz", "online", "site", "tech", "store", "cloud", "global", "me",
    "tv", "cc", "top", "vip", "link", "space", "live", "agency", "email", "group",
    "systems", "solutions", "digital", "network", "company", "media", "software",
    "zone", "design", "studio", "center", "team", "one", "pub", "pro", "shop", "club",
    "blog", "world", "bar",
    # Country code TLDs (ccTLDs)
    "us", "uk", "ca", "de", "fr", "eu", "jp", "cn", "au", "nl", "se", "no", "fi",
    "ru", "br", "mx", "ch", "it", "es", "pl", "cz", "at", "be", "dk", "kr", "tw",
    "hk", "sg", "nz", "za", "tr", "il", "ar", "cl", "pe", "vn", "th", "id", "my",
    "ua", "ro", "gr", "hu", "pt", "ie", "sk", "bg", "hr", "lt", "lv", "ee", "si", "lu",
    # Common internal domain TLDs
    "internal", "corp", "local", "lan", "home", "private", "test", "example", "invalid", "localhost"
}

CODE_IMPORT_PREFIX_RE = re.compile(
    r"\b(import|package|from|using|#include|#import)\b", re.IGNORECASE
)

CODE_ROOT_PACKAGES = (
    "java.",
    "javax.",
    "groovy.",
    "kotlin.",
    "scala.",
    "android.",
    "sun.",
    "com.sun.",
    "org.apache.",
    "org.springframework.",
)


def _is_mixed_case(s: str) -> bool:
    """Returns True if string contains camelCase or PascalCase letters."""
    has_upper = any(c.isupper() for c in s)
    has_lower = any(c.islower() for c in s)
    return has_upper and has_lower


class DomainDetector(BaseDetector):
    name = "domain"
    supported_types = ("DOMAIN", "INTERNAL_DOMAIN", "PUBLIC_DOMAIN")

    def __init__(self, internal_domains: list[str] | None = None):
        self.internal_domains = {d.lower() for d in (internal_domains or [])}

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []

        for match in DOMAIN_RE.finditer(text):
            val = match.group(0)
            val_lower = val.lower()
            start_pos = match.start()
            end_pos = match.end()

            # 1. DNS Specification: Hostnames cannot contain underscores `_`
            if "_" in val:
                continue

            # 2. Check surrounding character context (file paths, property chains, method calls, variables)
            if start_pos > 0 and text[start_pos - 1] in "._$\\":
                continue

            after_text = text[end_pos:]
            if after_text.startswith(("(", "=", "[", "{", ";")):
                continue

            # 3. Check line context for programming language import/package statements
            line_start = text.rfind("\n", 0, start_pos) + 1
            prefix_on_line = text[line_start:start_pos]
            if CODE_IMPORT_PREFIX_RE.search(prefix_on_line):
                continue

            # Check for standard code root package prefixes (e.g. java.text..., groovy.io...)
            if any(val_lower.startswith(pkg) for pkg in CODE_ROOT_PACKAGES):
                if val_lower not in self.internal_domains:
                    continue

            # 4. Check TLD validity and casing rules
            segments = val.split(".")
            tld = segments[-1]
            tld_lower = tld.lower()

            if tld_lower in EXCLUDED_SUFFIXES:
                continue

            # TLD must be a known valid TLD or configured internal domain
            is_valid_tld = (
                tld_lower in VALID_TLDS
                or tld_lower in self.internal_domains
                or val_lower in self.internal_domains
            )
            if not is_valid_tld:
                continue

            # 5. Reject code identifiers with camelCase / PascalCase segments or uppercase env variables
            if val_lower not in self.internal_domains:
                if any(_is_mixed_case(seg) for seg in segments):
                    continue
                # If TLD is uppercase while prefix is not all uppercase (e.g., env.WORKSPACE)
                if tld.isupper() and not all(seg.isupper() for seg in segments):
                    continue

            # Determine whether domain is internal or public
            is_internal = (
                val_lower in self.internal_domains
                or tld_lower in self.internal_domains
                or tld_lower in {"internal", "corp", "local", "lan", "home", "private"}
            )
            finding_type = "INTERNAL_DOMAIN" if is_internal else "PUBLIC_DOMAIN"

            findings.append(
                Finding(
                    type=finding_type,
                    start=start_pos,
                    end=end_pos,
                    value=val,
                    detector=self.name,
                    confidence=0.95,
                )
            )

        return findings