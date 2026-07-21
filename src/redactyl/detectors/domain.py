import re

from redactyl.detectors.base import BaseDetector
from redactyl.models import Finding

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
}

# Standard public gTLDs, ccTLDs, and common internal domain TLDs
VALID_TLDS = {
    # Generic & popular TLDs
    "com", "org", "net", "edu", "gov", "mil", "int", "info", "biz", "name", "pro",
    "io", "co", "ai", "dev", "app", "me", "xyz", "online", "site", "tech", "store",
    "cloud", "global", "top", "vip", "work", "agency", "email", "group", "live",
    "space", "today", "world", "link", "guru", "life", "solutions", "services",
    "systems", "digital", "network", "company", "media", "software", "zone", "design",
    "expert", "studio", "center", "team", "one", "pub", "tv", "cc", "bz", "ws",
    "fm", "to", "is", "st", "la", "im", "gg", "je", "ca", "us", "uk", "de",
    "fr", "eu", "jp", "cn", "au", "nl", "se", "no", "fi", "ru", "br", "mx",
    "ch", "it", "es", "pl", "cz", "at", "be", "dk", "kr", "tw", "hk", "sg",
    "nz", "za", "tr", "il", "ar", "pe", "vn", "th", "id", "my", "ua", "ro",
    "gr", "hu", "pt", "ie", "sk", "bg", "hr", "lt", "lv", "ee", "si", "lu",
    # Additional generic TLDs
    "academy", "accountant", "accountants", "active", "actor", "adult", "africa",
    "apartments", "art", "associates", "attorney", "auction", "audio", "auto",
    "autos", "band", "bank", "bar", "bargains", "bayern", "beer", "berlin", "best",
    "bid", "bike", "bingo", "bio", "black", "blog", "blue", "boutique", "build",
    "builders", "business", "buzz", "cab", "cafe", "cam", "camera", "camp", "capital",
    "cards", "care", "careers", "cars", "casa", "cash", "casino", "catering",
    "charity", "chat", "cheap", "church", "city", "claims", "cleaning", "click",
    "clinic", "clothing", "club", "coach", "codes", "coffee", "community", "deals",
    "degree", "delivery", "democrat", "dental", "dentist", "diamonds", "direct",
    "directory", "discount", "doctor", "dog", "domains", "download", "earth",
    "education", "energy", "engineer", "engineering", "enterprises", "equipment",
    "estate", "events", "exchange", "experts", "exposure", "express", "fail", "farm",
    "fashion", "finance", "financial", "fish", "fitness", "flights", "florist",
    "flowers", "football", "foundation", "fund", "furniture", "fyi", "gallery",
    "game", "games", "garden", "gifts", "glass", "gold", "golf", "graphics", "gratis",
    "green", "gripe", "guide", "gmbh", "healthcare", "help", "here", "hiphop", "holdings",
    "holiday", "homes", "horse", "hospital", "host", "hosting", "house", "how",
    "industries", "ink", "institute", "insurance", "insure", "international",
    "investments", "jewelry", "jobs", "kitchen", "land", "lawyer", "lease", "legal",
    "lighting", "limited", "limo", "loans", "london", "ltd", "luxury", "management",
    "market", "marketing", "markets", "mba", "memorial", "men", "menu", "money",
    "mortgage", "movie", "news", "ninja", "organic", "partners", "parts", "party",
    "pay", "pet", "pharmacy", "photo", "photography", "photos", "physio", "pics",
    "pictures", "pink", "pizza", "place", "plumbing", "plus", "press", "productions",
    "properties", "property", "protection", "quotes", "racing", "recipes", "red",
    "rent", "rentals", "repair", "report", "republican", "rest", "restaurant",
    "review", "reviews", "rocks", "rodeo", "run", "sale", "salon", "sample", "school",
    "science", "security", "shoes", "shopping", "show", "singles", "soccer", "solar",
    "sport", "sports", "spot", "style", "supplies", "supply", "support", "surf",
    "surgery", "tax", "taxi", "technology", "tennis", "theater", "tickets", "tips",
    "tires", "tools", "tours", "town", "toys", "trade", "trading", "training",
    "travel", "university", "vacations", "vc", "ventures", "vet", "video", "villas",
    "vision", "vodka", "voting", "voyage", "watch", "watches", "weather", "web",
    "website", "wedding", "whoswho", "wiki", "win", "wine", "works", "wtc", "wtf",
    "yoga",
    # Common internal domain TLDs
    "internal", "corp", "local", "lan", "home", "private", "test", "example", "invalid", "localhost"
}

CODE_IMPORT_PREFIX_RE = re.compile(r"\b(import|package|from|using|#include|#import)\s+$")


class DomainDetector(BaseDetector):
    name = "domain"
    supported_types = ("DOMAIN", "INTERNAL_DOMAIN", "PUBLIC_DOMAIN")

    def __init__(self, internal_domains: list[str] | None = None):
        self.internal_domains = {d.lower() for d in (internal_domains or [])}

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []

        for match in DOMAIN_RE.finditer(text):
            val = match.group(0)
            start_pos = match.start()
            end_pos = match.end()

            # 1. Check surrounding context for code invocation or import statements
            # Check if immediately followed by parenthesis `(` (method call)
            after_text = text[end_pos:]
            if after_text.startswith("(") or re.match(r"^\s*\(", after_text):
                continue

            # Check preceding character (e.g. `.` or `_` or `$`)
            if start_pos > 0 and text[start_pos - 1] in "._$":
                continue

            # Check preceding line prefix for code import/package statements
            line_start = text.rfind("\n", 0, start_pos) + 1
            prefix_on_line = text[line_start:start_pos].strip()
            if CODE_IMPORT_PREFIX_RE.search(prefix_on_line):
                continue

            # 2. Check TLD validity and casing rules
            segments = val.split(".")
            tld = segments[-1]
            tld_lower = tld.lower()

            if tld_lower in EXCLUDED_SUFFIXES:
                continue

            # TLD must be a known valid TLD or configured internal domain
            is_valid_tld = (
                tld_lower in VALID_TLDS
                or tld_lower in self.internal_domains
                or val.lower() in self.internal_domains
            )
            if not is_valid_tld:
                continue

            # Reject TLD casing that signals code class names (PascalCase/camelCase) or uppercase constants
            # e.g., FileType, WORKSPACE, GetName when not matching a full domain override
            if tld != tld_lower and val.lower() not in self.internal_domains:
                # If TLD is mixed case (e.g., FileType) or UPPERCASE while prefix is lowercase/camelCase (e.g., env.WORKSPACE)
                if not tld.isupper() or not all(s.isupper() for s in segments):
                    continue

            # Determine whether domain is internal or public
            is_internal = (
                val.lower() in self.internal_domains
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