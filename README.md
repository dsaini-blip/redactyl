# Redactyl 🛡️

Redactyl is a powerful Python library and Command-Line Interface (CLI) tool designed for detecting and redacting sensitive information within text strings, JSON payloads, files, and entire directories.

It uses a modular, confidence-based detection engine capable of identifying API keys, PII (Personally Identifiable Information), AWS credentials, domains, IP addresses, and more.

## ✨ Features

- **Extensive Detection Capabilities**: Comes with 18+ built-in detectors including:
  - Credentials (API Keys, AWS Keys, Passwords, JWTs, Bearer Tokens)
  - PII (Emails, Phone Numbers, SSNs, Credit Cards)
  - Infrastructure (IP Addresses, Domains, DB Connection Strings)
- **High Accuracy**: Uses strict patterns and validation (like Luhn algorithms for credit cards) to minimize false positives.
- **Smart Redaction**: Handles overlapping findings gracefully and replaces sensitive data with `[REDACTED]`.
- **JSON Reports**: Generates detailed `findings.json` reports alongside redactions.
- **Flexible Configuration**: Uses a YAML config file to enable/disable specific detectors or define internal company assets (e.g., internal domains or business units).

---

## 📦 Installation

To install Redactyl locally, clone the repository and install it using `pip`.

```bash
git clone https://github.com/yourusername/redactyl.git
cd redactyl
pip install -e .
```

---

## 💻 Command-Line Interface (CLI)

Redactyl provides an intuitive CLI built with Typer. You can use it to scan individual files or entire directories.

### Basic Usage

**Detect Only (File)**
Scan a file and generate a JSON report of the findings without modifying the original text.
```bash
redactyl path/to/file.txt --detect-only
```
*Outputs: `path/to/file.findings.json`*

**Redact (File or JSON)**
Scan a text or `.json` file, replace sensitive data with `[REDACTED]`, and generate a report. If a `.json` file is passed, Redactyl will natively parse and safely sanitize the JSON without breaking its structure.
```bash
redactyl path/to/file.json --redact
```
*Outputs:* 
* `path/to/file.redacted.json` (Valid JSON with redacted strings)
* `path/to/file.findings.json` (Report with JSON paths)

**Redact an Entire Directory**
Scan all text files inside a directory. 
```bash
redactyl path/to/logs_directory/ --redact
```

**Output to a Specific Location**
Use the `--out` flag to place the redacted files and reports into a separate folder, maintaining the original directory structure.
```bash
redactyl path/to/input_dir/ --redact --out path/to/output_dir/
```

**Use a Configuration File**
Pass a custom YAML configuration.
```bash
redactyl path/to/file.txt --redact --config ./my_config.yml
```

---

## 🐍 Python API
Redactyl is designed to be easily integrated into any Python application, web server, or data pipeline.

### 🌟 The Universal `redact()` Function
You don't have to memorize a bunch of different functions! The `redact()` function is a smart dispatcher that accepts **anything** (strings, dicts, lists, file paths, or directory paths) and automatically routes it to the correct processor.

```python
from redactyl.api import redact

# 1. Pass a raw string
redacted_text, findings = redact("My email is admin@foo.bar")

# 2. Pass a JSON payload (dict/list)
sanitized_json, findings = redact({"email": "admin@foo.bar"})

# 3. Pass a file path
# This writes to "logs.redacted.json" automatically!
redacted_file, report_file, findings = redact("./logs.json")

# 4. Pass a directory path
processed_files, all_findings = redact("./raw_data/", output_dir="./clean_data/")
```

### Advanced Usage (Specific Functions)
If you prefer explicit functions, you can still use them:

#### 1. Scanning Text
Detect sensitive information and get a structured list of findings.

```python
from redactyl.api import scan_text

text = "Please contact me at admin@internal.corp.com or use API Key: sk_live_1234567890abcdef12345678"
findings = scan_text(text)

for finding in findings:
    print(f"[{finding.type}] Found '{finding.value}' (Confidence: {finding.confidence})")
```

### 2. Redacting Text
Redact text directly in memory. You can optionally pass a custom `replacement` string.

```python
from redactyl.api import redact_text

text = "User IP is 192.168.1.50."
redacted_text, findings = redact_text(text, replacement="***")

print(redacted_text)
# Output: User IP is ***.
```

### 3. Sanitizing JSON/Dictionaries
Useful for sanitizing incoming payloads, webhooks, or outgoing API responses. The `sanitize_json_payload` function deeply traverses lists and dictionaries, redacting any string values without breaking the overall structure. It also attaches the exact JSON path (e.g. `users[0].email`) to each finding's metadata!

```python
from redactyl.api import sanitize_json_payload

payload = {
    "users": [
        {"id": 123, "email": "admin@foo.bar"},
        {"id": 124, "email": "test@internal.corp"}
    ],
    "is_active": True
}

# Automatically traverses and sanitizes nested dictionaries and lists
sanitized, findings = sanitize_json_payload(payload)

print(sanitized["users"][0]["email"])
# Output: [REDACTED]

print(findings[0].metadata["json_path"])
# Output: users[0].email
```

### 4. Redacting Files and Directories Programmatically
You can also invoke the file and directory redaction logic directly from Python. If you pass a `.json` file, it will natively sanitize it.

**Redact a single file**
```python
from redactyl.api import redact_file_with_report

# This will generate "data.redacted.json" and "data.findings.json"
redacted_file, report_file, findings = redact_file_with_report("data.json")

print(f"Redacted file saved to: {redacted_file}")
print(f"Found {len(findings)} sensitive items.")
```

**Redact an entire directory**
```python
from redactyl.api import redact_directory_with_report

processed_files, all_findings = redact_directory_with_report(
    input_dir="./raw_logs",
    output_dir="./clean_logs"
)

print(f"Cleaned {len(processed_files)} files and found {len(all_findings)} sensitive items.")
```

---

## ⚙️ Configuration

Redactyl can be configured using a YAML file (default: `redactyl.yml` or `.redactyl.yml`). This is extremely useful for defining custom business logic, such as ensuring your company's domains are tagged as `INTERNAL_DOMAIN` rather than generic public domains.

**Example `redactyl.yml`**
```yaml
# Define internal domains. These will be classified as INTERNAL_DOMAIN instead of PUBLIC_DOMAIN.
internal_domains:
  - "internal.corp.com"
  - "staging.myapp.net"

# Specific business units you might want to detect/redact
business_units:
  - "HR"
  - "Finance"
  - "Engineering"

# Any custom strings, names, or secret words you want strictly redacted
custom_keywords:
  - "Project Pegasus"
  - "Dakshil Saini"
  - "SuperSecretPassword123!"

# Disable specific detectors if they are causing false positives
disabled_detectors:
  - "phone"

# Allowed file extensions when scanning directories
include_extensions: 
  - ".txt"
  - ".log"
  - ".env"
  - ".json"
  - ".md"

# Directories to skip when recursively scanning
exclude_dirs: 
  - ".git"
  - ".venv"
  - "node_modules"
  - "__pycache__"
```
