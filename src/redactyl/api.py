import copy
import json
from pathlib import Path

from redactyl.config import load_config
from redactyl.engine.registry import build_detectors
from redactyl.io_utils import iter_text_files


def _sort_findings(findings):
    return sorted(findings, key=lambda f: (f.start, f.end))


def _redact_with_findings(text, findings, replacement="[REDACTED]"):
    if not findings:
        return text
        
    # Merge overlapping ranges
    sorted_findings = sorted(findings, key=lambda f: f.start)
    merged_ranges = []
    
    current_start = sorted_findings[0].start
    current_end = sorted_findings[0].end
    
    for finding in sorted_findings[1:]:
        if finding.start <= current_end:
            current_end = max(current_end, finding.end)
        else:
            merged_ranges.append((current_start, current_end))
            current_start = finding.start
            current_end = finding.end
            
    merged_ranges.append((current_start, current_end))
    
    redacted = text
    for start, end in reversed(merged_ranges):
        redacted = redacted[:start] + replacement + redacted[end:]
        
    return redacted


def _finding_to_dict(finding):
    d = {
        "type": getattr(finding, "type", None),
        "start": getattr(finding, "start", None),
        "end": getattr(finding, "end", None),
        "value": getattr(finding, "value", None),
        "detector": getattr(finding, "detector", None),
        "confidence": getattr(finding, "confidence", None),
    }
    if hasattr(finding, "metadata") and finding.metadata and "json_path" in finding.metadata:
        d["json_path"] = finding.metadata["json_path"]
    elif getattr(finding, "json_path", None) is not None:
        d["json_path"] = finding.json_path
    return d


def _default_output_paths(input_file: Path):
    suffix = input_file.suffix or ".txt"
    redacted_file = input_file.with_name(f"{input_file.stem}.redacted{suffix}")
    json_file = input_file.with_name(f"{input_file.stem}.findings.json")
    return redacted_file, json_file


def scan_text(text: str, config_path: str | None = None):
    config = load_config(config_path)
    detectors = build_detectors(config)
    findings = []

    for detector in detectors:
        findings.extend(detector.detect(text))

    return _sort_findings(findings)


def redact_text(
    text: str,
    config_path: str | None = None,
    replacement: str = "[REDACTED]",
):
    findings = scan_text(text, config_path=config_path)
    redacted = _redact_with_findings(text, findings, replacement=replacement)
    return redacted, findings


def sanitize_text(
    text: str,
    config_path: str | None = None,
    replacement: str = "[REDACTED]",
):
    sanitized_text, findings = redact_text(
        text,
        config_path=config_path,
        replacement=replacement,
    )
    return sanitized_text, findings


def sanitize_message(
    message: dict,
    config_path: str | None = None,
    replacement: str = "[REDACTED]",
    content_key: str = "content",
):
    sanitized_message = copy.deepcopy(message)
    content = sanitized_message.get(content_key)

    if not isinstance(content, str):
        return sanitized_message, []

    sanitized_content, findings = sanitize_text(
        content,
        config_path=config_path,
        replacement=replacement,
    )
    sanitized_message[content_key] = sanitized_content
    return sanitized_message, findings


def sanitize_json_payload(
    payload,
    config_path: str | None = None,
    replacement: str = "[REDACTED]",
    _path_prefix: str = "",
):
    sanitized = copy.deepcopy(payload)
    all_findings = []

    def _traverse(obj, current_path):
        if isinstance(obj, dict):
            for k, v in obj.items():
                new_path = f"{current_path}.{k}" if current_path else k
                if isinstance(v, str):
                    redacted_str, findings = sanitize_text(v, config_path, replacement)
                    for f in findings:
                        f.metadata["json_path"] = new_path
                        all_findings.append(f)
                    obj[k] = redacted_str
                elif isinstance(v, (dict, list)):
                    _traverse(v, new_path)
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                new_path = f"{current_path}[{idx}]"
                if isinstance(item, str):
                    redacted_str, findings = sanitize_text(item, config_path, replacement)
                    for f in findings:
                        f.metadata["json_path"] = new_path
                        all_findings.append(f)
                    obj[idx] = redacted_str
                elif isinstance(item, (dict, list)):
                    _traverse(item, new_path)

    _traverse(sanitized, _path_prefix)
    return sanitized, all_findings


def sanitize_messages(
    messages: list[dict],
    config_path: str | None = None,
    replacement: str = "[REDACTED]",
    content_key: str = "content",
):
    sanitized_messages = []
    all_findings = []

    for index, message in enumerate(messages):
        sanitized_message, findings = sanitize_message(
            message,
            config_path=config_path,
            replacement=replacement,
            content_key=content_key,
        )

        for finding in findings:
            finding_dict = _finding_to_dict(finding)
            finding_dict["message_index"] = index
            all_findings.append(finding_dict)

        sanitized_messages.append(sanitized_message)

    return sanitized_messages, all_findings


def prepare_safe_prompt_payload(
    text: str,
    config_path: str | None = None,
    replacement: str = "[REDACTED]",
):
    sanitized_text, findings = sanitize_text(
        text,
        config_path=config_path,
        replacement=replacement,
    )

    findings_payload = [_finding_to_dict(f) for f in findings]

    return {
        "sanitized_text": sanitized_text,
        "had_sensitive_data": len(findings_payload) > 0,
        "total_findings": len(findings_payload),
        "findings": findings_payload,
    }


def _categorize_findings(findings_dicts: list[dict]) -> dict[str, list[dict]]:
    categories: dict[str, list[dict]] = {}
    for f in findings_dicts:
        ftype = f.get("type", "UNKNOWN")
        categories.setdefault(ftype, []).append(f)
    return categories


def write_findings_json(findings, source_file: str, json_output_path: str):
    output_path = Path(json_output_path)
    file_obj = Path(source_file)
    findings_dicts = [_finding_to_dict(f) for f in findings]
    categories = _categorize_findings(findings_dicts)

    payload = {
        "file_name": file_obj.name,
        "file_path": str(file_obj.resolve()),
        "source_file": str(file_obj),
        "total_findings": len(findings),
        "categories": categories,
        "findings": findings_dicts,
    }
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return output_path


def redact_file(
    input_path: str,
    output_path: str | None = None,
    config_path: str | None = None,
    replacement: str = "[REDACTED]",
):
    input_file = Path(input_path)
    
    if input_file.suffix.lower() == ".json":
        try:
            payload = json.loads(input_file.read_text(encoding="utf-8"))
            sanitized_payload, findings = sanitize_json_payload(
                payload, config_path=config_path, replacement=replacement
            )
            redacted_text = json.dumps(sanitized_payload, indent=2)
        except json.JSONDecodeError:
            # Fallback to plain text if JSON is invalid
            text = input_file.read_text(encoding="utf-8", errors="ignore")
            redacted_text, findings = redact_text(
                text, config_path=config_path, replacement=replacement
            )
    else:
        text = input_file.read_text(encoding="utf-8", errors="ignore")
        redacted_text, findings = redact_text(
            text, config_path=config_path, replacement=replacement
        )

    if output_path is None:
        redacted_file, _ = _default_output_paths(input_file)
    else:
        redacted_file = Path(output_path)

    redacted_file.write_text(redacted_text, encoding="utf-8")
    return redacted_file, findings


def redact_file_with_report(
    input_path: str,
    output_path: str | None = None,
    json_output_path: str | None = None,
    config_path: str | None = None,
    replacement: str = "[REDACTED]",
):
    input_file = Path(input_path)
    redacted_file_default, json_file_default = _default_output_paths(input_file)

    redacted_file = Path(output_path) if output_path else redacted_file_default
    json_file = Path(json_output_path) if json_output_path else json_file_default

    written_redacted_file, findings = redact_file(
        input_path=input_path,
        output_path=str(redacted_file),
        config_path=config_path,
        replacement=replacement,
    )

    written_json_file = write_findings_json(
        findings=findings,
        source_file=str(input_file),
        json_output_path=str(json_file),
    )

    return written_redacted_file, written_json_file, findings


def detect_directory_with_report(
    input_dir: str,
    output_dir: str | None = None,
    json_output_path: str | None = None,
    config_path: str | None = None,
):
    input_path = Path(input_dir)
    config = load_config(config_path)

    include_extensions = config.get("include_extensions")
    exclude_dirs = config.get("exclude_dirs", [".git", ".venv", "node_modules", "__pycache__"])

    all_findings = []
    processed_files = []

    out_dir_path = Path(output_dir) if output_dir else None
    if out_dir_path:
        out_dir_path.mkdir(parents=True, exist_ok=True)

    for file_path in iter_text_files(input_path, include_extensions, exclude_dirs):
        # Scan file for findings
        if file_path.suffix.lower() == ".json":
            try:
                payload = json.loads(file_path.read_text(encoding="utf-8"))
                _, findings = sanitize_json_payload(payload, config_path=config_path)
            except Exception:
                text = file_path.read_text(encoding="utf-8", errors="ignore")
                findings = scan_text(text, config_path=config_path)
        else:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
            findings = scan_text(text, config_path=config_path)

        json_file_path = None
        if out_dir_path:
            rel_path = file_path.relative_to(input_path)
            out_file_path = out_dir_path / rel_path
            out_file_path.parent.mkdir(parents=True, exist_ok=True)
            json_file_path = out_file_path.with_name(f"{out_file_path.stem}.findings.json")

            write_findings_json(
                findings=findings,
                source_file=str(file_path),
                json_output_path=str(json_file_path),
            )

        findings_dicts = [_finding_to_dict(f) for f in findings]
        categories = _categorize_findings(findings_dicts)
        all_findings.extend(findings)
        processed_files.append({
            "file_name": file_path.name,
            "file_path": str(file_path.resolve()),
            "original": str(file_path),
            "report": str(json_file_path) if json_file_path else None,
            "findings_count": len(findings),
            "categories": categories,
            "findings": findings_dicts,
        })

    if json_output_path:
        json_path = Path(json_output_path)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        aggregate_payload = {
            "source_directory": str(input_path.resolve()),
            "total_files_scanned": len(processed_files),
            "total_findings": len(all_findings),
            "files": processed_files,
        }
        json_path.write_text(json.dumps(aggregate_payload, indent=2), encoding="utf-8")

    return processed_files, all_findings


def redact_directory_with_report(
    input_dir: str,
    output_dir: str | None = None,
    json_output_path: str | None = None,
    config_path: str | None = None,
    replacement: str = "[REDACTED]",
    detect_only: bool = False,
):
    if detect_only:
        return detect_directory_with_report(
            input_dir=input_dir,
            output_dir=output_dir,
            json_output_path=json_output_path,
            config_path=config_path,
        )

    input_path = Path(input_dir)
    config = load_config(config_path)

    include_extensions = config.get("include_extensions")
    exclude_dirs = config.get("exclude_dirs", [".git", ".venv", "node_modules", "__pycache__"])

    all_findings = []
    processed_files = []

    out_dir_path = Path(output_dir) if output_dir else None
    if out_dir_path:
        out_dir_path.mkdir(parents=True, exist_ok=True)

    for file_path in iter_text_files(input_path, include_extensions, exclude_dirs):
        if out_dir_path:
            rel_path = file_path.relative_to(input_path)
            out_file_path = out_dir_path / rel_path
            out_file_path.parent.mkdir(parents=True, exist_ok=True)
            
            suffix = out_file_path.suffix or ".txt"
            redacted_file_path = out_file_path.with_name(f"{out_file_path.stem}.redacted{suffix}")
            json_file_path = out_file_path.with_name(f"{out_file_path.stem}.findings.json")
        else:
            redacted_file_path = None
            json_file_path = None

        redacted_file, json_file, findings = redact_file_with_report(
            input_path=str(file_path),
            output_path=str(redacted_file_path) if redacted_file_path else None,
            json_output_path=str(json_file_path) if json_file_path else None,
            config_path=config_path,
            replacement=replacement,
        )

        findings_dicts = [_finding_to_dict(f) for f in findings]
        categories = _categorize_findings(findings_dicts)
        all_findings.extend(findings)
        processed_files.append({
            "file_name": file_path.name,
            "file_path": str(file_path.resolve()),
            "original": str(file_path),
            "redacted": str(redacted_file),
            "report": str(json_file),
            "findings_count": len(findings),
            "categories": categories,
            "findings": findings_dicts,
        })

    if json_output_path:
        json_path = Path(json_output_path)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        aggregate_payload = {
            "source_directory": str(input_path.resolve()),
            "total_files_scanned": len(processed_files),
            "total_findings": len(all_findings),
            "files": processed_files,
        }
        json_path.write_text(json.dumps(aggregate_payload, indent=2), encoding="utf-8")

    return processed_files, all_findings


def redact(
    data,
    config_path: str | None = None,
    replacement: str = "[REDACTED]",
    detect_only: bool = False,
    **kwargs
):
    """
    Universal dispatcher for Redactyl.
    Accepts a string, dictionary, list, file path, or directory path and routes it to the correct redaction or detection function.
    """
    if isinstance(data, (dict, list)):
        if detect_only:
            sanitized, findings = sanitize_json_payload(data, config_path=config_path, replacement=replacement)
            return findings
        return sanitize_json_payload(data, config_path=config_path, replacement=replacement)
        
    elif isinstance(data, (str, Path)):
        path_obj = Path(data)
        
        try:
            is_valid_path = path_obj.exists()
        except OSError:
            is_valid_path = False
            
        if is_valid_path:
            if path_obj.is_dir():
                return redact_directory_with_report(
                    str(path_obj), 
                    config_path=config_path, 
                    replacement=replacement,
                    detect_only=detect_only,
                    **kwargs
                )
            else:
                if detect_only:
                    if path_obj.suffix.lower() == ".json":
                        try:
                            payload = json.loads(path_obj.read_text(encoding="utf-8"))
                            _, findings = sanitize_json_payload(payload, config_path=config_path)
                            return findings
                        except Exception:
                            text = path_obj.read_text(encoding="utf-8", errors="ignore")
                            return scan_text(text, config_path=config_path)
                    text = path_obj.read_text(encoding="utf-8", errors="ignore")
                    return scan_text(text, config_path=config_path)

                return redact_file_with_report(
                    str(path_obj), 
                    config_path=config_path, 
                    replacement=replacement,
                    **kwargs
                )
                
        if isinstance(data, str):
            if detect_only:
                return scan_text(data, config_path=config_path)
            return redact_text(data, config_path=config_path, replacement=replacement)
            
    raise ValueError(f"Unsupported data type for redactyl.redact(): {type(data)}")