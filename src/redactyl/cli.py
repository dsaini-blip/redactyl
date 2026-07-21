import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich import print

from redactyl.api import redact_directory_with_report, redact_file_with_report, scan_text

app = typer.Typer(help="Python library and CLI for detecting and redacting sensitive information.")


def finding_to_dict(finding):
    return {
        "type": getattr(finding, "type", None),
        "start": getattr(finding, "start", None),
        "end": getattr(finding, "end", None),
        "value": getattr(finding, "value", None),
        "detector": getattr(finding, "detector", None),
        "confidence": getattr(finding, "confidence", None),
    }


@app.command()
def main(
    path: Annotated[Path, typer.Argument(help="File or directory to scan")],
    config: Annotated[Optional[Path], typer.Option("--config", help="Path to YAML config file")] = None,
    detect_only: Annotated[bool, typer.Option("--detect-only", help="Only detect sensitive values")] = False,
    redact: Annotated[bool, typer.Option("--redact", help="Redact sensitive values")] = False,
    out: Annotated[Optional[Path], typer.Option("--out", help="Path for redacted output file or directory")] = None,
    json_out: Annotated[Optional[Path], typer.Option("--json-out", help="Path for JSON findings report (only used for file input)")] = None,
):
    if not path.exists():
        print(f"[red]Error: Path does not exist: {path}[/red]")
        raise typer.Exit(code=1)

    config_str = str(config) if config else None

    if path.is_dir():
        if detect_only and not redact:
            print(f"Scanning directory (detect-only): {path}")
            json_target_path = (
                json_out
                if json_out
                else (out / "findings.json" if out else path.with_name(f"{path.name}.findings.json"))
            )
            processed_files, all_findings = redact_directory_with_report(
                input_dir=str(path),
                output_dir=str(out) if out else None,
                json_output_path=str(json_target_path),
                config_path=config_str,
                detect_only=True,
            )
            print(f"[green]Successfully scanned {len(processed_files)} files across nested directories.[/green]")
            print(f"Total findings across all files: {len(all_findings)}")
            print(f"JSON report written to: {json_target_path}")
            return

        print(f"Scanning directory: {path}")
        processed_files, all_findings = redact_directory_with_report(
            input_dir=str(path),
            output_dir=str(out) if out else None,
            config_path=config_str,
        )
        print(f"[green]Successfully processed {len(processed_files)} files.[/green]")
        print(f"Total findings across all files: {len(all_findings)}")

    else:
        # File mode
        if detect_only and not redact:
            findings = scan_text(
                path.read_text(encoding="utf-8", errors="ignore"),
                config_path=config_str,
            )

            json_output_path = (
                json_out if json_out else path.with_name(f"{path.stem}.findings.json")
            )

            payload = {
                "source_file": str(path),
                "total_findings": len(findings),
                "findings": [finding_to_dict(f) for f in findings],
            }

            json_output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            print(f"JSON report written to: {json_output_path}")
            return

        redacted_file, json_file, findings = redact_file_with_report(
            input_path=str(path),
            output_path=str(out) if out else None,
            json_output_path=str(json_out) if json_out else None,
            config_path=config_str,
        )

        print(f"Redacted file written to: {redacted_file}")
        print(f"JSON report written to: {json_file}")
        print(f"Total findings: {len(findings)}")


if __name__ == "__main__":
    app()