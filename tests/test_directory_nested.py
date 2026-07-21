import json
from pathlib import Path
from typer.testing import CliRunner
from redactyl.cli import app
from redactyl.api import redact, detect_directory_with_report, redact_directory_with_report

runner = CliRunner()


def test_multi_level_directory_redaction_all_files(tmp_path):
    root_dir = tmp_path / "root"
    sub_dir1 = root_dir / "level1"
    sub_dir2 = sub_dir1 / "level2"
    sub_dir2.mkdir(parents=True)

    file_txt = root_dir / "info.txt"
    file_txt.write_text("User IP is 192.168.1.1")

    file_py = sub_dir1 / "script.py"
    file_py.write_text("API_KEY = 'sk_live_123456789012345678'")

    file_json = sub_dir2 / "config.json"
    file_json.write_text(json.dumps({"secret_email": "admin@foo.bar"}))

    file_noext = sub_dir2 / "dockerfile_like"
    file_noext.write_text("ENV SECRET_IP 10.0.0.1")

    out_dir = tmp_path / "redacted_out"

    # Run CLI redaction
    result = runner.invoke(app, [str(root_dir), "--redact", "--out", str(out_dir)])
    assert result.exit_code == 0
    assert "Successfully processed 4 files" in result.stdout

    # Verify all files across all nested levels were redacted
    redacted_txt = out_dir / "info.redacted.txt"
    assert redacted_txt.exists()
    assert "User IP is [REDACTED]" in redacted_txt.read_text()

    redacted_py = out_dir / "level1" / "script.redacted.py"
    assert redacted_py.exists()
    assert "API_KEY = '[REDACTED]'" in redacted_py.read_text()

    redacted_json = out_dir / "level1" / "level2" / "config.redacted.json"
    assert redacted_json.exists()
    json_data = json.loads(redacted_json.read_text())
    assert json_data["secret_email"] == "[REDACTED]"

    redacted_noext = out_dir / "level1" / "level2" / "dockerfile_like.redacted.txt"
    assert redacted_noext.exists()
    assert "ENV SECRET_IP [REDACTED]" in redacted_noext.read_text()


def test_multi_level_directory_detect_only_cli(tmp_path):
    root_dir = tmp_path / "scan_target"
    sub_dir = root_dir / "a" / "b" / "c"
    sub_dir.mkdir(parents=True)

    (root_dir / "root.log").write_text("Email boss@company.com")
    (sub_dir / "deep.csv").write_text("col1,col2\n192.168.0.5,test@example.com")

    json_report = tmp_path / "scan_report.json"

    result = runner.invoke(app, [str(root_dir), "--detect-only", "--json-out", str(json_report)])
    assert result.exit_code == 0
    assert "Successfully scanned 2 files" in result.stdout

    assert json_report.exists()
    report_data = json.loads(json_report.read_text())
    assert report_data["total_files_scanned"] == 2
    assert report_data["total_findings"] >= 3  # boss@company.com (email+domain), 192.168.0.5, test@example.com (email+domain)

    # Ensure original files remain untouched
    assert "boss@company.com" in (root_dir / "root.log").read_text()
    assert "192.168.0.5" in (sub_dir / "deep.csv").read_text()


def test_api_redact_universal_dispatcher_detect_only_dir(tmp_path):
    root_dir = tmp_path / "api_dir"
    nested_dir = root_dir / "sub"
    nested_dir.mkdir(parents=True)

    (nested_dir / "secret.env").write_text("DB_IP=172.16.0.1")

    processed, findings = redact(root_dir, detect_only=True)
    assert len(processed) == 1
    assert len(findings) >= 1
    assert findings[0].value == "172.16.0.1"
