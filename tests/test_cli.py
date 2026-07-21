import json
from pathlib import Path
from typer.testing import CliRunner
from redactyl.cli import app

runner = CliRunner()

def test_cli_file_detect_only(tmp_path):
    input_file = tmp_path / "test.txt"
    input_file.write_text("Email admin@foo.bar")

    result = runner.invoke(app, [str(input_file), "--detect-only"])
    assert result.exit_code == 0
    assert "JSON report written to:" in result.stdout

    json_file = tmp_path / "test.findings.json"
    assert json_file.exists()
    
    data = json.loads(json_file.read_text())
    assert data["file_name"] == "test.txt"
    assert "file_path" in data
    assert "categories" in data
    assert "EMAIL" in data["categories"]
    assert data["total_findings"] == 2
    values = [f["value"] for f in data["findings"]]
    assert "admin@foo.bar" in values

def test_cli_file_redact(tmp_path):
    input_file = tmp_path / "test.txt"
    input_file.write_text("Email admin@foo.bar")

    result = runner.invoke(app, [str(input_file), "--redact"])
    assert result.exit_code == 0
    
    redacted_file = tmp_path / "test.redacted.txt"
    assert redacted_file.exists()
    assert "Email [REDACTED]" in redacted_file.read_text()

def test_cli_directory(tmp_path):
    dir_path = tmp_path / "mydir"
    dir_path.mkdir()
    
    file1 = dir_path / "f1.txt"
    file1.write_text("IP 8.8.8.8")
    
    file2 = dir_path / "f2.txt"
    file2.write_text("Email test@example.com")
    
    out_dir = tmp_path / "outdir"

    result = runner.invoke(app, [str(dir_path), "--redact", "--out", str(out_dir)])
    assert result.exit_code == 0
    assert "Successfully processed 2 files" in result.stdout
    
    assert (out_dir / "f1.redacted.txt").exists()
    assert (out_dir / "f2.redacted.txt").exists()

def test_cli_json_file_redact(tmp_path):
    input_file = tmp_path / "data.json"
    payload = {"users": [{"email": "admin@foo.bar", "id": 1}]}
    input_file.write_text(json.dumps(payload))

    result = runner.invoke(app, [str(input_file), "--redact"])
    assert result.exit_code == 0
    
    redacted_file = tmp_path / "data.redacted.json"
    assert redacted_file.exists()
    
    redacted_payload = json.loads(redacted_file.read_text())
    assert redacted_payload["users"][0]["id"] == 1
    assert redacted_payload["users"][0]["email"] == "[REDACTED]"
    
    json_file = tmp_path / "data.findings.json"
    assert json_file.exists()
    
    findings_data = json.loads(json_file.read_text())
    assert findings_data["total_findings"] == 2 # EMAIL + DOMAIN
