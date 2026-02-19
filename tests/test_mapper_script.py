import pytest
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.update_via_map_file import (
    _update_rule_severity,
    _process_sarif_runs,
    _process_text_lines,
    load_severity_map
)

# Test that the dictionaries update correctly
def test_update_rule_severity():
    rule = {}
    _update_rule_severity(rule, "HIGH")
    
    assert rule["properties"]["security-severity"] == "8.0"
    assert rule["defaultConfiguration"]["level"] == "error"

    # Test fallback for unknown severity
    rule2 = {}
    _update_rule_severity(rule2, "UNKNOWN_SEVERITY")
    assert rule2["properties"]["security-severity"] == "0.0"
    assert rule2["defaultConfiguration"]["level"] == "note"

# Create a test map CSV file and test conversion logic
def test_load_severity_map(tmp_path):
    csv_file = tmp_path / "test_map.csv"
    csv_file.write_text("CKV_123, HIGH\nCKV_456, INFO\nINVALID_ROW_NO_COMMA\n")
    
    mapping = load_severity_map(str(csv_file))
    
    assert mapping["CKV_123"] == "HIGH"
    assert mapping["CKV_456"] == "LOW"
    assert "INVALID_ROW_NO_COMMA" not in mapping

def test_load_severity_map_missing_file():
    # Does it error on an empty dictionary?
    assert load_severity_map("does_not_exist.csv") == {}

# Test SARIF file
def test_process_sarif_runs():
    runs = [{
        "tool": {
            "driver": {
                "rules": [
                    {"id": "CKV_123"}, # Valid
                    {"id": "CKV_999"}, # Valid but missing ID
                    {"id": "OTHER_123"}, # Invalid prefix
                    {} # Blank
                ]
            }
        }
    }]
    severity_map = {"CKV_123": "HIGH"}
    
    updates, missing = _process_sarif_runs(runs, severity_map)
    
    assert updates == 1
    assert "CKV_999" in missing
    assert "OTHER_123" not in missing

# Test TXT file
def test_process_text_lines():
    lines = [
        "Check: CKV_123\n",
        "\tPassed\n",
        "Check: CKV_456\n",
        "\tSeverity: LOW\n" # This block already has a severity set (Unlikely though as only working ones are FINOPS tags whch have a different prefix)
    ]
    severity_map = {"CKV_123": "HIGH", "CKV_456": "MEDIUM"}
    
    updated_lines, updates = _process_text_lines(lines, severity_map)
    
    # Only update once
    assert updates == 1
    assert "\tSeverity: HIGH\n" in updated_lines
    
    # Make sure there are no duplications
    assert updated_lines.count("\tSeverity: LOW\n") == 1
    assert "\tSeverity: MEDIUM\n" not in updated_lines
