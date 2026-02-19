from unittest.mock import patch
import json
import pytest
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.update_via_map_file import (
    _update_rule_severity,
    _process_sarif_runs,
    _process_text_lines,
    load_severity_map,
    update_sarif,
    update_text_report,
    main
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

# Test SARIF Input and Output files
def test_update_sarif(tmp_path):
    input_sarif = tmp_path / "input.sarif"
    output_sarif = tmp_path / "output.sarif"
    
    dummy_data = {
        "runs": [{"tool": {"driver": {"rules": [{"id": "CKV_123"}]}}}]
    }
    input_sarif.write_text(json.dumps(dummy_data))
    
    severity_map = {"CKV_123": "HIGH"}
    

    update_sarif(str(input_sarif), str(output_sarif), severity_map)
    
    # Check output file is there and has been modified
    assert output_sarif.exists()
    result_data = json.loads(output_sarif.read_text())
    rule = result_data["runs"][0]["tool"]["driver"]["rules"][0]
    
    assert rule["properties"]["security-severity"] == "8.0"
    assert rule["defaultConfiguration"]["level"] == "error"

def test_update_sarif_file_not_found():
    # Does it error on an empty dictionary?
    update_sarif("fake_input.sarif", "fake_output.sarif", {})

# Test TXT Input and Output files
def test_update_text_report(tmp_path):
    input_txt = tmp_path / "input.txt"
    output_txt = tmp_path / "output.txt"
    
    input_txt.write_text("Check: CKV_123\n\tPassed\n")
    
    severity_map = {"CKV_123": "HIGH"}
    
    update_text_report(str(input_txt), str(output_txt), severity_map)
    
    # Check output file is there and has been modified
    assert output_txt.exists()
    content = output_txt.read_text()
    assert "\tSeverity: HIGH\n" in content

def test_update_text_report_file_not_found():
    # Does it error on an empty dictionary?
    update_text_report("fake_input.txt", "fake_output.txt", {})

# Test main function

@patch("scripts.update_via_map_file.load_severity_map")
def test_main_no_severity_map(mock_load):
    # Test empty file
    mock_load.return_value = {}
    
    # Does running main terminate early?
    main()
    
    mock_load.assert_called_once()

@patch("scripts.update_via_map_file.os.environ.get")
@patch("scripts.update_via_map_file.load_severity_map")
@patch("scripts.update_via_map_file.update_sarif")
@patch("scripts.update_via_map_file.update_text_report")
@patch("scripts.update_via_map_file.Path.exists")
@patch("scripts.update_via_map_file.Path.unlink")
def test_main_successful_execution(mock_unlink, mock_exists, mock_update_txt, mock_update_sarif, mock_load, mock_env):
    # Mock test finds a valid severity
    mock_load.return_value = {"CKV_123": "HIGH"}
    
    # Mock test has 2 directories being present in SARIF_DIRS env var
    mock_env.return_value = "dir_one, dir_two"
    
    # Mock test Input files exist
    mock_exists.return_value = True 
    
    # Execute
    main()
    
    # Expecting to call functions twice as there are 2 directories to process
    assert mock_update_sarif.call_count == 2
    assert mock_update_txt.call_count == 2
    
    # Expecting to delete 2 files per directory. So as there are 2 directories in the test, we're expecting 4
    assert mock_unlink.call_count == 4
