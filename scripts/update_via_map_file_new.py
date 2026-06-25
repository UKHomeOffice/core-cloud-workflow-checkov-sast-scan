import json
import csv
import os
import re
from pathlib import Path

CWD = Path(os.getcwd())

SARIF_DIR_NAME = os.environ.get("SARIF_DIR", "results.sarif")
SARIF_DIR_PATH = CWD / SARIF_DIR_NAME

CSV_MAP_FILE = "checkout-checkov-mapping-updates/checkov_map.csv"

SEVERITY_TO_SCORE = {
    "INFO": "0.0",
    "LOW": "3.0",
    "MEDIUM": "6.0",
    "HIGH": "8.0",
    "CRITICAL": "9.0"
}

SEVERITY_TO_LEVEL = {
    "INFO": "note",
    "LOW": "note",
    "MEDIUM": "warning",
    "HIGH": "error",
    "CRITICAL": "error"
}

def load_severity_map(csv_path):
    mapping = {}
    if not os.path.exists(csv_path):
        print(f"Checkov CSV file {csv_path} not found")
        return {}

    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 2:
                continue
            
            rule_id = row[0].strip()
            severity_text = row[1].strip().upper()

            # GHA doesn't have an INFO severity level, so substitute for LOW
            if severity_text == "INFO":
                severity_text = "LOW"
            
            if severity_text in SEVERITY_TO_SCORE:
                mapping[rule_id] = severity_text
                
    print(f"Loaded {len(mapping)} rules from Checkov CSV file")
    return mapping

def _update_rule_severity(rule, severity_label):
    """Helper to update a single SARIF rule dict."""
    new_score = SEVERITY_TO_SCORE.get(severity_label, "0.0")
    new_level = SEVERITY_TO_LEVEL.get(severity_label, "note")

    # Use dict.setdefault to avoid deeply nested if-statements
    rule.setdefault("properties", {})["security-severity"] = new_score
    rule.setdefault("defaultConfiguration", {})["level"] = new_level

def _process_sarif_runs(runs, severity_map):
    """Helper to iterate through runs and apply severity map."""
    updates_count = 0
    missing_ids = set()

    for run in runs:
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])

        for rule in rules:
            rule_id = rule.get("id")
            
            # Guard clause: Skip if no rule ID or not a Checkov rule
            if not rule_id or not rule_id.startswith(("CKV_", "CKV2_")):
                continue
            
            # Guard clause: Track missing mappings
            if rule_id not in severity_map:
                missing_ids.add(rule_id)
                continue
                
            severity_label = severity_map[rule_id]
            _update_rule_severity(rule, severity_label)
            updates_count += 1

    return updates_count, missing_ids

def update_sarif(input_path, output_path, severity_map):
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            sarif_data = json.load(f)
    except FileNotFoundError:
        print(f"SARIF file {input_path} not found")
        return

    # Process runs using helper function to reduce complexity
    runs = sarif_data.get("runs", [])
    updates_count, missing_ids = _process_sarif_runs(runs, severity_map)

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(sarif_data, f, indent=2)

    if missing_ids:
        print(f"Warning: {len(missing_ids)} CKV rules missing from map")
        
    print(f"{updates_count} rules updated in {output_path}")

def _process_text_lines(lines, severity_map):
    """Helper to process text lines and inject severity labels."""
    updated_lines = []
    updates_count = 0
    re_check_line = re.compile(r"^Check:\s+(CKV2?_[A-Z0-9_]+|CCL_[A-Z0-9_]+)")

    for i, line in enumerate(lines):
        updated_lines.append(line)
        
        match = re_check_line.search(line)
        if not match:
            continue
            
        current_check_id = match.group(1)
        if current_check_id not in severity_map:
            continue
            
        # Check the next 2 lines for the Severity: line
        next_line = lines[i+1] if i+1 < len(lines) else ""
        second_line = lines[i+2] if i+2 < len(lines) else ""

        if "Severity:" in next_line or "Severity:" in second_line:
            continue

        # If it passed all guards, inject the severity
        severity_label = severity_map[current_check_id]
        updated_lines.append(f"\tSeverity: {severity_label}\n")
        updates_count += 1
        
    return updated_lines, updates_count

def update_text_report(input_path, output_path, severity_map):
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Text file {input_path} not found")
        return

    # Process lines using helper function to reduce complexity
    updated_lines, updates_count = _process_text_lines(lines, severity_map)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.writelines(updated_lines)

    print(f"Added severity to {updates_count} blocks in {output_path}")

def main():
    print("Updating SARIF and TXT files")
    
    severity_map = load_severity_map(CSV_MAP_FILE)
    
    if not severity_map:
        print("Severity map invalid or missing")
        return

    dirs_env = os.environ.get("SARIF_DIRS", "results.sarif")
    target_dirs = [d.strip() for d in dirs_env.split(",") if d.strip()]

    print(f"Processing {len(target_dirs)} directories: {target_dirs}")

    for dir_name in target_dirs:
        base_dir = CWD / dir_name
        
        input_sarif = base_dir / "results_sarif.sarif"
        output_sarif = base_dir / "results_enriched.sarif"
        input_txt = base_dir / "results_cli.txt"
        output_txt = base_dir / "results_updated.txt"

        print(f"\n--- Processing Directory: {dir_name} ---")

        update_sarif(input_sarif, output_sarif, severity_map)
        update_text_report(input_txt, output_txt, severity_map)

        try:
            if input_sarif.exists():
                input_sarif.unlink()
                print(f" - Deleted {input_sarif.name}")

            if input_txt.exists():
                input_txt.unlink()
                print(f" - Deleted {input_txt.name}")

        except Exception as e:
            print(f"Warning: Could not delete input files in {dir_name}: {e}")

    print("Completed Successfully")

if __name__ == "__main__":
    main()
