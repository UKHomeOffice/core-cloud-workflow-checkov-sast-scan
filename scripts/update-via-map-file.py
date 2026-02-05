import json
import csv
import os
import re
from pathlib import Path

CWD = Path(os.getcwd())

CSV_MAP_FILE = CWD / "checkov_map.csv"
INPUT_SARIF  = CWD / "results.sarif" / "results_sarif.sarif"
OUTPUT_SARIF = CWD / "results.sarif" / "results_enriched.sarif"
INPUT_TXT    = CWD / "results.sarif" / "results_cli.txt"
OUTPUT_TXT   = CWD / "results.sarif" / "results_updated.txt"

print(f"Script running in: {CWD}")
print(f"Looking for SARIF at: {INPUT_SARIF}")

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
            
            if severity_text in SEVERITY_TO_SCORE:
                mapping[rule_id] = severity_text
                
    print(f"Loaded {len(mapping)} rules from Checkov CSV file")
    return mapping

def update_sarif(input_path, output_path, severity_map):
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            sarif_data = json.load(f)
    except FileNotFoundError:
        print(f"SARIF file {input_path} not found")
        return

    updates_count = 0
    missing_ids = set()
    
    # Iterate through the sarif data
    for run in sarif_data.get("runs", []):
        tool = run.get("tool", {})
        driver = tool.get("driver", {})
        rules = driver.get("rules", [])

        for rule in rules:
            rule_id = rule.get("id")
            if not rule_id:
                continue

            # Checkov IDs are prefixed with either CKV_ or CKV2_
            is_checkov_rule = rule_id.startswith(("CKV_", "CKV2_"))
            
            if is_checkov_rule:
                if rule_id in severity_map:
                    severity_label = severity_map[rule_id]
                    
                    new_score = SEVERITY_TO_SCORE.get(severity_label, "0.0")
                    new_level = SEVERITY_TO_LEVEL.get(severity_label, "note")

                    # Create 'security-severity' and set the score
                    if "properties" not in rule:
                        rule["properties"] = {}
                    rule["properties"]["security-severity"] = new_score

                    # 4. Update 'level' according to the severity score
                    if "defaultConfiguration" not in rule:
                        rule["defaultConfiguration"] = {}
                    rule["defaultConfiguration"]["level"] = new_level
                    
                    updates_count += 1
                else:
                    missing_ids.add(rule_id)

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(sarif_data, f, indent=2)

    if missing_ids:
        print(f"Warning: {len(missing_ids)} CKV rules missing from map")
        
    print(f"{updates_count} rules updated in {output_path}")

def update_text_report(input_path, output_path, severity_map):
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Text file {input_path} not found")
        return

    updated_lines = []
    updates_count = 0
    
    # Regex to find Check: line. Must have prefix of either CKV_ CKV2_ or CCL_
    re_check_line = re.compile(r"^Check:\s+(CKV2?_[A-Z0-9_]+|CCL_[A-Z0-9_]+)")

    for i, line in enumerate(lines):
        updated_lines.append(line)
        
        match = re_check_line.search(line)
        if match:
            current_check_id = match.group(1)
            
            # Check the next 2 lines for the Severity: line and update it with the relevant label
            next_line = lines[i+1] if i+1 < len(lines) else ""
            second_line = lines[i+2] if i+2 < len(lines) else ""

            if "Severity:" not in next_line and "Severity:" not in second_line:
                if current_check_id in severity_map:
                    severity_label = severity_map[current_check_id]
                    new_line = f"\tSeverity: {severity_label}\n"
                    updated_lines.append(new_line)
                    updates_count += 1

    with open(output_path, 'w', encoding='utf-8') as f:
        f.writelines(updated_lines)

    print(f"Added severity to {updates_count} blocks in {output_path}")

def main():
    print("Updating SARIF and TXT files")
    
    severity_map = load_severity_map(CSV_MAP_FILE)
    
    if not severity_map:
        print("Severity map invalid or missing")
        return

    update_sarif(INPUT_SARIF, OUTPUT_SARIF, severity_map)
    update_text_report(INPUT_TXT, OUTPUT_TXT, severity_map)
    
    print("Completed Successfully")

if __name__ == "__main__":
    main()
