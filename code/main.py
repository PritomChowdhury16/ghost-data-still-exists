"""
Main execution script for Ghost Data Still Exists challenge.
Processes dataset/deletion_requests.csv and outputs output.csv at repository root.
"""

import os
import sys
import csv
import json
from pathlib import Path

# Ensure code directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.auditor import CaseAuditor


def main():
    root_dir = Path(__file__).resolve().parent.parent
    dataset_dir = root_dir / "dataset"
    requests_path = dataset_dir / "deletion_requests.csv"
    output_path = root_dir / "output.csv"

    print(f"Initializing CaseAuditor with dataset at {dataset_dir}...")
    auditor = CaseAuditor(str(dataset_dir))

    print(f"Reading deletion requests from {requests_path}...")
    with open(requests_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        requests = list(reader)

    print(f"Auditing {len(requests)} deletion requests...")
    results = []
    for req in requests:
        cid = req["case_id"]
        status, steps = auditor.audit_case(req)
        steps_json_str = json.dumps(steps, separators=(",", ":"))
        results.append({
            "case_id": cid,
            "deletion_status": status,
            "steps_json": steps_json_str
        })

    # Sort results by case_id
    results.sort(key=lambda x: x["case_id"])

    print(f"Writing {len(results)} evaluated cases to {output_path}...")
    with open(output_path, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        writer.writerows(results)

    print("Audit process completed successfully.")


if __name__ == "__main__":
    main()
