"""
Case Auditor module for Ghost Data Still Exists.
Orchestrates identity resolution, system activity tracking, evidence evaluation,
remediation planning, and verification check generation.
"""

import os
import csv
import json
import re
from typing import Dict, List, Any, Tuple, Set, Optional

from .identity import IdentityResolver
from .intent import IntentClassifier
from .policy import PolicyEngine
from .evidence_index import EvidenceIndex


class CaseAuditor:
    def __init__(self, dataset_dir: str):
        self.dataset_dir = dataset_dir
        self.identity_resolver = IdentityResolver(dataset_dir)
        self.evidence_index = EvidenceIndex(dataset_dir)
        self.system_activity = self._load_system_activity()
        self.linked_resources = self._load_linked_resources()

    def _load_system_activity(self) -> List[Dict[str, Any]]:
        path = os.path.join(self.dataset_dir, "system_activity.csv")
        with open(path, mode="r", encoding="utf-8") as f:
            return list(csv.DictReader(f))

    def _load_linked_resources(self) -> Dict[str, Set[str]]:
        uid_to_res: Dict[str, Set[str]] = {}
        for a in self.system_activity:
            if a["event_type"] == "LINK_RESOURCE_IDENTITY":
                det = a.get("details", "")
                res_id = a.get("resource_id", "")
                u_m = re.search(r'user_\d+', det)
                if u_m:
                    uid_to_res.setdefault(u_m.group(0), set()).add(res_id)
        return uid_to_res

    def audit_case(self, case_req: Dict[str, Any]) -> Tuple[str, List[Dict[str, Any]]]:
        cid = case_req["case_id"]
        email = case_req["email"].strip().lower()
        req_text = case_req.get("request_text", "")
        req_at = case_req.get("requested_at", "")
        rep_at = case_req.get("reported_at", "")
        audit_at = case_req.get("audit_at", "")

        # 1. Determine if deletion is authorized
        if not IntentClassifier.is_deletion_authorized(req_text):
            return "NOT_APPLICABLE", []

        # 2. Resolve Subject Identifiers
        uid = self.identity_resolver.resolve_email(email)
        footprint = self.identity_resolver.get_user_footprint(uid) if uid else {
            "user_id": uid, "emails": {email}, "phones": set(), "names": set(), "hashes": set()
        }
        all_emails = footprint["emails"]
        all_emails.add(email)

        # 3. Discover Candidate Resources
        candidate_resources: Set[str] = set()

        # Add resources from linked_resources
        if uid and uid in self.linked_resources:
            candidate_resources.update(self.linked_resources[uid])

        # Add resources directly observed in evidence index for user
        for em in all_emails:
            candidate_resources.update(self.evidence_index.email_to_resources.get(em, set()))
        if uid:
            candidate_resources.update(self.evidence_index.uid_to_resources.get(uid, set()))

        # Check deletion_worker activity for the case window
        for a in self.system_activity:
            if a["source_system"] == "deletion_worker":
                t = a["event_time"]
                if req_at <= t <= rep_at + "Z":
                    det = a.get("details", "").lower()
                    res = a.get("resource_id")
                    if res:
                        if any(em in det for em in all_emails) or (uid and uid.lower() in det):
                            candidate_resources.add(res)
                        elif uid and res in self.linked_resources.get(uid, set()):
                            candidate_resources.add(res)
                        elif res in self.evidence_index.resource_observations:
                            # check if this resource was observed with this user's email or uid
                            for obs in self.evidence_index.resource_observations[res]:
                                if any(em in obs.get("emails", set()) for em in all_emails) or (uid and uid in obs.get("uids", set())):
                                    candidate_resources.add(res)
                                    break

        # Discover primary account resource if not present
        has_account = any(r.startswith("account_") for r in candidate_resources)
        if not has_account:
            # Check deletion_worker activity in [req_at, rep_at]
            for a in self.system_activity:
                if a["target_system"] == "account_service" and a["source_system"] == "deletion_worker":
                    if req_at <= a["event_time"] <= rep_at + "Z":
                        candidate_resources.add(a["resource_id"])
                        break

        # 4. Evaluate Resource States at audit_at
        findings: List[Dict[str, Any]] = []
        remediations: List[Dict[str, Any]] = []
        verifications: List[Dict[str, Any]] = []

        is_incomplete = False

        for res_id in sorted(candidate_resources):
            obs = self.evidence_index.get_latest_observation(res_id, audit_at)
            
            # Determine system_id
            sys_id = "account_service"
            if res_id.startswith("search_"): sys_id = "search_service"
            elif res_id.startswith("analytics_"): sys_id = "analytics_platform"
            elif res_id.startswith("support_"): sys_id = "support_platform"
            elif res_id.startswith("export_"): sys_id = "export_service"
            elif res_id.startswith("data_flow_"): sys_id = "integration_service"
            elif res_id.startswith("backup_"): sys_id = "backup_service"
            elif res_id.startswith("audit_record_"): sys_id = "security_service"
            elif res_id.startswith("tombstone_"): sys_id = "identity_service"
            elif obs: sys_id = obs["system_id"]

            if obs:
                status = obs.get("status", "PRESENT")
                has_pii = obs.get("has_pii", False)
                ev_id = obs["evidence_id"]

                # Case A: Whole record still exists and should be deleted
                if status in ["PRESENT", "FOUND", "ACTIVE"] and sys_id in ["account_service", "search_service", "export_service"]:
                    is_incomplete = True
                    findings.append({
                        "phase": "FINDING",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "REPORT_REMAINING_RECORD",
                        "state": "PRESENT",
                        "evidence_id": ev_id
                    })
                    remediations.append({
                        "phase": "REMEDIATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "DELETE_RECORD",
                        "state": "ABSENT",
                        "evidence_id": ""
                    })
                    verifications.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "VERIFY_RECORD_ABSENT",
                        "state": "ABSENT",
                        "evidence_id": ""
                    })

                # Case B: Support record or tombstone or analytics contains exposed PII
                elif status in ["PRESENT", "FOUND", "IDENTIFIABLE"] and has_pii:
                    if sys_id == "analytics_platform":
                        is_incomplete = True
                        findings.append({
                            "phase": "FINDING",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "REPORT_EXPOSED_PII",
                            "state": "PRESENT",
                            "evidence_id": ev_id
                        })
                        remediations.append({
                            "phase": "REMEDIATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "ANONYMIZE_RECORD",
                            "state": "ANONYMIZED",
                            "evidence_id": ""
                        })
                        verifications.append({
                            "phase": "VERIFICATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "VERIFY_RECORD_ANONYMIZED",
                            "state": "ANONYMIZED",
                            "evidence_id": ""
                        })
                    elif sys_id in ["support_platform", "identity_service"]:
                        is_incomplete = True
                        findings.append({
                            "phase": "FINDING",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "REPORT_EXPOSED_PII",
                            "state": "PRESENT",
                            "evidence_id": ev_id
                        })
                        remediations.append({
                            "phase": "REMEDIATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "REDACT_RECORD",
                            "state": "REDACTED",
                            "evidence_id": ""
                        })
                        verifications.append({
                            "phase": "VERIFICATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "VERIFY_RECORD_REDACTED",
                            "state": "REDACTED",
                            "evidence_id": ""
                        })

                # Case C: Active data flow
                elif sys_id == "integration_service" and (status == "ACTIVE" or obs.get("enabled", False)):
                    is_incomplete = True
                    findings.append({
                        "phase": "FINDING",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "REPORT_ACTIVE_DATA_FLOW",
                        "state": "ACTIVE",
                        "evidence_id": ev_id
                    })
                    remediations.append({
                        "phase": "REMEDIATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "DISABLE_DATA_FLOW",
                        "state": "DISABLED",
                        "evidence_id": ""
                    })
                    verifications.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "VERIFY_DATA_FLOW_DISABLED",
                        "state": "DISABLED",
                        "evidence_id": ""
                    })

                # Case D: Restore risk
                elif sys_id == "backup_service" and (status == "ACTIVE" or obs.get("restore_allowed", False)):
                    is_incomplete = True
                    findings.append({
                        "phase": "FINDING",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "REPORT_RESTORE_RISK",
                        "state": "ACTIVE",
                        "evidence_id": ev_id
                    })
                    remediations.append({
                        "phase": "REMEDIATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "BLOCK_RESTORE",
                        "state": "BLOCKED",
                        "evidence_id": ""
                    })
                    verifications.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "VERIFY_RESTORE_BLOCKED",
                        "state": "BLOCKED",
                        "evidence_id": ""
                    })

                # Case E: Record is already properly treated at audit_at
                else:
                    if sys_id == "security_service":
                        verifications.append({
                            "phase": "VERIFICATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "VERIFY_RECORD_PRESENT",
                            "state": "PRESENT",
                            "evidence_id": ev_id
                        })
                    elif sys_id == "analytics_platform":
                        verifications.append({
                            "phase": "VERIFICATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "VERIFY_RECORD_ANONYMIZED",
                            "state": "ANONYMIZED",
                            "evidence_id": ev_id
                        })
                    elif sys_id in ["support_platform", "identity_service"]:
                        verifications.append({
                            "phase": "VERIFICATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "VERIFY_RECORD_REDACTED",
                            "state": "REDACTED",
                            "evidence_id": ev_id
                        })
                    elif sys_id == "integration_service":
                        verifications.append({
                            "phase": "VERIFICATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "VERIFY_DATA_FLOW_DISABLED",
                            "state": "DISABLED",
                            "evidence_id": ev_id
                        })
                    elif sys_id == "backup_service":
                        verifications.append({
                            "phase": "VERIFICATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "VERIFY_RESTORE_BLOCKED",
                            "state": "BLOCKED",
                            "evidence_id": ev_id
                        })
                    elif sys_id in ["account_service", "search_service", "export_service"]:
                        verifications.append({
                            "phase": "VERIFICATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "VERIFY_RECORD_ABSENT",
                            "state": "ABSENT",
                            "evidence_id": ev_id
                        })

        # 5. Determine Overall Deletion Status
        deletion_status = "INCOMPLETE" if is_incomplete else "COMPLETE"

        if is_incomplete:
            final_steps = []
            final_steps.extend(findings)
            final_steps.extend(remediations)
            for v in verifications:
                v_copy = dict(v)
                v_copy["evidence_id"] = ""
                final_steps.append(v_copy)
        else:
            final_steps = list(verifications)

        sorted_steps = PolicyEngine.sort_and_number_steps(final_steps)
        return deletion_status, sorted_steps
