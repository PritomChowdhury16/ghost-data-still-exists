"""
Policy rules and sorting constraints for Ghost Data Still Exists.
Enforces deletion_rules.csv semantics, operation/state validation, and exact sequence sorting.
"""

from typing import List, Dict, Any, Tuple


class PolicyEngine:
    # Phase weights for exact sequence sorting
    PHASE_ORDER = {
        "FINDING": 1,
        "REMEDIATION": 2,
        "VERIFICATION": 3,
    }

    # Operation priority within each phase
    OPERATION_ORDER = {
        # Finding operations
        "REPORT_REMAINING_RECORD": 1,
        "REPORT_EXPOSED_PII": 2,
        "REPORT_ACTIVE_DATA_FLOW": 3,
        "REPORT_RESTORE_RISK": 4,
        # Remediation operations
        "DISABLE_DATA_FLOW": 1,
        "BLOCK_RESTORE": 2,
        "DELETE_RECORD": 3,
        "REDACT_RECORD": 4,
        "ANONYMIZE_RECORD": 5,
        # Verification operations
        "VERIFY_RECORD_ABSENT": 1,
        "VERIFY_RECORD_PRESENT": 2,
        "VERIFY_RECORD_REDACTED": 3,
        "VERIFY_RECORD_ANONYMIZED": 4,
        "VERIFY_DATA_FLOW_DISABLED": 5,
        "VERIFY_RESTORE_BLOCKED": 6,
    }

    # Valid operation -> state mapping
    OPERATION_STATE_MAP = {
        "REPORT_REMAINING_RECORD": "PRESENT",
        "REPORT_EXPOSED_PII": "PRESENT",
        "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
        "REPORT_RESTORE_RISK": "ACTIVE",
        "DISABLE_DATA_FLOW": "DISABLED",
        "BLOCK_RESTORE": "BLOCKED",
        "DELETE_RECORD": "ABSENT",
        "REDACT_RECORD": "REDACTED",
        "ANONYMIZE_RECORD": "ANONYMIZED",
        "VERIFY_RECORD_ABSENT": "ABSENT",
        "VERIFY_RECORD_PRESENT": "PRESENT",
        "VERIFY_RECORD_REDACTED": "REDACTED",
        "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
        "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
        "VERIFY_RESTORE_BLOCKED": "BLOCKED",
    }

    @classmethod
    def get_sort_key(cls, step: Dict[str, Any]) -> Tuple[int, int, str, str]:
        phase_w = cls.PHASE_ORDER.get(step["phase"], 99)
        op_w = cls.OPERATION_ORDER.get(step["operation"], 99)
        sys_id = step.get("system_id", "")
        res_id = step.get("resource_id", "")
        return (phase_w, op_w, sys_id, res_id)

    @classmethod
    def sort_and_number_steps(cls, steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Sorts steps by (phase, operation, system_id, resource_id) and numbers consecutively starting from 1.
        """
        sorted_steps = sorted(steps, key=cls.get_sort_key)
        result = []
        for idx, s in enumerate(sorted_steps, start=1):
            s_copy = dict(s)
            s_copy["step_no"] = idx
            # Ensure state is valid
            if "operation" in s_copy and s_copy["operation"] in cls.OPERATION_STATE_MAP:
                s_copy["state"] = cls.OPERATION_STATE_MAP[s_copy["operation"]]
            result.append(s_copy)
        return result
