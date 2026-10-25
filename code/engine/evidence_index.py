"""
Evidence indexer for Ghost Data Still Exists.
Parses all participant-facing evidence artifacts (SQL, JSON, LOG, PDF)
and provides fast point-in-time state lookup indexed by resource_id, email, and user_id.
"""

import os
import re
import csv
import json
import zlib
import base64
from typing import Dict, List, Any, Optional, Set


class EvidenceIndex:
    def __init__(self, dataset_dir: str):
        self.dataset_dir = dataset_dir
        self.evidence_files: Dict[str, Dict[str, str]] = {}
        self.resource_observations: Dict[str, List[Dict[str, Any]]] = {}
        self.email_to_resources: Dict[str, Set[str]] = {}
        self.uid_to_resources: Dict[str, Set[str]] = {}
        self.hash_to_resources: Dict[str, Set[str]] = {}
        self._load_manifest()
        self._index_all_evidence()

    def _load_manifest(self) -> None:
        manifest_path = os.path.join(self.dataset_dir, "evidence_files.csv")
        with open(manifest_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                self.evidence_files[row["file_id"]] = row

    def _add_observation(self, obs: Dict[str, Any]) -> None:
        res_id = obs["resource_id"]
        self.resource_observations.setdefault(res_id, []).append(obs)
        for em in obs.get("emails", []):
            if em:
                self.email_to_resources.setdefault(em.lower(), set()).add(res_id)
        for uid in obs.get("uids", []):
            if uid:
                self.uid_to_resources.setdefault(uid, set()).add(res_id)
        for h in obs.get("hashes", []):
            if h:
                self.hash_to_resources.setdefault(h.lower(), set()).add(res_id)

    def _index_all_evidence(self) -> None:
        for fid, meta in self.evidence_files.items():
            rel_path = meta["file_path"]
            abs_path = os.path.join(self.dataset_dir, rel_path)
            if not os.path.exists(abs_path):
                continue
            cap_at = meta["captured_at"]

            if rel_path.endswith(".sql"):
                self._parse_sql(fid, abs_path, cap_at)
            elif rel_path.endswith(".json"):
                self._parse_json(fid, abs_path, cap_at)
            elif rel_path.endswith(".log") or rel_path.endswith(".txt"):
                self._parse_log_or_txt(fid, abs_path, cap_at)
            elif rel_path.endswith(".pdf"):
                self._parse_pdf(fid, abs_path, cap_at)

    def _parse_sql(self, fid: str, path: str, cap_at: str) -> None:
        with open(path, mode="r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        is_failover = "failover_replica" in path or "customer_profiles_failover_replica" in content
        is_read_rep = "read_replica" in path or "customer_data_read_replica" in content

        if is_failover and "customer_profiles" in content:
            rep_matches = re.findall(
                r'customer_profiles_failover_replica.*?VALUES\s*\(\s*\'([^\']+)\'\s*,\s*\'([^\']+)\'\s*,\s*\'([^\']+)\'\s*,\s*\'([^\']+)\'\s*,\s*\'([^\']+)\'\s*,\s*\'([^\']+)\'',
                content, re.DOTALL | re.IGNORECASE
            )
            for res_id, uid, name, email, phone, status in rep_matches:
                obs = {
                    "evidence_id": fid,
                    "captured_at": cap_at,
                    "system_id": "account_service",
                    "resource_id": res_id,
                    "status": "PRESENT" if status == "ACTIVE" else "ABSENT",
                    "has_pii": True if status == "ACTIVE" else False,
                    "emails": {email.lower()},
                    "uids": {uid},
                }
                self._add_observation(obs)

        if is_read_rep or "regional_replicas" in path or "reporting_replica" in path or "customer_data_failover" in path:
            records = re.findall(
                r'VALUES\s*\(\s*\'([^\']+)\'\s*,\s*\'([^\']+)\'\s*,\s*\'([^\']+)\'\s*,\s*\'(\{.*?\})\'',
                content
            )
            for res_id, sys_id, coll, r_json in records:
                try:
                    d = json.loads(r_json)
                    em = d.get("email") or ""
                    uid = d.get("user_id") or d.get("customer_reference") or d.get("subject_reference") or ""
                    doc = d.get("document", {})
                    if not em and isinstance(doc, dict):
                        em = doc.get("email", "")
                        uid = uid or doc.get("customer_reference", "") or doc.get("user_id", "")
                    
                    has_pii = bool(em or uid)
                    obs = {
                        "evidence_id": fid,
                        "captured_at": cap_at,
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "status": "PRESENT",
                        "has_pii": has_pii,
                        "emails": {em.lower()} if em else set(),
                        "uids": {uid} if uid else set(),
                    }
                    self._add_observation(obs)
                except:
                    pass

        if "customer_search_primary" in path:
            matches = re.findall(
                r'search_documents_primary.*?VALUES\s*\(\s*\'([^\']+)\'\s*,\s*\'([^\']+)\'\s*,\s*\'([^\']+)\'\s*,\s*\'([^\']+)\'',
                content, re.DOTALL | re.IGNORECASE
            )
            for res_id, name, email, src_acc in matches:
                obs = {
                    "evidence_id": fid,
                    "captured_at": cap_at,
                    "system_id": "search_service",
                    "resource_id": res_id,
                    "status": "PRESENT",
                    "has_pii": True,
                    "emails": {email.lower()},
                    "uids": set(),
                }
                self._add_observation(obs)

        if "customer_data_inventory" in path:
            bk_matches = re.findall(
                r'backup_restore_entries\s+VALUES\s*\(\s*\'([^\']+)\'\s*,\s*(NULL|\'[^\']*\')\s*,\s*(NULL|\'[^\']*\')\s*,\s*\'([^\']+)\'\s*,\s*\'([01])\'',
                content, re.IGNORECASE
            )
            for res_id, uid_raw, em_raw, arc, allowed in bk_matches:
                uid = uid_raw.strip("'") if uid_raw != "NULL" else ""
                em = em_raw.strip("'") if em_raw != "NULL" else ""
                obs = {
                    "evidence_id": fid,
                    "captured_at": cap_at,
                    "system_id": "backup_service",
                    "resource_id": res_id,
                    "status": "ACTIVE" if allowed == "1" else "BLOCKED",
                    "restore_allowed": (allowed == "1"),
                    "emails": {em.lower()} if em else set(),
                    "uids": {uid} if uid else set(),
                }
                self._add_observation(obs)

            conn_matches = re.findall(
                r'connector_subscriptions\s+VALUES\s*\(\s*\'([^\']+)\'\s*,\s*(NULL|\'[^\']*\')\s*,\s*(NULL|\'[^\']*\')\s*,\s*\'([^\']+)\'\s*,\s*\'([01])\'\s*,\s*\'([^\']+)\'',
                content, re.IGNORECASE
            )
            for res_id, uid_raw, em_raw, cname, enabled, last_stat in conn_matches:
                uid = uid_raw.strip("'") if uid_raw != "NULL" else ""
                em = em_raw.strip("'") if em_raw != "NULL" else ""
                obs = {
                    "evidence_id": fid,
                    "captured_at": cap_at,
                    "system_id": "integration_service",
                    "resource_id": res_id,
                    "status": "ACTIVE" if enabled == "1" else "DISABLED",
                    "enabled": (enabled == "1"),
                    "emails": {em.lower()} if em else set(),
                    "uids": {uid} if uid else set(),
                }
                self._add_observation(obs)

    def _parse_json(self, fid: str, path: str, cap_at: str) -> None:
        with open(path, mode="r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except:
                return

        if "service_exports" in data:
            exports = data["service_exports"]
            for item in exports.get("account_service", {}).get("profile_lookups", []):
                res_id = item.get("resource_id")
                sc = item.get("status_code", 404)
                prof = item.get("profile") or {}
                em = prof.get("email") or ""
                uid = prof.get("customer_reference") or ""
                obs = {
                    "evidence_id": fid,
                    "captured_at": cap_at,
                    "system_id": "account_service",
                    "resource_id": res_id,
                    "status": "ABSENT" if sc == 404 else "PRESENT",
                    "has_pii": bool(em or uid),
                    "emails": {em.lower()} if em else set(),
                    "uids": {uid} if uid else set(),
                }
                self._add_observation(obs)

            for item in exports.get("analytics_platform", {}).get("profiles", []):
                res_id = item.get("resource_id")
                em = item.get("email") or ""
                uid = item.get("customer_reference") or ""
                obs = {
                    "evidence_id": fid,
                    "captured_at": cap_at,
                    "system_id": "analytics_platform",
                    "resource_id": res_id,
                    "status": "PRESENT" if (em or uid) else "ANONYMIZED",
                    "has_pii": bool(em or uid),
                    "emails": {em.lower()} if em else set(),
                    "uids": {uid} if uid else set(),
                }
                self._add_observation(obs)

            for item in exports.get("search_service", {}).get("index_queries", []):
                res_id = item.get("resource_id")
                em = item.get("email") or item.get("query") or ""
                uid = item.get("customer_reference") or ""
                hits_obj = item.get("hits")
                if isinstance(hits_obj, dict):
                    hits = hits_obj.get("total", 0)
                    docs = hits_obj.get("documents", [])
                    if docs and isinstance(docs, list):
                        doc0 = docs[0]
                        if not em: em = doc0.get("email") or ""
                        if not uid: uid = doc0.get("customer_reference") or ""
                elif isinstance(hits_obj, int):
                    hits = hits_obj
                else:
                    hits = 0

                obs = {
                    "evidence_id": fid,
                    "captured_at": cap_at,
                    "system_id": "search_service",
                    "resource_id": res_id,
                    "status": "PRESENT" if hits > 0 else "ABSENT",
                    "has_pii": bool(hits > 0),
                    "emails": {em.lower()} if em else set(),
                    "uids": {uid} if uid else set(),
                }
                self._add_observation(obs)

            for item in exports.get("security_service", {}).get("audit_records", []):
                res_id = item.get("resource_id")
                uid = item.get("subject_reference") or ""
                obs = {
                    "evidence_id": fid,
                    "captured_at": cap_at,
                    "system_id": "security_service",
                    "resource_id": res_id,
                    "status": "PRESENT",
                    "emails": set(),
                    "uids": {uid} if uid else set(),
                }
                self._add_observation(obs)

            for item in exports.get("support_platform", {}).get("tickets", []):
                res_id = item.get("resource_id")
                em = item.get("requester_email") or ""
                uid = item.get("customer_reference") or ""
                obs = {
                    "evidence_id": fid,
                    "captured_at": cap_at,
                    "system_id": "support_platform",
                    "resource_id": res_id,
                    "status": "PRESENT" if (em or uid) else "REDACTED",
                    "has_pii": bool(em or uid),
                    "emails": {em.lower()} if em else set(),
                    "uids": {uid} if uid else set(),
                }
                self._add_observation(obs)

            for item in exports.get("export_service", {}).get("exports", []):
                res_id = item.get("resource_id")
                em = item.get("owner_email") or ""
                uid = item.get("customer_reference") or ""
                avail = item.get("available", True)
                obs = {
                    "evidence_id": fid,
                    "captured_at": cap_at,
                    "system_id": "export_service",
                    "resource_id": res_id,
                    "status": "PRESENT" if avail else "ABSENT",
                    "has_pii": True,
                    "emails": {em.lower()} if em else set(),
                    "uids": {uid} if uid else set(),
                }
                self._add_observation(obs)

            for item in exports.get("integration_service", {}).get("connectors", []):
                res_id = item.get("resource_id")
                em = item.get("customer_email") or ""
                uid = item.get("customer_reference") or ""
                en = item.get("enabled", False)
                obs = {
                    "evidence_id": fid,
                    "captured_at": cap_at,
                    "system_id": "integration_service",
                    "resource_id": res_id,
                    "status": "ACTIVE" if en else "DISABLED",
                    "emails": {em.lower()} if em else set(),
                    "uids": {uid} if uid else set(),
                }
                self._add_observation(obs)

            for item in exports.get("backup_service", {}).get("restore_entries", []):
                res_id = item.get("resource_id")
                em = item.get("customer_email") or ""
                uid = item.get("customer_reference") or ""
                ra = item.get("restore_allowed", False)
                obs = {
                    "evidence_id": fid,
                    "captured_at": cap_at,
                    "system_id": "backup_service",
                    "resource_id": res_id,
                    "status": "ACTIVE" if ra else "BLOCKED",
                    "emails": {em.lower()} if em else set(),
                    "uids": {uid} if uid else set(),
                }
                self._add_observation(obs)

        if "snapshots" in data:
            for snap in data["snapshots"]:
                store = snap.get("data_store")
                for r in snap.get("records", []):
                    res_id = r.get("resource_id")
                    if not res_id: continue
                    em = r.get("email") or ""
                    uid = r.get("subject_reference") or r.get("user_id") or ""
                    name = r.get("name") or ""
                    has_pii = bool(em or name or r.get("phone") or r.get("email_hash"))
                    status = "PRESENT"
                    if store == "identity_service":
                        status = "PRESENT" if has_pii else "REDACTED"
                    elif store == "analytics_platform":
                        status = "PRESENT" if has_pii else "ANONYMIZED"

                    obs = {
                        "evidence_id": fid,
                        "captured_at": cap_at,
                        "system_id": store,
                        "resource_id": res_id,
                        "status": status,
                        "has_pii": has_pii,
                        "emails": {em.lower()} if em else set(),
                        "uids": {uid} if uid else set(),
                    }
                    self._add_observation(obs)

        if "records" in data and isinstance(data["records"], list):
            for r in data.get("records", []):
                res_id = r.get("resource_id")
                if not res_id: continue
                prefix = res_id.split("_")[0]
                sys_id = r.get("system") or data.get("origin", "").split("_")[0] + "_service"
                if prefix == "export": sys_id = "export_service"
                elif prefix == "analytics": sys_id = "analytics_platform"
                elif prefix == "support": sys_id = "support_platform"
                elif prefix == "data" or "data_flow" in res_id: sys_id = "integration_service"
                elif prefix == "backup": sys_id = "backup_service"
                elif prefix == "search": sys_id = "search_service"
                elif prefix == "account": sys_id = "account_service"
                elif prefix == "audit" or "audit_record" in res_id: sys_id = "security_service"

                raw_sub = str(r.get("subject_reference") or r.get("owner_email") or r.get("email") or "")
                em = raw_sub.lower() if "@" in raw_sub else ""
                uid = raw_sub if raw_sub.startswith("user_") else str(r.get("user_id") or "")
                
                result = r.get("result")
                if not result:
                    if sys_id == "export_service":
                        result = "PRESENT" if r.get("download_available", True) else "ABSENT"
                    elif sys_id == "analytics_platform":
                        result = "PRESENT" if bool(em or uid) else "ANONYMIZED"
                    else:
                        result = "FOUND"

                has_pii = (result in ["FOUND", "IDENTIFIABLE", "ACTIVE", "PRESENT"]) and bool(em or uid or r.get("phone") or r.get("name"))
                if sys_id == "export_service" and result == "PRESENT":
                    has_pii = True

                obs = {
                    "evidence_id": fid,
                    "captured_at": cap_at,
                    "system_id": sys_id,
                    "resource_id": res_id,
                    "status": result,
                    "has_pii": has_pii,
                    "emails": {em} if em else set(),
                    "uids": {uid} if uid else set(),
                }
                self._add_observation(obs)

    def _parse_log_or_txt(self, fid: str, path: str, cap_at: str) -> None:
        with open(path, mode="r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        trace_data: Dict[str, Dict[str, Any]] = {}
        for line in lines:
            line_str = line.strip()
            # 1. Format: - 2026-10-01T12:00:00Z | account_service | account_146 | USER_PROFILE | NOT_FOUND | e.lindberg18@yahoo.com
            if line_str.startswith("- ") and "|" in line_str:
                parts = [p.strip() for p in line_str[2:].split("|")]
                if len(parts) >= 6:
                    ts, sys_id, res_id, rtype, result, ident = parts[:6]
                    obs = {
                        "evidence_id": fid,
                        "captured_at": cap_at,
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "status": result,
                        "has_pii": result in ["FOUND", "IDENTIFIABLE", "ACTIVE"],
                        "emails": {ident.lower()} if "@" in ident else set(),
                        "uids": {ident} if ident.startswith("user_") else set(),
                    }
                    self._add_observation(obs)
                continue

            # 2. Key-value distributed traces
            tr_m = re.search(r'trace_id=([a-zA-Z0-9_\-]+)', line_str)
            tr = tr_m.group(1) if tr_m else None

            if tr:
                tinfo = trace_data.setdefault(tr, {
                    "emails": set(), "uids": set(), "hashes": set(), "lines": []
                })
                for em in re.findall(r'[a-zA-Z0-9_\-\.]+@[a-zA-Z0-9_\-\.]+', line_str):
                    tinfo["emails"].add(em.lower())
                for u in re.findall(r'user_\d+', line_str):
                    tinfo["uids"].add(u)
                for h in re.findall(r'[a-f0-9]{64}', line_str):
                    tinfo["hashes"].add(h.lower())
                tinfo["lines"].append(line_str)
            else:
                res_m = re.search(r'resource_id=([a-z0-9_]+)', line_str)
                if res_m:
                    res_id = res_m.group(1)
                    prefix = res_id.split("_")[0]
                    sys_id = "account_service"
                    if prefix == "search": sys_id = "search_service"
                    elif prefix == "analytics": sys_id = "analytics_platform"
                    elif prefix == "support": sys_id = "support_platform"
                    elif prefix == "export": sys_id = "export_service"
                    elif prefix == "data" or "data_flow" in res_id: sys_id = "integration_service"
                    elif prefix == "backup": sys_id = "backup_service"
                    elif prefix == "audit" or "audit_record" in res_id: sys_id = "security_service"
                    elif prefix == "tombstone": sys_id = "identity_service"

                    em_m = re.search(r'[a-zA-Z0-9_\-\.]+@[a-zA-Z0-9_\-\.]+', line_str)
                    em = em_m.group(0).lower() if em_m else ""
                    u_m = re.search(r'user_\d+', line_str)
                    uid = u_m.group(0) if u_m else ""
                    h_m = re.search(r'[a-f0-9]{64}', line_str)
                    h = h_m.group(0).lower() if h_m else ""

                    self._add_observation({
                        "evidence_id": fid,
                        "captured_at": cap_at,
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "status": "ABSENT" if ("404" in line_str or "NOT_FOUND" in line_str or "rows=0" in line_str) else "PRESENT",
                        "has_pii": bool(em or uid),
                        "emails": {em} if em else set(),
                        "uids": {uid} if uid else set(),
                        "hashes": {h} if h else set(),
                    })

        # Second pass on trace_data
        for tr, tinfo in trace_data.items():
            emails = tinfo["emails"]
            uids = tinfo["uids"]
            hashes = tinfo["hashes"]
            for l in tinfo["lines"]:
                res_m = re.search(r'resource_id=([a-z0-9_]+)', l)
                if res_m:
                    res_id = res_m.group(1)
                    prefix = res_id.split("_")[0]
                    sys_id = "account_service"
                    if prefix == "search": sys_id = "search_service"
                    elif prefix == "analytics": sys_id = "analytics_platform"
                    elif prefix == "support": sys_id = "support_platform"
                    elif prefix == "export": sys_id = "export_service"
                    elif prefix == "data" or "data_flow" in res_id: sys_id = "integration_service"
                    elif prefix == "backup": sys_id = "backup_service"
                    elif prefix == "audit" or "audit_record" in res_id: sys_id = "security_service"
                    elif prefix == "tombstone": sys_id = "identity_service"

                    status = "PRESENT"
                    has_pii = False
                    if "404" in l or "rows=0" in l or "NOT_FOUND" in l:
                        status = "ABSENT"
                    elif "enabled=true" in l or "last_run=success" in l:
                        status = "ACTIVE"
                        has_pii = True
                    elif "enabled=false" in l or "last_delivery_status=stopped" in l:
                        status = "DISABLED"
                    elif "deletion_block=false" in l or "eligible=true" in l or "restore_allowed=true" in l:
                        status = "ACTIVE"
                        has_pii = True
                    elif "deletion_block=true" in l or "restore_allowed=false" in l:
                        status = "BLOCKED"
                    elif "result=hit" in l or "rows=1" in l:
                        status = "PRESENT"
                        has_pii = True

                    obs = {
                        "evidence_id": fid,
                        "captured_at": cap_at,
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "status": status,
                        "has_pii": has_pii,
                        "emails": set(emails),
                        "uids": set(uids),
                        "hashes": set(hashes),
                    }
                    self._add_observation(obs)

    def _parse_pdf(self, fid: str, path: str, cap_at: str) -> None:
        try:
            with open(path, "rb") as f:
                data = f.read()
            matches = list(re.finditer(rb'<<\s*/Filter\s*\[\s*/ASCII85Decode\s*/FlateDecode\s*\]\s*/Length\s*(\d+)\s*>>\s*stream[\r\n]+', data))
            all_text = []
            for m in matches:
                length = int(m.group(1))
                s_start = m.end()
                raw = data[s_start:s_start+length].strip()
                a85 = base64.a85decode(raw, adobe=True)
                decomp = zlib.decompress(a85)
                text_pieces = re.findall(rb'\(([^\)]+)\)', decomp)
                all_text.append(b' '.join(text_pieces).decode('latin1', errors='ignore'))
            text = " ".join(all_text)

            emails = set(re.findall(r'[a-zA-Z0-9_\-\.]+@[a-zA-Z0-9_\-\.]+', text))
            uids = set(re.findall(r'user_\d+', text))
            resources = set(re.findall(r'(?:account|analytics|backup|data_flow|export|search|security|support|tombstone|audit_record)_\d+', text))

            for res_id in resources:
                sys_id = "support_platform" if res_id.startswith("support_") else "security_service" if res_id.startswith("audit_record_") else "export_service"
                obs = {
                    "evidence_id": fid,
                    "captured_at": cap_at,
                    "system_id": sys_id,
                    "resource_id": res_id,
                    "status": "PRESENT",
                    "has_pii": bool(emails or uids),
                    "emails": set(e.lower() for e in emails),
                    "uids": uids,
                }
                self._add_observation(obs)
        except:
            pass

    def get_latest_observation(self, resource_id: str, cutoff_time: str) -> Optional[Dict[str, Any]]:
        obs_list = self.resource_observations.get(resource_id, [])
        valid_obs = [o for o in obs_list if o["captured_at"] <= cutoff_time]
        if not valid_obs:
            return None
        valid_obs.sort(key=lambda x: x["captured_at"], reverse=True)
        return valid_obs[0]
