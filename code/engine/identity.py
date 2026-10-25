"""
Identity resolution module for Ghost Data Still Exists.
Resolves users' current and historical identifiers using user_identities.csv and user_audit_log.csv.
"""

import csv
import os
from typing import Dict, Set, Optional, Any


class IdentityResolver:
    def __init__(self, dataset_dir: str):
        self.dataset_dir = dataset_dir
        self.user_by_id: Dict[str, Dict[str, Any]] = {}
        self.email_to_uid: Dict[str, str] = {}
        self.hash_to_uid: Dict[str, str] = {}
        self.phone_to_uid: Dict[str, str] = {}
        self.uid_to_all_emails: Dict[str, Set[str]] = {}
        self.uid_to_all_phones: Dict[str, Set[str]] = {}
        self.uid_to_all_names: Dict[str, Set[str]] = {}
        self.uid_to_hashes: Dict[str, Set[str]] = {}
        self._load_data()

    def _load_data(self) -> None:
        identities_path = os.path.join(self.dataset_dir, "user_identities.csv")
        audit_path = os.path.join(self.dataset_dir, "user_audit_log.csv")

        # Load current identities
        with open(identities_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row["user_id"].strip()
                self.user_by_id[uid] = row
                self.uid_to_all_emails[uid] = set()
                self.uid_to_all_phones[uid] = set()
                self.uid_to_all_names[uid] = set()
                self.uid_to_hashes[uid] = set()

                if row.get("email"):
                    em = row["email"].strip().lower()
                    self.email_to_uid[em] = uid
                    self.uid_to_all_emails[uid].add(em)
                if row.get("phone"):
                    ph = row["phone"].strip()
                    self.phone_to_uid[ph] = uid
                    self.uid_to_all_phones[uid].add(ph)
                if row.get("name"):
                    self.uid_to_all_names[uid].add(row["name"].strip())
                if row.get("email_hash"):
                    h = row["email_hash"].strip().lower()
                    self.hash_to_uid[h] = uid
                    self.uid_to_hashes[uid].add(h)

        # Load historical changes from audit log
        if os.path.exists(audit_path):
            with open(audit_path, mode="r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    uid = row["user_id"].strip()
                    field = row["field_name"].strip()
                    old_val = row["old_value"].strip() if row.get("old_value") else ""
                    new_val = row["new_value"].strip() if row.get("new_value") else ""

                    if uid not in self.user_by_id:
                        continue

                    if field == "email":
                        if old_val:
                            em = old_val.lower()
                            self.email_to_uid[em] = uid
                            self.uid_to_all_emails[uid].add(em)
                        if new_val:
                            em = new_val.lower()
                            self.email_to_uid[em] = uid
                            self.uid_to_all_emails[uid].add(em)
                    elif field == "phone":
                        if old_val:
                            self.phone_to_uid[old_val] = uid
                            self.uid_to_all_phones[uid].add(old_val)
                        if new_val:
                            self.phone_to_uid[new_val] = uid
                            self.uid_to_all_phones[uid].add(new_val)
                    elif field == "name":
                        if old_val:
                            self.uid_to_all_names[uid].add(old_val)
                        if new_val:
                            self.uid_to_all_names[uid].add(new_val)
                    elif field == "email_hash":
                        if old_val:
                            h = old_val.lower()
                            self.hash_to_uid[h] = uid
                            self.uid_to_hashes[uid].add(h)
                        if new_val:
                            h = new_val.lower()
                            self.hash_to_uid[h] = uid
                            self.uid_to_hashes[uid].add(h)

    def resolve_email(self, email: str) -> Optional[str]:
        if not email:
            return None
        return self.email_to_uid.get(email.strip().lower())

    def get_user_footprint(self, uid: str) -> Dict[str, Any]:
        """Returns all current and historical identifiers associated with a user."""
        return {
            "user_id": uid,
            "emails": self.uid_to_all_emails.get(uid, set()),
            "phones": self.uid_to_all_phones.get(uid, set()),
            "names": self.uid_to_all_names.get(uid, set()),
            "hashes": self.uid_to_hashes.get(uid, set()),
        }
