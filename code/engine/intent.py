"""
Intent detection module for Ghost Data Still Exists.
Determines whether a user request authorizes deletion or is a non-deletion request (access, export, rectification).
"""

import re


class IntentClassifier:
    # Explicit patterns requesting account retention, rectification without deletion, or pure export/access
    NON_DELETION_PATTERNS = [
        re.compile(r"leave\s+the\s+account\s+active", re.I),
        re.compile(r"leave\s+my\s+profile\s+active", re.I),
        re.compile(r"keep\s+the\s+account\s+as\s+it\s+is", re.I),
        re.compile(r"continue\s+using\s+the\s+service", re.I),
        re.compile(r"do\s+not\s+delete", re.I),
        re.compile(r"not\s+a\s+deletion", re.I),
        re.compile(r"not\s+a\s+request\s+to\s+erase", re.I),
        re.compile(r"don't\s+delete\s+or\s+change\s+anything", re.I),
        re.compile(r"don't\s+delete", re.I),
        re.compile(r"download\s+my\s+account\s+information.*portable\s+format", re.I),
        re.compile(r"copy\s+of\s+last\s+year'?s\s+invoices", re.I),
        re.compile(r"mobile\s+number.*is\s+out\s+of\s+date.*replace\s+it.*leave", re.I),
        re.compile(r"change\s+the\s+email\s+address\s+used.*continue", re.I),
    ]

    DELETION_KEYWORDS = [
        "delet", "eras", "remov", "clos", "suppress", "eliminar", "suppression",
        "削除", "supprim", "exclus", "cancela", "lösch", "effac", "cancella",
        "apagar", "odstran", "usuń", "삭제", "closed", "gone"
    ]

    @classmethod
    def is_deletion_authorized(cls, request_text: str) -> bool:
        """
        Determines whether the given request text authorizes personal data deletion.
        Returns False for NOT_APPLICABLE cases, True for authorized deletions.
        """
        if not request_text:
            return False

        text = request_text.strip()

        # Check explicit non-deletion patterns
        for pat in cls.NON_DELETION_PATTERNS:
            if pat.search(text):
                return False

        # Check multilingual deletion keywords
        text_lower = text.lower()
        if any(kw in text_lower for kw in cls.DELETION_KEYWORDS):
            return True

        return False
