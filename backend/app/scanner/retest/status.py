from enum import Enum

class RetestVerdict(str, Enum):
    FIXED = "FIXED"
    STILL_VULNERABLE = "STILL_VULNERABLE"
    INCONCLUSIVE = "INCONCLUSIVE"

class FindingStatus(str, Enum):
    OPEN = "OPEN"
    VERIFIED_FIXED = "VERIFIED_FIXED"
    REQUIRES_REVIEW = "REQUIRES_REVIEW"
