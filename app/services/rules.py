import re

from app.schemas.soc import SecurityEventCreate


SUSPICIOUS_PATTERNS = {
    "brute_force": re.compile(r"failed password|invalid user|authentication failure", re.I),
    "privilege_escalation": re.compile(r"sudo|su root|privilege|administrator", re.I),
    "malware": re.compile(r"mimikatz|ransomware|trojan|payload|powershell encodedcommand", re.I),
    "data_exfiltration": re.compile(r"exfil|large upload|scp|rsync|s3 copy", re.I),
}

SEVERITY_WEIGHT = {
    "low": 10,
    "medium": 30,
    "high": 55,
    "critical": 75,
}


def score_with_rules(event: SecurityEventCreate) -> tuple[float, list[str]]:
    score = SEVERITY_WEIGHT.get(event.severity.lower(), 10)
    reasons: list[str] = []

    for name, pattern in SUSPICIOUS_PATTERNS.items():
        if pattern.search(event.message):
            score += 20
            reasons.append(name)

    if event.username and event.username.lower() in {"root", "admin", "administrator"}:
        score += 10
        reasons.append("sensitive_account")

    if event.src_ip and not event.src_ip.startswith(("10.", "172.16.", "192.168.")):
        score += 5
        reasons.append("external_source")

    return min(float(score), 100.0), reasons
