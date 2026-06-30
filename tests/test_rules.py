from app.schemas.soc import SecurityEventCreate
from app.services.rules import score_with_rules


def test_rule_score_detects_brute_force_admin_external_ip():
    event = SecurityEventCreate(
        source="auth.log",
        host="web-01",
        username="admin",
        src_ip="185.220.101.1",
        event_type="login_failed",
        severity="medium",
        message="Failed password for admin from 185.220.101.1 port 4444 ssh2",
    )

    score, reasons = score_with_rules(event)

    assert score >= 60
    assert "brute_force" in reasons
    assert "sensitive_account" in reasons
    assert "external_source" in reasons
