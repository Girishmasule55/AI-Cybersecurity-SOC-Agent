from dataclasses import dataclass, field

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from app.schemas.soc import SecurityEventCreate
from app.services.rules import score_with_rules


@dataclass
class AnomalyDetector:
    model: IsolationForest = field(
        default_factory=lambda: IsolationForest(contamination=0.1, random_state=42)
    )
    trained: bool = False

    def _features(self, events: list[SecurityEventCreate]) -> pd.DataFrame:
        rows = []
        for event in events:
            rule_score, _ = score_with_rules(event)
            rows.append(
                {
                    "message_len": len(event.message),
                    "severity_score": rule_score,
                    "has_ip": int(bool(event.src_ip)),
                    "is_auth_event": int("login" in event.event_type.lower() or "auth" in event.source.lower()),
                }
            )
        return pd.DataFrame(rows)

    def fit(self, events: list[SecurityEventCreate]) -> None:
        if len(events) < 10:
            return
        self.model.fit(self._features(events))
        self.trained = True

    def anomaly_score(self, event: SecurityEventCreate) -> float:
        if not self.trained:
            rule_score, _ = score_with_rules(event)
            return rule_score

        features = self._features([event])
        decision = self.model.decision_function(features)[0]
        normalized = float(np.clip((0.25 - decision) * 100, 0, 100))
        rule_score, _ = score_with_rules(event)
        return max(rule_score, normalized)


detector = AnomalyDetector()
