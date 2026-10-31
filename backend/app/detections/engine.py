from __future__ import annotations

from typing import List, Tuple

from ..models import DetectionThresholds
from ..repository import SecurityRepository
from .rules import (
    AlertCandidate,
    detect_brute_force,
    detect_correlated_compromise_chains,
    detect_password_spraying,
    detect_privileged_account_changes,
    detect_suspicious_auth_sequences,
)


class DetectionEngine:
    def __init__(self, repo: SecurityRepository) -> None:
        self.repo = repo

    def evaluate_all(
        self,
        thresholds: DetectionThresholds | None = None,
        prune_uninvestigated_stale: bool = False,
    ) -> Tuple[int, int]:
        """Run all detection rules across stored events and persist alerts idempotently.

        Returns (new_alerts_created, total_active_alerts).
        """
        active_thresholds = thresholds or self.repo.get_thresholds()
        events = self.repo.get_all_events_chronological()

        bf_candidates = detect_brute_force(events, active_thresholds)
        ps_candidates = detect_password_spraying(events, active_thresholds)
        seq_candidates = detect_suspicious_auth_sequences(events, active_thresholds)
        priv_candidates = detect_privileged_account_changes(events, active_thresholds)
        corr_candidates = detect_correlated_compromise_chains(
            events, seq_candidates, active_thresholds
        )

        all_candidates: List[AlertCandidate] = [
            *bf_candidates,
            *ps_candidates,
            *seq_candidates,
            *priv_candidates,
            *corr_candidates,
        ]

        new_alerts_count = 0
        active_fingerprints: List[str] = []
        for candidate in all_candidates:
            active_fingerprints.append(candidate.alert_fingerprint)
            _, is_new = self.repo.upsert_alert(
                alert_fingerprint=candidate.alert_fingerprint,
                rule_id=candidate.rule_id,
                rule_name=candidate.rule_name,
                category=candidate.category,
                severity=candidate.severity,
                title=candidate.title,
                explanation=candidate.explanation,
                host=candidate.host,
                user=candidate.user,
                source_ip=candidate.source_ip,
                first_seen=candidate.first_seen,
                last_seen=candidate.last_seen,
                evidence_event_ids=candidate.evidence_event_ids,
                mitre_tactic=candidate.mitre_tactic,
                mitre_technique_id=candidate.mitre_technique_id,
                mitre_technique_name=candidate.mitre_technique_name,
                mitre_mapping_rationale=candidate.mitre_mapping_rationale,
                rule_limitations=candidate.rule_limitations,
                threshold_snapshot=candidate.threshold_snapshot,
            )
            if is_new:
                new_alerts_count += 1

        if prune_uninvestigated_stale:
            self.repo.prune_stale_uninvestigated_alerts(active_fingerprints)

        total_active = len(self.repo.list_alerts())
        return new_alerts_count, total_active
