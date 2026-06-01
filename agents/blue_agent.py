"""Blue-team agent that analyzes local logs and applies toy defenses."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from agents.agent_logging import append_jsonl
from agents.red_agent import AttackResult, LocalHttpClient, results_as_dict
from app import security


@dataclass
class BlueSummary:
    total_events: int
    event_counts: dict[str, int]
    suspicious_findings: list[str]
    defenses_enabled: dict[str, Any]


@dataclass
class BlueObservation:
    total_events: int
    event_counts: dict[str, int]
    recent_attack_results: list[dict[str, Any]]
    defenses_enabled: dict[str, Any]


@dataclass
class DefenseDecision:
    action: str
    reason: str


@dataclass
class ValidationResult:
    name: str
    passed: bool
    details: dict[str, Any]


@dataclass
class BlueRoundSummary:
    agent: str
    round_name: str
    observation: BlueObservation
    findings: list[str]
    decision: DefenseDecision
    validation_results: list[ValidationResult]
    defenses_enabled: dict[str, Any]


class BlueAgent:
    def __init__(
        self,
        log_file: str | Path | None = None,
        client: LocalHttpClient | TestClient | None = None,
        agent_log_file: str | Path = "logs/blue_agent.jsonl",
    ) -> None:
        self.log_file = Path(log_file) if log_file is not None else None
        self.client = client
        self.agent_log_file = Path(agent_log_file)
        self.last_summary: BlueRoundSummary | None = None

    def analyze_logs(self) -> BlueSummary:
        events = security.read_events(self.log_file)
        counts = Counter(event.get("event_type", "unknown") for event in events)
        findings = self._findings(counts)
        return BlueSummary(
            total_events=len(events),
            event_counts=dict(counts),
            suspicious_findings=findings,
            defenses_enabled=security.config_snapshot(),
        )

    def run_loop(
        self,
        round_name: str,
        recent_attack_results: list[AttackResult] | None = None,
    ) -> BlueRoundSummary:
        """Explicit blue-agent loop: observe, identify, decide, defend, validate."""

        observation = self.observe(recent_attack_results or [])
        findings = self.identify_vulnerabilities(observation)
        decision = self.choose_defense_action(findings, observation)
        defenses = self.apply_defense_action(decision)
        validation_results = self.rerun_validation_tests()

        summary = BlueRoundSummary(
            agent="blue",
            round_name=round_name,
            observation=observation,
            findings=findings,
            decision=decision,
            validation_results=validation_results,
            defenses_enabled=defenses,
        )
        self.last_summary = summary
        self._log("round_summary", self._summary_as_dict(summary))
        return summary

    def observe(self, recent_attack_results: list[AttackResult]) -> BlueObservation:
        """Read local logs and recent red-agent outcomes."""

        events = security.read_events(self.log_file)
        counts = Counter(event.get("event_type", "unknown") for event in events)
        observation = BlueObservation(
            total_events=len(events),
            event_counts=dict(counts),
            recent_attack_results=results_as_dict(recent_attack_results),
            defenses_enabled=security.config_snapshot(),
        )
        self._log("observe", asdict(observation))
        return observation

    def identify_vulnerabilities(self, observation: BlueObservation) -> list[str]:
        findings = self._findings(Counter(observation.event_counts))

        accepted_attacks = [
            result
            for result in observation.recent_attack_results
            if result.get("accepted", 0) > 0
        ]
        if accepted_attacks:
            names = ", ".join(result["name"] for result in accepted_attacks)
            findings.append(f"Recent red-agent results show accepted attacks: {names}.")

        self._log("identify", {"findings": findings})
        return findings

    def choose_defense_action(
        self,
        findings: list[str],
        observation: BlueObservation,
    ) -> DefenseDecision:
        if all(
            observation.defenses_enabled.get(key, False)
            for key in [
                "rate_limit_enabled",
                "account_lockout_enabled",
                "payload_validation_enabled",
                "safer_errors_enabled",
            ]
        ):
            decision = DefenseDecision(
                action="no_change",
                reason="Core defenses are already enabled.",
            )
        elif findings and findings != ["No suspicious behavior detected yet."]:
            decision = DefenseDecision(
                action="enable_standard_defenses",
                reason="Suspicious behavior or accepted attacks were observed.",
            )
        else:
            decision = DefenseDecision(
                action="monitor_only",
                reason="No suspicious behavior was detected.",
            )

        self._log("choose_defense", asdict(decision))
        return decision

    def apply_defense_action(self, decision: DefenseDecision) -> dict[str, Any]:
        if decision.action == "enable_standard_defenses":
            defenses = self.apply_defenses()
        else:
            defenses = security.config_snapshot()
            security.log_event("defense_decision", action=decision.action, reason=decision.reason)

        self._log("apply_defense", {"action": decision.action, "defenses": defenses})
        return defenses

    def apply_defenses(self) -> dict[str, Any]:
        """Enable the standard defensive profile and return the new settings."""

        enabled = security.apply_defense_profile("standard")
        security.log_event("defenses_enabled", profile="standard", settings=security.config_snapshot())
        return enabled.__dict__.copy()

    def rerun_validation_tests(self) -> list[ValidationResult]:
        """Run lightweight local checks that confirm defenses changed behavior."""

        if self.client is None:
            result = ValidationResult(
                name="validation_skipped",
                passed=False,
                details={"reason": "BlueAgent was not given a local TestClient."},
            )
            self._log("validate", {"results": [asdict(result)]})
            return [result]

        # Validation is a separate blue-team check, so it starts with fresh
        # rate-limit buckets while leaving accounts, messages, and defenses.
        security.state.request_history.clear()
        results = [
            self._validate_health(),
            self._validate_oversized_payload_blocked(),
            self._validate_account_lockout(),
        ]
        self._log("validate", {"results": [asdict(result) for result in results]})
        return results

    def _validate_health(self) -> ValidationResult:
        response = self.client.get("/health")
        return ValidationResult(
            name="service_health",
            passed=response.status_code == 200,
            details={"status_code": response.status_code},
        )

    def _validate_oversized_payload_blocked(self) -> ValidationResult:
        login = self.client.post("/login", json={"username": "bob", "password": "builder"})
        if login.status_code != 200:
            return ValidationResult(
                name="oversized_payload_blocked",
                passed=False,
                details={"login_status_code": login.status_code},
            )

        response = self.client.post(
            "/send_message",
            json={
                "token": login.json()["token"],
                "recipient": "alice",
                "content": "B" * 5_000,
            },
        )
        return ValidationResult(
            name="oversized_payload_blocked",
            passed=response.status_code == 413,
            details={"status_code": response.status_code},
        )

    def _validate_account_lockout(self) -> ValidationResult:
        username = "validation_user"
        statuses = [
            self.client.post("/login", json={"username": username, "password": "bad"}).status_code
            for _ in range(security.config.max_failed_logins + 1)
        ]
        return ValidationResult(
            name="account_lockout",
            passed=statuses[-1] == 423,
            details={"statuses": statuses},
        )

    @staticmethod
    def _findings(counts: Counter[str]) -> list[str]:
        findings: list[str] = []
        if counts["failed_login"] >= 3:
            findings.append("Repeated failed logins indicate credential guessing.")
        if counts["message_sent"] >= 8:
            findings.append("Burst message activity indicates spam or flooding.")
        if counts["payload_rejected"] > 0:
            findings.append("Oversized or invalid payloads were attempted.")
        if counts["malformed_request"] > 0:
            findings.append("Malformed JSON or schema probing was observed.")
        if counts["endpoint_probe"] > 0:
            findings.append("Unknown endpoint probing was observed.")
        if not findings:
            findings.append("No suspicious behavior detected yet.")
        return findings

    def _log(self, step: str, payload: dict[str, Any]) -> None:
        append_jsonl(self.agent_log_file, {"agent": "blue", "step": step, "payload": payload})

    @staticmethod
    def _summary_as_dict(summary: BlueRoundSummary) -> dict[str, Any]:
        return {
            "agent": summary.agent,
            "round_name": summary.round_name,
            "observation": asdict(summary.observation),
            "findings": summary.findings,
            "decision": asdict(summary.decision),
            "validation_results": [asdict(result) for result in summary.validation_results],
            "defenses_enabled": summary.defenses_enabled,
        }
