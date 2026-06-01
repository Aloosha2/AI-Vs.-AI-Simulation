"""Bounded local red-team simulation agent.

The agent never opens sockets or targets remote hosts. It accepts a FastAPI
TestClient and sends a small, fixed number of requests to the local toy app.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from time import perf_counter
from typing import Any, Protocol

from fastapi.testclient import TestClient
from httpx import Response

from agents.agent_logging import append_jsonl


SAFE_STRATEGIES = [
    "repeated_failed_logins",
    "oversized_payload",
    "burst_message_spam",
    "malformed_json",
    "endpoint_probing",
]


class LocalHttpClient(Protocol):
    def get(self, url: str, **kwargs: Any) -> Response:
        ...

    def post(self, url: str, **kwargs: Any) -> Response:
        ...

    def request(self, method: str, url: str, **kwargs: Any) -> Response:
        ...


@dataclass
class AttackResult:
    name: str
    attempts: int
    accepted: int
    blocked: int
    statuses: list[int]
    response_times_ms: list[float]

    @property
    def average_response_time_ms(self) -> float:
        if not self.response_times_ms:
            return 0.0
        return sum(self.response_times_ms) / len(self.response_times_ms)


@dataclass
class RedObservation:
    service_online: bool
    status_code: int
    defenses: dict[str, Any]


@dataclass
class RedFinding:
    strategy: str
    outcome: str
    evidence: dict[str, Any]


@dataclass
class RedRoundSummary:
    agent: str
    round_name: str
    observation: RedObservation
    strategies_run: list[str]
    findings: list[RedFinding]
    results: list[AttackResult]


class RedAgent:
    def __init__(
        self,
        client: LocalHttpClient | TestClient,
        max_attempts: int = 12,
        log_file: str | Path = "logs/red_agent.jsonl",
    ) -> None:
        self.client = client
        self.max_attempts = max_attempts
        self.log_file = Path(log_file)
        self.findings: list[RedFinding] = []
        self.last_summary: RedRoundSummary | None = None

    def run_all(self) -> list[AttackResult]:
        """Run every safe local attack scenario through the agent loop."""

        return self.run_loop("red_round").results

    def run_loop(
        self,
        round_name: str = "red_round",
        strategies: list[str] | None = None,
    ) -> RedRoundSummary:
        """Explicit red-agent loop: observe, choose, execute, record."""

        self.findings = []
        selected = strategies or SAFE_STRATEGIES.copy()
        observation = self.observe_service_state()
        token = self._get_token()
        results: list[AttackResult] = []
        pending = selected.copy()

        while pending:
            strategy = self.choose_attack_strategy(observation, pending)
            pending.remove(strategy)
            result = self.execute_bounded_attack(strategy, token)
            results.append(result)
            self.record_finding(result)

        summary = RedRoundSummary(
            agent="red",
            round_name=round_name,
            observation=observation,
            strategies_run=selected,
            findings=self.findings.copy(),
            results=results,
        )
        self.last_summary = summary
        self._log("round_summary", self._summary_as_dict(summary))
        return summary

    def observe_service_state(self) -> RedObservation:
        """Inspect only the local service health endpoint."""

        response = self.client.get("/health")
        defenses = response.json().get("defenses", {}) if response.status_code == 200 else {}
        observation = RedObservation(
            service_online=response.status_code == 200,
            status_code=response.status_code,
            defenses=defenses,
        )
        self._log("observe", asdict(observation))
        return observation

    def choose_attack_strategy(
        self,
        observation: RedObservation,
        pending_strategies: list[str],
    ) -> str:
        """Pick the next attack from a fixed, safe local set."""

        if not observation.service_online:
            strategy = "endpoint_probing"
        else:
            strategy = pending_strategies[0]
        self._log("choose_strategy", {"strategy": strategy, "safe_set": SAFE_STRATEGIES})
        return strategy

    def execute_bounded_attack(self, strategy: str, token: str) -> AttackResult:
        """Execute one bounded local scenario by name."""

        self._log("execute_attack", {"strategy": strategy, "max_attempts": self.max_attempts})
        if strategy == "repeated_failed_logins":
            return self.repeated_failed_logins()
        if strategy == "oversized_payload":
            return self.oversized_payload(token)
        if strategy == "burst_message_spam":
            return self.burst_message_spam(token)
        if strategy == "malformed_json":
            return self.malformed_json()
        if strategy == "endpoint_probing":
            return self.endpoint_probing()
        raise ValueError(f"unknown red-team strategy: {strategy}")

    def record_finding(self, result: AttackResult) -> RedFinding:
        """Convert raw request outcomes into a presentation-friendly finding."""

        if result.accepted > 0 and result.blocked == 0:
            outcome = "attack accepted by service"
        elif result.accepted > 0:
            outcome = "attack partially mitigated"
        else:
            outcome = "attack blocked"

        finding = RedFinding(
            strategy=result.name,
            outcome=outcome,
            evidence={
                "attempts": result.attempts,
                "accepted": result.accepted,
                "blocked": result.blocked,
                "statuses": result.statuses,
                "average_response_time_ms": round(result.average_response_time_ms, 2),
            },
        )
        self.findings.append(finding)
        self._log("record_finding", asdict(finding))
        return finding

    def _legacy_order(self) -> list[AttackResult]:
        token = self._get_token()
        return [
            self.repeated_failed_logins(),
            self.oversized_payload(token),
            self.burst_message_spam(token),
            self.malformed_json(),
            self.endpoint_probing(),
        ]

    def repeated_failed_logins(self) -> AttackResult:
        statuses: list[int] = []
        timings: list[float] = []
        for index in range(min(6, self.max_attempts)):
            response, elapsed_ms = self._timed_request(
                "POST",
                "/login",
                json={"username": "alice", "password": f"wrong-{index}"},
            )
            statuses.append(response.status_code)
            timings.append(elapsed_ms)
        return self._result("repeated_failed_logins", statuses, timings, accepted_statuses={401})

    def burst_message_spam(self, token: str) -> AttackResult:
        statuses: list[int] = []
        timings: list[float] = []
        for index in range(min(10, self.max_attempts)):
            response, elapsed_ms = self._timed_request(
                "POST",
                "/send_message",
                json={
                    "token": token,
                    "recipient": "bob",
                    "content": f"spam message {index}",
                },
            )
            statuses.append(response.status_code)
            timings.append(elapsed_ms)
        return self._result("burst_message_spam", statuses, timings, accepted_statuses={200})

    def oversized_payload(self, token: str) -> AttackResult:
        payload = "A" * 5_000
        response, elapsed_ms = self._timed_request(
            "POST",
            "/send_message",
            json={"token": token, "recipient": "bob", "content": payload},
        )
        return self._result(
            "oversized_payload",
            [response.status_code],
            [elapsed_ms],
            accepted_statuses={200},
        )

    def malformed_json(self) -> AttackResult:
        response, elapsed_ms = self._timed_request(
            "POST",
            "/login",
            content='{"username": "alice", "password": ',
            headers={"content-type": "application/json"},
        )
        return self._result("malformed_json", [response.status_code], [elapsed_ms], accepted_statuses={422})

    def endpoint_probing(self) -> AttackResult:
        statuses: list[int] = []
        timings: list[float] = []
        for path in ["/admin", "/debug", "/metrics", "/.env"]:
            response, elapsed_ms = self._timed_request("GET", path)
            statuses.append(response.status_code)
            timings.append(elapsed_ms)
        return self._result("endpoint_probing", statuses, timings, accepted_statuses={404})

    def _get_token(self) -> str:
        response = self.client.post(
            "/login",
            json={"username": "alice", "password": "wonderland"},
        )
        response.raise_for_status()
        return response.json()["token"]

    def _timed_request(self, method: str, path: str, **kwargs: Any) -> tuple[Response, float]:
        start = perf_counter()
        response = self.client.request(method, path, **kwargs)
        elapsed_ms = (perf_counter() - start) * 1000
        return response, elapsed_ms

    def _log(self, step: str, payload: dict[str, Any]) -> None:
        append_jsonl(self.log_file, {"agent": "red", "step": step, "payload": payload})

    @staticmethod
    def _summary_as_dict(summary: RedRoundSummary) -> dict[str, Any]:
        return {
            "agent": summary.agent,
            "round_name": summary.round_name,
            "observation": asdict(summary.observation),
            "strategies_run": summary.strategies_run,
            "findings": [asdict(finding) for finding in summary.findings],
            "results": results_as_dict(summary.results),
        }

    @staticmethod
    def _result(
        name: str,
        statuses: list[int],
        timings: list[float],
        accepted_statuses: set[int],
    ) -> AttackResult:
        accepted = sum(1 for status in statuses if status in accepted_statuses)
        blocked = len(statuses) - accepted
        return AttackResult(
            name=name,
            attempts=len(statuses),
            accepted=accepted,
            blocked=blocked,
            statuses=statuses,
            response_times_ms=timings,
        )


def results_as_dict(results: list[AttackResult]) -> list[dict[str, Any]]:
    return [asdict(result) for result in results]
