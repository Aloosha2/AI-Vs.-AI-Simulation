"""Run local attack/defense rounds and score the toy simulation."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from agents.agent_logging import append_jsonl
from agents.blue_agent import BlueAgent, BlueRoundSummary
from agents.red_agent import AttackResult, RedAgent, RedRoundSummary, results_as_dict
from app import security
from app.server import app, reset_app_state


@dataclass
class RoundReport:
    name: str
    score: int
    red_summary: RedRoundSummary
    blue_summary: BlueRoundSummary


def score_round(results: list[AttackResult]) -> int:
    """Score defenses from 0 to 100 based on blocked red-agent attempts."""

    attempts = sum(result.attempts for result in results)
    blocked = sum(result.blocked for result in results)
    if attempts == 0:
        return 0
    return round((blocked / attempts) * 100)


class Judge:
    def __init__(self, log_file: str | Path = "logs/security.log") -> None:
        self.log_file = Path(log_file)
        self.round_report_file = self.log_file.parent / "round_reports.jsonl"
        self.red_log_file = self.log_file.parent / "red_agent.jsonl"
        self.blue_log_file = self.log_file.parent / "blue_agent.jsonl"

    def run(self) -> dict[str, Any]:
        security.configure_log_file(self.log_file)
        reset_app_state(clear_log=True)
        client = TestClient(app)

        baseline_red = RedAgent(client, log_file=self.red_log_file).run_loop("baseline")
        baseline_blue = BlueAgent(
            self.log_file,
            client=client,
            agent_log_file=self.blue_log_file,
        ).run_loop("baseline_review", baseline_red.results)
        baseline = self._build_round_report("baseline", baseline_red, baseline_blue)

        defended_red = RedAgent(client, log_file=self.red_log_file).run_loop("defended")
        defended_blue = BlueAgent(
            self.log_file,
            client=client,
            agent_log_file=self.blue_log_file,
        ).run_loop("defended_review", defended_red.results)
        defended = self._build_round_report("defended", defended_red, defended_blue)

        return {
            "baseline": self._serialize_round(baseline),
            "defended": self._serialize_round(defended),
            "improvement": defended.score - baseline.score,
        }

    def _build_round_report(
        self,
        name: str,
        red_summary: RedRoundSummary,
        blue_summary: BlueRoundSummary,
    ) -> RoundReport:
        report = RoundReport(
            name=name,
            score=score_round(red_summary.results),
            red_summary=red_summary,
            blue_summary=blue_summary,
        )
        append_jsonl(self.round_report_file, {"type": "round_summary", "payload": self._serialize_round(report)})
        return report

    @staticmethod
    def _serialize_round(report: RoundReport) -> dict[str, Any]:
        return {
            "name": report.name,
            "score": report.score,
            "red_results": results_as_dict(report.red_summary.results),
            "red_summary": {
                "agent": report.red_summary.agent,
                "round_name": report.red_summary.round_name,
                "observation": asdict(report.red_summary.observation),
                "strategies_run": report.red_summary.strategies_run,
                "findings": [asdict(finding) for finding in report.red_summary.findings],
            },
            "blue_summary": {
                "agent": report.blue_summary.agent,
                "round_name": report.blue_summary.round_name,
                "observation": asdict(report.blue_summary.observation),
                "findings": report.blue_summary.findings,
                "decision": asdict(report.blue_summary.decision),
                "validation_results": [
                    asdict(result) for result in report.blue_summary.validation_results
                ],
                "defenses_enabled": report.blue_summary.defenses_enabled,
            },
        }


def main() -> None:
    report = Judge().run()
    print("AI vs AI Local Cybersecurity Simulation")
    print(f"Baseline score: {report['baseline']['score']}/100")
    print(f"Defended score: {report['defended']['score']}/100")
    print(f"Improvement: {report['improvement']} points")
    print("\nDefended findings:")
    for finding in report["defended"]["blue_summary"]["findings"]:
        print(f"- {finding}")
    print("\nStructured logs:")
    print("- logs/red_agent.jsonl")
    print("- logs/blue_agent.jsonl")
    print("- logs/round_reports.jsonl")


if __name__ == "__main__":
    main()
