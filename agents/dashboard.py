"""Rich terminal dashboard for the local AI-vs-AI simulation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from time import sleep
from typing import Any

from fastapi.testclient import TestClient
from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from agents.blue_agent import BlueAgent
from agents.judge import score_round
from agents.red_agent import AttackResult, RedAgent
from app import security
from app.server import app, reset_app_state


@dataclass
class DashboardState:
    phase: str = "BOOTING LOCAL CYBER RANGE"
    service_health: str = "unknown"
    baseline_results: list[AttackResult] = field(default_factory=list)
    defended_results: list[AttackResult] = field(default_factory=list)
    event_feed: list[str] = field(default_factory=list)
    defenses: dict[str, Any] = field(default_factory=dict)
    findings: list[str] = field(default_factory=list)


class CyberDashboard:
    """Animated local terminal demo using the existing simulation agents."""

    def __init__(self, log_file: str | Path = "logs/security.log", delay: float = 0.7) -> None:
        self.log_file = Path(log_file)
        self.delay = delay
        self.console = Console()
        self.state = DashboardState()

    def run(self) -> None:
        security.configure_log_file(self.log_file)
        reset_app_state(clear_log=True)
        client = TestClient(app)
        blue = BlueAgent(self.log_file)

        with Live(self._render(), console=self.console, refresh_per_second=8, screen=True) as live:
            self._push("SYSTEM: local-only simulation initialized")
            self._refresh_health(client, live)

            self.state.phase = "ROUND 1: RED AGENT BASELINE ATTACK"
            baseline_red = RedAgent(client)
            self._run_red_actions(baseline_red, self.state.baseline_results, live)

            self.state.phase = "BLUE AGENT LOG ANALYSIS"
            summary = blue.analyze_logs()
            self.state.findings = summary.suspicious_findings
            for finding in summary.suspicious_findings:
                self._push(f"BLUE AGENT: {finding}")
                self._tick(live)

            self._push("BLUE AGENT: enabled rate limiter")
            self._push("BLUE AGENT: enabled account lockout")
            self._push("BLUE AGENT: enabled payload validation")
            self._push("BLUE AGENT: enabled safer error responses")
            self.state.defenses = blue.apply_defenses()
            self._tick(live)

            self.state.phase = "ROUND 2: DEFENDED SERVICE UNDER ATTACK"
            defended_red = RedAgent(client)
            self._run_red_actions(defended_red, self.state.defended_results, live)
            self._refresh_health(client, live)

            baseline_score = score_round(self.state.baseline_results)
            defended_score = score_round(self.state.defended_results)
            if defended_score > baseline_score:
                self._push("JUDGE: attack partially mitigated")
            else:
                self._push("JUDGE: defenses did not improve mitigation")
            self.state.phase = "JUDGE: FINAL SCOREBOARD"
            self._tick(live, pause=2.5)

    def _run_red_actions(
        self,
        red: RedAgent,
        target: list[AttackResult],
        live: Live,
    ) -> None:
        token = red._get_token()
        actions = [
            ("RED AGENT: burst login attack", red.repeated_failed_logins),
            ("RED AGENT: oversized payload injection", lambda: red.oversized_payload(token)),
            ("RED AGENT: message spam burst", lambda: red.burst_message_spam(token)),
            ("RED AGENT: malformed JSON probe", red.malformed_json),
            ("RED AGENT: endpoint reconnaissance", red.endpoint_probing),
        ]
        for label, action in actions:
            self._push(label)
            result = action()
            target.append(result)
            blocked_note = f"JUDGE: {result.name} blocked {result.blocked}/{result.attempts}"
            self._push(blocked_note)
            self._tick(live)

    def _refresh_health(self, client: TestClient, live: Live) -> None:
        response = client.get("/health")
        self.state.service_health = "online" if response.status_code == 200 else "degraded"
        self.state.defenses = response.json().get("defenses", {})
        self._push(f"SERVICE: health={self.state.service_health}")
        self._tick(live)

    def _push(self, message: str) -> None:
        self.state.event_feed.append(message)
        self.state.event_feed = self.state.event_feed[-12:]

    def _tick(self, live: Live, pause: float | None = None) -> None:
        live.update(self._render())
        sleep(self.delay if pause is None else pause)

    def _render(self) -> Panel:
        title = Text("AI vs AI LOCAL CYBER RANGE", style="bold bright_cyan")
        subtitle = Text(self.state.phase, style="bold magenta")
        return Panel(
            Group(
                Align.center(title),
                Align.center(subtitle),
                self._status_table(),
                self._scoreboard(),
                self._event_feed(),
            ),
            border_style="bright_cyan",
            padding=(1, 2),
        )

    def _status_table(self) -> Table:
        table = Table.grid(expand=True)
        table.add_column(ratio=1)
        table.add_column(ratio=1)
        enabled = [name for name, value in self.state.defenses.items() if name.endswith("_enabled") and value]
        defense_text = ", ".join(enabled) if enabled else "none"
        table.add_row(
            Panel(f"[bold green]{self.state.service_health}[/]", title="Service Health", border_style="green"),
            Panel(f"[bright_magenta]{defense_text}[/]", title="Defense Actions Enabled", border_style="magenta"),
        )
        return table

    def _scoreboard(self) -> Table:
        table = Table(title="Scoreboard", border_style="bright_blue", expand=True)
        table.add_column("Metric", style="cyan")
        table.add_column("Baseline", justify="right")
        table.add_column("Defended", justify="right")
        table.add_row("Attack success rate", self._attack_rate(self.state.baseline_results), self._attack_rate(self.state.defended_results))
        table.add_row("Blocked requests", self._blocked(self.state.baseline_results), self._blocked(self.state.defended_results))
        table.add_row("Average response time", self._avg_time(self.state.baseline_results), self._avg_time(self.state.defended_results))
        table.add_row("Service availability", self._availability(self.state.baseline_results), self._availability(self.state.defended_results))
        table.add_row("Judge score", f"{score_round(self.state.baseline_results)}/100", f"{score_round(self.state.defended_results)}/100")
        return table

    def _event_feed(self) -> Panel:
        lines = "\n".join(f"[bright_green]>[/] {event}" for event in self.state.event_feed)
        return Panel(lines or "waiting for events", title="Event Feed", border_style="bright_green")

    @staticmethod
    def _attack_rate(results: list[AttackResult]) -> str:
        attempts = sum(result.attempts for result in results)
        accepted = sum(result.accepted for result in results)
        if attempts == 0:
            return "0.0%"
        return f"{(accepted / attempts) * 100:.1f}%"

    @staticmethod
    def _blocked(results: list[AttackResult]) -> str:
        return str(sum(result.blocked for result in results))

    @staticmethod
    def _avg_time(results: list[AttackResult]) -> str:
        timings = [timing for result in results for timing in result.response_times_ms]
        if not timings:
            return "0.00 ms"
        return f"{sum(timings) / len(timings):.2f} ms"

    @staticmethod
    def _availability(results: list[AttackResult]) -> str:
        statuses = [status for result in results for status in result.statuses]
        if not statuses:
            return "100.0%"
        available = sum(1 for status in statuses if status < 500)
        return f"{(available / len(statuses)) * 100:.1f}%"


def main() -> None:
    CyberDashboard().run()


if __name__ == "__main__":
    main()
