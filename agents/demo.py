"""Reliable classroom demo mode for the local AI-vs-AI simulation."""

from __future__ import annotations

import argparse
from contextlib import AbstractContextManager
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import socket
import threading
import time
from typing import Any

import httpx
from fastapi.testclient import TestClient
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import uvicorn

from agents.agent_logging import append_jsonl
from agents.blue_agent import BlueAgent, BlueRoundSummary
from agents.judge import score_round
from agents.red_agent import AttackResult, RedAgent, RedRoundSummary
from app import security
from app.server import app, reset_app_state


PRESENTATION_PAUSE_SECONDS = 2.0
RESULTS_DIR = Path("results")
FIGURES_DIR = RESULTS_DIR / "figures"


class LocalUvicornServer(AbstractContextManager["LocalUvicornServer"]):
    """Start the FastAPI app on localhost for the duration of the demo."""

    def __init__(self) -> None:
        self.host = "127.0.0.1"
        self.port = _find_free_port()
        self.base_url = f"http://{self.host}:{self.port}"
        config = uvicorn.Config(
            app,
            host=self.host,
            port=self.port,
            log_level="warning",
            access_log=False,
        )
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self) -> "LocalUvicornServer":
        self.thread.start()
        self._wait_until_ready()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=5)

    def _wait_until_ready(self) -> None:
        deadline = time.monotonic() + 10
        with httpx.Client(base_url=self.base_url, timeout=1.0) as client:
            while time.monotonic() < deadline:
                try:
                    response = client.get("/health")
                    if response.status_code == 200:
                        return
                except httpx.HTTPError:
                    time.sleep(0.1)
        raise RuntimeError("local demo server did not become ready")


def run_demo(use_live_server: bool = True, presentation: bool = False) -> dict[str, Any]:
    """Run the full before/after demo in less than 60 seconds."""

    paths = _prepare_demo_logs()
    reset_app_state(clear_log=True)
    security.configure_log_file(paths["security"])

    console = Console()
    console.print(Panel.fit("AI vs AI Local Demo Mode", style="bold bright_cyan"))
    _phase(
        console,
        1,
        "Starting the Toy Communication Channel",
        "This server represents a tiny chat system with login and message endpoints. "
        "It starts intentionally weak so we can see what the defender improves.",
        presentation,
    )

    if use_live_server:
        with LocalUvicornServer() as server:
            console.print(f"[green]SERVER[/] started on {server.base_url} local-only")
            with httpx.Client(base_url=server.base_url, timeout=5.0) as client:
                vulnerable, blue_summary, defended = _run_demo_rounds(
                    console,
                    client,
                    paths,
                    presentation,
                )
    else:
        console.print("[green]SERVER[/] using in-process local test server")
        vulnerable, blue_summary, defended = _run_demo_rounds(
            console,
            TestClient(app),
            paths,
            presentation,
        )

    report = {
        "vulnerable": _metrics(vulnerable.results),
        "defended": _metrics(defended.results),
        "blue_decision": blue_summary.decision.action,
        "blue_findings": [_human_finding(finding) for finding in blue_summary.findings],
        "defenses_enabled": blue_summary.defenses_enabled,
        "validation_passed": all(result.passed for result in blue_summary.validation_results),
        "logs": {key: str(path) for key, path in paths.items()},
    }
    append_jsonl(paths["rounds"], {"type": "demo_summary", "payload": report})
    result_paths = _write_demo_artifacts(report)
    report["artifacts"] = {key: str(path) for key, path in result_paths.items()}
    _phase(
        console,
        6,
        "Judge Compares Before and After",
        "The judge compares the vulnerable round against the defended round. "
        "Better defenses should lower attack success and increase blocked requests.",
        presentation,
    )
    _print_before_after(console, report)
    _print_artifacts(console, result_paths)
    return report


def _run_demo_rounds(
    console: Console,
    client: Any,
    paths: dict[str, Path],
    presentation: bool,
) -> tuple[RedRoundSummary, BlueRoundSummary, RedRoundSummary]:
    _phase(
        console,
        2,
        "Red Agent Probes the Vulnerable System",
        "The red agent plays the attacker in a safe, local-only way. "
        "It tries login guessing, message flooding, oversized messages, malformed data, and endpoint probing.",
        presentation,
    )
    console.print("[red]RED AGENT[/] running vulnerable round")
    vulnerable = RedAgent(
        client,
        max_attempts=6,
        log_file=paths["red"],
    ).run_loop("demo_vulnerable_round")
    _print_red_findings(console, vulnerable)

    _phase(
        console,
        3,
        "Judge Evaluates Attack Success",
        "The judge asks a simple question: how many attack attempts got through before defenses existed?",
        presentation,
    )
    _print_round_score(console, "Vulnerable Round Score", vulnerable.results, "red")

    _phase(
        console,
        4,
        "Blue Agent Reads Logs and Applies Defenses",
        "The blue agent acts like a defender. It reviews the event logs, identifies suspicious behavior, "
        "then turns on safer controls for the toy service.",
        presentation,
    )
    console.print("[blue]BLUE AGENT[/] analyzing logs and applying defenses")
    blue_summary = BlueAgent(
        paths["security"],
        client=client,
        agent_log_file=paths["blue"],
    ).run_loop("demo_blue_defense_round", vulnerable.results)
    _print_blue_observations(console, blue_summary)
    _print_blue_actions(console, blue_summary)

    _phase(
        console,
        5,
        "Red Agent Attacks Again",
        "Now the same red-agent playbook runs against the defended service. "
        "Some attempts should be blocked or limited.",
        presentation,
    )
    console.print("[red]RED AGENT[/] running defended round")
    defended = RedAgent(
        client,
        max_attempts=6,
        log_file=paths["red"],
    ).run_loop("demo_defended_round")
    _print_round_score(console, "Defended Round Score", defended.results, "green")
    return vulnerable, blue_summary, defended


def _prepare_demo_logs() -> dict[str, Path]:
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    paths = {
        "security": log_dir / "demo_security.log",
        "red": log_dir / "demo_red_agent.jsonl",
        "blue": log_dir / "demo_blue_agent.jsonl",
        "rounds": log_dir / "demo_round_reports.jsonl",
    }
    for path in paths.values():
        if path.exists():
            path.unlink()
    return paths


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _metrics(results: list[AttackResult]) -> dict[str, Any]:
    attempts = sum(result.attempts for result in results)
    accepted = sum(result.accepted for result in results)
    blocked = sum(result.blocked for result in results)
    timings = [timing for result in results for timing in result.response_times_ms]
    statuses = [status for result in results for status in result.statuses]
    available = sum(1 for status in statuses if status < 500)
    return {
        "attempts": attempts,
        "accepted": accepted,
        "blocked": blocked,
        "attack_success_rate": (accepted / attempts) * 100 if attempts else 0.0,
        "avg_response_time_ms": sum(timings) / len(timings) if timings else 0.0,
        "service_availability": (available / len(statuses)) * 100 if statuses else 100.0,
        "judge_score": score_round(results),
    }


def _write_demo_artifacts(report: dict[str, Any]) -> dict[str, Path]:
    RESULTS_DIR.mkdir(exist_ok=True)
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)

    data_path = RESULTS_DIR / "demo_results.json"
    figure_paths = _generate_charts(report)
    report_path = RESULTS_DIR / "demo_report.md"
    result_paths = {
        "data": data_path,
        "report": report_path,
        **figure_paths,
    }
    report["artifacts"] = {key: str(path) for key, path in result_paths.items()}
    with data_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
    report_path.write_text(_build_markdown_report(report, figure_paths), encoding="utf-8")

    return result_paths


def _generate_charts(report: dict[str, Any]) -> dict[str, Path]:
    os.environ.setdefault("MPLCONFIGDIR", str(Path("/private/tmp/cyber_sim_matplotlib")))
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    charts = {
        "attack_success_chart": {
            "path": FIGURES_DIR / "attack_success_before_after.png",
            "title": "Attack Success Rate Before and After Defenses",
            "ylabel": "Attack success rate (%)",
            "values": [
                report["vulnerable"]["attack_success_rate"],
                report["defended"]["attack_success_rate"],
            ],
            "ylim": (0, 100),
            "format": "{:.1f}%",
        },
        "blocked_requests_chart": {
            "path": FIGURES_DIR / "blocked_requests_before_after.png",
            "title": "Blocked Requests Before and After Defenses",
            "ylabel": "Blocked request count",
            "values": [
                report["vulnerable"]["blocked"],
                report["defended"]["blocked"],
            ],
            "ylim": None,
            "format": "{:.0f}",
        },
        "service_availability_chart": {
            "path": FIGURES_DIR / "service_availability_before_after.png",
            "title": "Service Availability During Demo Rounds",
            "ylabel": "Availability (%)",
            "values": [
                report["vulnerable"]["service_availability"],
                report["defended"]["service_availability"],
            ],
            "ylim": (0, 100),
            "format": "{:.1f}%",
        },
        "defense_score_chart": {
            "path": FIGURES_DIR / "defense_score_before_after.png",
            "title": "Judge Defense Score Before and After Defenses",
            "ylabel": "Defense score (0-100)",
            "values": [
                report["vulnerable"]["judge_score"],
                report["defended"]["judge_score"],
            ],
            "ylim": (0, 100),
            "format": "{:.0f}/100",
        },
    }

    for chart in charts.values():
        _save_bar_chart(
            plt,
            chart["path"],
            chart["title"],
            chart["ylabel"],
            chart["values"],
            chart["ylim"],
            chart["format"],
        )

    return {name: chart["path"] for name, chart in charts.items()}


def _save_bar_chart(
    plt: Any,
    path: Path,
    title: str,
    ylabel: str,
    values: list[float],
    ylim: tuple[int, int] | None,
    value_format: str,
) -> None:
    labels = ["Vulnerable", "Defended"]
    colors = ["#d1495b", "#2a9d8f"]

    fig, ax = plt.subplots(figsize=(8, 5), dpi=150)
    bars = ax.bar(labels, values, color=colors, width=0.55)
    ax.set_title(title, fontsize=15, fontweight="bold", pad=14)
    ax.set_ylabel(ylabel, fontsize=12)
    ax.set_xlabel("Demo round", fontsize=12)
    ax.tick_params(axis="both", labelsize=11)
    ax.grid(axis="y", linestyle="--", alpha=0.35)
    if ylim:
        ax.set_ylim(*ylim)
    else:
        ax.set_ylim(0, max(values + [1]) * 1.25)

    for bar, value in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            value_format.format(value),
            ha="center",
            va="bottom",
            fontsize=11,
            fontweight="bold",
        )

    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def _build_markdown_report(report: dict[str, Any], figure_paths: dict[str, Path]) -> str:
    before = report["vulnerable"]
    after = report["defended"]
    defenses = [
        name.replace("_enabled", "").replace("_", " ")
        for name, enabled in report["defenses_enabled"].items()
        if name.endswith("_enabled") and enabled
    ]
    enabled_defenses = ", ".join(defenses) if defenses else "none"

    return f"""# AI vs AI Local Cybersecurity Demo Report

## Project Overview

This project is a local-only educational cyber range. It models an AI-vs-AI security workflow around a toy communication service. The red agent behaves like a bounded attacker, the blue agent behaves like a defender, and the judge compares what happened before and after defenses were enabled.

## What the Toy Communication Channel Represents

The service is a small FastAPI chat-style API. It has:

- `POST /login` for username/password login.
- `POST /send_message` for sending a message with a token.
- `GET /messages` for reading messages visible to a user.
- `GET /health` for service health and current defense settings.

Technically, the server keeps users, tokens, messages, defense settings, and rate-limit counters in local memory. Security events are written to local JSON-lines logs. The initial service is intentionally weak: it has no rate limiting, no account lockout, weak payload checks, no message size limit, and verbose errors.

## Red Agent Strategy

The red agent only targets the local demo server. It observes `/health`, chooses from a fixed safe set of demo actions, executes bounded requests, and records findings. The safe actions are repeated failed logins, message spam, oversized messages, malformed JSON, and simple endpoint probing.

In the vulnerable round, the red agent is expected to succeed at some actions because the controls are intentionally disabled.

## Blue Agent Strategy

The blue agent reads the local service log and recent red-agent results. It looks for suspicious behavior such as repeated login failures, message floods, malformed requests, endpoint probes, and accepted red-agent actions. In this demo it chose: **{_human_decision(report["blue_decision"])}**.

The enabled defenses were: **{enabled_defenses}**.

Technically, the defense profile turns on request rate limiting, account lockout after repeated failures, payload validation with a message size cap, and safer error messages.

## Judge Scoring System

The judge scores each round from 0 to 100 based on how many red-agent attempts were blocked. A higher score means the service mitigated more of the bounded local attack attempts. The judge also reports attack success rate, blocked requests, average response time, and service availability.

## Before/After Metrics

| Metric | Vulnerable Round | Defended Round |
|---|---:|---:|
| Attack attempts | {before["attempts"]} | {after["attempts"]} |
| Accepted attempts | {before["accepted"]} | {after["accepted"]} |
| Blocked requests | {before["blocked"]} | {after["blocked"]} |
| Attack success rate | {before["attack_success_rate"]:.1f}% | {after["attack_success_rate"]:.1f}% |
| Average response time | {before["avg_response_time_ms"]:.2f} ms | {after["avg_response_time_ms"]:.2f} ms |
| Service availability | {before["service_availability"]:.1f}% | {after["service_availability"]:.1f}% |
| Judge defense score | {before["judge_score"]}/100 | {after["judge_score"]}/100 |

## Chart Explanations

### Attack Success Before/After

![Attack Success Before/After]({_report_chart_link(figure_paths["attack_success_chart"])})

This chart shows the percentage of red-agent attempts that were accepted by the service. A lower defended value means the blue-agent controls reduced attacker success.

### Blocked Requests Before/After

![Blocked Requests Before/After]({_report_chart_link(figure_paths["blocked_requests_chart"])})

This chart shows how many requests were blocked by defensive controls. In the vulnerable round this is low or zero because the controls start disabled.

### Service Availability Before/After

![Service Availability Before/After]({_report_chart_link(figure_paths["service_availability_chart"])})

This chart confirms that the demo service stayed available while defenses were applied. The goal is to mitigate attacks without crashing the service.

### Defense Score Before/After

![Defense Score Before/After]({_report_chart_link(figure_paths["defense_score_chart"])})

This chart shows the judge's 0-to-100 defense score. It increases when more red-agent attempts are blocked.

## Limitations and Safety Statement

This is a toy simulation, not a real security testing platform. The attacks are intentionally bounded, local-only, and designed for classroom explanation. The code must never be used against public systems, third-party services, classmates' devices, or any machine you do not own and explicitly control.

The simulation simplifies many real-world details. It uses in-memory state, simple scoring, fixed red-agent strategies, and a single standard blue-agent defense profile. Its purpose is to explain security concepts and defensive reasoning, not to validate production security.
"""


def _report_chart_link(path: Path) -> str:
    return path.relative_to(RESULTS_DIR).as_posix()


def _phase(
    console: Console,
    number: int,
    title: str,
    explanation: str,
    presentation: bool,
) -> None:
    console.print(
        Panel(
            explanation,
            title=f"Phase {number}: {title}",
            border_style="bright_cyan",
            padding=(1, 2),
        )
    )
    _pause(presentation)


def _pause(presentation: bool) -> None:
    if presentation:
        time.sleep(PRESENTATION_PAUSE_SECONDS)


def _human_name(strategy: str) -> str:
    names = {
        "repeated_failed_logins": "Repeated login attempts",
        "oversized_payload": "Oversized message",
        "burst_message_spam": "Message spam burst",
        "malformed_json": "Malformed request",
        "endpoint_probing": "Endpoint probing",
    }
    return names.get(strategy, strategy.replace("_", " ").title())


def _print_round_score(
    console: Console,
    title: str,
    results: list[AttackResult],
    border_style: str,
) -> None:
    metrics = _metrics(results)
    table = Table(title=title, border_style=border_style)
    table.add_column("What the judge checks", style="cyan")
    table.add_column("Result", justify="right")
    table.add_row("Attack attempts accepted", str(metrics["accepted"]))
    table.add_row("Attack attempts blocked", str(metrics["blocked"]))
    table.add_row("Attack success rate", f"{metrics['attack_success_rate']:.1f}%")
    table.add_row("Service availability", f"{metrics['service_availability']:.1f}%")
    table.add_row("Defense score", f"{metrics['judge_score']}/100")
    console.print(table)


def _print_red_findings(console: Console, summary: RedRoundSummary) -> None:
    table = Table(title="Vulnerable Round: Red Findings", border_style="red")
    table.add_column("Red-agent action")
    table.add_column("Outcome")
    table.add_column("Accepted", justify="right")
    table.add_column("Blocked", justify="right")
    for finding in summary.findings:
        table.add_row(
            _human_name(finding.strategy),
            finding.outcome,
            str(finding.evidence["accepted"]),
            str(finding.evidence["blocked"]),
        )
    console.print(table)


def _print_blue_observations(console: Console, summary: BlueRoundSummary) -> None:
    table = Table(title="What the Blue Agent Observed", border_style="blue")
    table.add_column("Finding")
    for finding in summary.findings[:4]:
        table.add_row(_human_finding(finding))
    console.print(table)


def _print_blue_actions(console: Console, summary: BlueRoundSummary) -> None:
    table = Table(title="Blue Agent Defense Action", border_style="blue")
    table.add_column("Decision")
    table.add_column("Reason")
    table.add_column("Validation")
    validation = "passed" if all(result.passed for result in summary.validation_results) else "needs review"
    table.add_row(_human_decision(summary.decision.action), _human_reason(summary.decision.reason), validation)
    console.print(table)


def _human_finding(finding: str) -> str:
    if finding.startswith("Recent red-agent results show accepted attacks"):
        return "Several red-agent actions got through before defenses were enabled."
    return finding


def _human_decision(action: str) -> str:
    decisions = {
        "enable_standard_defenses": "Enable standard defenses",
        "no_change": "Keep current defenses",
        "monitor_only": "Monitor only",
    }
    return decisions.get(action, action.replace("_", " ").title())


def _human_reason(reason: str) -> str:
    if reason == "Suspicious behavior or accepted attacks were observed.":
        return "The logs show suspicious activity and successful red-agent actions."
    if reason == "Core defenses are already enabled.":
        return "The main defenses are already active."
    return reason


def _print_before_after(console: Console, report: dict[str, Any]) -> None:
    before = report["vulnerable"]
    after = report["defended"]
    table = Table(title="Before / After Summary", border_style="bright_cyan")
    table.add_column("Metric", style="cyan")
    table.add_column("Vulnerable Round", justify="right")
    table.add_column("Defended Round", justify="right")
    table.add_row("Attack success rate", f"{before['attack_success_rate']:.1f}%", f"{after['attack_success_rate']:.1f}%")
    table.add_row("Blocked requests", str(before["blocked"]), str(after["blocked"]))
    table.add_row("Average response time", f"{before['avg_response_time_ms']:.2f} ms", f"{after['avg_response_time_ms']:.2f} ms")
    table.add_row("Service availability", f"{before['service_availability']:.1f}%", f"{after['service_availability']:.1f}%")
    table.add_row("Judge defense score", f"{before['judge_score']}/100", f"{after['judge_score']}/100")
    console.print(table)
    console.print("[green]DEMO COMPLETE[/] improved mitigation after blue-team defenses")
    console.print(
        "[dim]Logs: logs/demo_security.log, logs/demo_red_agent.jsonl, "
        "logs/demo_blue_agent.jsonl, logs/demo_round_reports.jsonl[/]"
    )


def _print_artifacts(console: Console, result_paths: dict[str, Path]) -> None:
    table = Table(title="Generated Presentation Artifacts", border_style="bright_green")
    table.add_column("Artifact")
    table.add_column("Path")
    labels = {
        "data": "Demo data",
        "round_history": "Round history",
        "report": "Markdown report",
        "attack_success_chart": "Attack success chart",
        "blocked_requests_chart": "Blocked requests chart",
        "service_availability_chart": "Service availability chart",
        "defense_score_chart": "Defense score chart",
        "score_timeline_chart": "Score timeline chart",
        "system_state_timeline_chart": "System state chart",
    }
    for key, path in result_paths.items():
        table.add_row(labels.get(key, key), str(path))
    console.print(table)


@dataclass
class BattleState:
    service_availability: float = 100.0
    average_latency_ms: float = 25.0
    error_rate: float = 0.0
    message_queue_pollution: float = 0.0
    message_queue_size: float = 0.0
    failed_login_pressure: float = 0.0
    reconnaissance_exposure: float = 0.0
    false_positive_rate: float = 0.0
    false_positive_blocks: float = 0.0
    normal_user_success_rate: float = 100.0
    normal_user_latency_ms: float = 25.0


@dataclass
class DemoUser:
    username: str
    role: str


@dataclass
class NormalTrafficResult:
    attempted_actions: int
    successful_actions: int
    false_positive_blocks: int
    normal_user_success_rate: float
    normal_user_latency_ms: float
    public_messages_sent: int
    private_messages_sent: int
    messages_read: int


NORMAL_USERS = [
    DemoUser("alice", "user"),
    DemoUser("bob", "user"),
    DemoUser("admin", "admin"),
    DemoUser("guest", "guest"),
]


@dataclass
class DefensePosture:
    rate_limiting: int = 0
    account_lockout: int = 0
    payload_validation: int = 0
    aggressive_blocking: int = 0
    allowlist_normal_user_patterns: int = 0

    def cost(self) -> int:
        return (
            self.rate_limiting
            + self.account_lockout
            + self.payload_validation
            + self.aggressive_blocking * 2
            + self.allowlist_normal_user_patterns
        )


@dataclass
class RoundScore:
    attack_success_points: float
    disruption_points: float
    reconnaissance_points: float
    stealth_points: float
    blocked_attack_points: float
    availability_points: float
    normal_user_success_points: float
    low_false_positive_points: float
    defense_efficiency_points: float

    @property
    def red_total(self) -> float:
        return (
            self.attack_success_points
            + self.disruption_points
            + self.reconnaissance_points
            + self.stealth_points
        )

    @property
    def blue_total(self) -> float:
        return (
            self.blocked_attack_points
            + self.availability_points
            + self.normal_user_success_points
            + self.low_false_positive_points
            + self.defense_efficiency_points
        )


ROUND_OBJECTIVES = [
    ("Round 1: Reconnaissance", "reconnaissance"),
    ("Round 2: Flood Attempt", "message_spam"),
    ("Round 3: Credential Pressure", "credential_attack"),
    ("Round 4: Payload Abuse", "oversized_payload_abuse"),
    ("Round 5: Availability Disruption", "availability_disruption"),
    ("Round 6: Low-and-Slow Probing", "stealthy_low_and_slow"),
]


def run_demo(use_live_server: bool = True, presentation: bool = False) -> dict[str, Any]:
    """Run an adaptive, local-only multi-round red/blue battle."""

    paths = _prepare_demo_logs()
    reset_app_state(clear_log=True)
    security.configure_log_file(paths["security"])

    console = Console()
    console.print(Panel.fit("AI vs AI Local Cyber Battle", style="bold bright_cyan"))
    _phase(
        console,
        1,
        "Starting the Toy Communication Channel",
        "Arena: a local FastAPI chat service with login, send-message, read-message, and health endpoints. "
        "The battle model tracks service health, message pollution, login pressure, latency, errors, and user disruption.",
        presentation,
    )

    if use_live_server:
        with LocalUvicornServer() as server:
            console.print(f"[green]SERVER[/] started on {server.base_url} local-only")
            report = _run_battle(console, paths, presentation)
    else:
        console.print("[green]SERVER[/] using in-process local test server")
        report = _run_battle(console, paths, presentation)

    result_paths = _write_battle_artifacts(report)
    report["artifacts"] = {key: str(path) for key, path in result_paths.items()}
    _print_artifacts(console, result_paths)
    return report


def _run_battle(console: Console, paths: dict[str, Path], presentation: bool) -> dict[str, Any]:
    state = BattleState()
    defenses = DefensePosture()
    history: list[dict[str, Any]] = []
    previous_result: dict[str, Any] | None = None

    for round_number, (default_title, default_objective) in enumerate(ROUND_OBJECTIVES, start=1):
        objective = _choose_red_objective(default_objective, defenses, previous_result)
        title = _round_title(round_number, objective, default_title)
        _battle_round_intro(
            console,
            title,
            _objective_narration(objective, defenses),
            presentation,
        )
        _print_health_bar(console, state)
        console.print(Panel(_red_reveal(objective), title="Red-Agent Strategy Reveal", border_style="red"))
        _pause(presentation)

        result = _simulate_attack(objective, state, defenses)
        _apply_damage(state, result, defenses)
        normal_traffic = _simulate_normal_user_traffic(state, defenses)
        observations, missed = _blue_observations(result, state)
        decision = _blue_decision(observations, defenses, state)
        _apply_blue_decision(defenses, decision)
        _apply_blue_recovery(state, decision, defenses)

        console.print(_damage_panel(result, state))
        console.print(_normal_user_panel(normal_traffic))
        console.print(_observation_panel(observations, missed))
        console.print(_decision_panel(decision, defenses))
        _pause(presentation)
        console.print(Panel("Judge is revealing full ground truth for the audience.", border_style="yellow"))
        _pause(presentation)

        score = _judge_score(result, state, defenses)
        round_record = {
            "round": round_number,
            "title": title,
            "red_objective": objective,
            "red_result": result,
            "normal_user_traffic": asdict(normal_traffic),
            "blue_observations": observations,
            "blue_missed": missed,
            "blue_decision": decision,
            "defenses_after_round": asdict(defenses),
            "system_state": asdict(state),
            "scores": {
                **asdict(score),
                "red_total": round(score.red_total, 2),
                "blue_total": round(score.blue_total, 2),
            },
        }
        history.append(round_record)
        append_jsonl(paths["rounds"], {"type": "battle_round", "payload": round_record})
        _print_judge_verdict(console, round_record)
        previous_result = result

    report = {
        "mode": "multi_round_battle",
        "round_count": len(history),
        "rounds": history,
        "final_state": asdict(state),
        "final_defenses": asdict(defenses),
        "vulnerable": _round_metrics(history[0]),
        "defended": _round_metrics(history[-1]),
        "logs": {key: str(path) for key, path in paths.items()},
    }
    _print_battle_timeline(console, history)
    _print_multi_round_summary(console, report)
    return report


def _choose_red_objective(
    default_objective: str,
    defenses: DefensePosture,
    previous_result: dict[str, Any] | None,
) -> str:
    if previous_result and previous_result["blocked"] > previous_result["accepted"]:
        if previous_result["objective"] == "message_spam":
            return "credential_attack"
        if previous_result["objective"] == "credential_attack" and defenses.account_lockout:
            return "oversized_payload_abuse"
        if previous_result["objective"] == "oversized_payload_abuse" and defenses.payload_validation:
            return "reconnaissance"
    if default_objective == "message_spam" and defenses.rate_limiting >= 2:
        return "stealthy_low_and_slow"
    if default_objective == "credential_attack" and defenses.account_lockout:
        return "oversized_payload_abuse"
    if default_objective == "oversized_payload_abuse" and defenses.payload_validation >= 2:
        return "reconnaissance"
    return default_objective


def _simulate_attack(objective: str, state: BattleState, defenses: DefensePosture) -> dict[str, Any]:
    profiles = {
        "reconnaissance": {"attempts": 5, "base_damage": 8, "noise": 1},
        "message_spam": {"attempts": 12, "base_damage": 18, "noise": 4},
        "availability_disruption": {"attempts": 10, "base_damage": 22, "noise": 5},
        "credential_attack": {"attempts": 8, "base_damage": 16, "noise": 4},
        "oversized_payload_abuse": {"attempts": 6, "base_damage": 20, "noise": 3},
        "stealthy_low_and_slow": {"attempts": 5, "base_damage": 10, "noise": 0.5},
    }
    profile = profiles[objective]
    attempts = profile["attempts"]
    blocked = _blocked_attempts(objective, attempts, defenses)
    accepted = attempts - blocked
    return {
        "objective": objective,
        "attempts": attempts,
        "accepted": accepted,
        "blocked": blocked,
        "base_damage": profile["base_damage"],
        "log_noise": profile["noise"],
    }


def _blocked_attempts(objective: str, attempts: int, defenses: DefensePosture) -> int:
    if objective == "message_spam":
        blocked = defenses.rate_limiting * 4 + defenses.aggressive_blocking * 2
    elif objective == "availability_disruption":
        blocked = defenses.rate_limiting * 3 + defenses.aggressive_blocking * 3
    elif objective == "credential_attack":
        blocked = defenses.account_lockout * 4 + defenses.rate_limiting
    elif objective == "oversized_payload_abuse":
        blocked = defenses.payload_validation * 4 + defenses.aggressive_blocking
    elif objective == "reconnaissance":
        blocked = defenses.aggressive_blocking * 2
    else:
        blocked = defenses.aggressive_blocking + defenses.rate_limiting
    return max(0, min(attempts, blocked))


def _apply_damage(state: BattleState, result: dict[str, Any], defenses: DefensePosture) -> None:
    accepted = result["accepted"]
    objective = result["objective"]
    damage_factor = accepted / max(result["attempts"], 1)

    if objective == "message_spam":
        state.message_queue_pollution += accepted * 5
        state.message_queue_size += accepted
        state.average_latency_ms += accepted * 2.5
        state.normal_user_success_rate -= accepted * 0.8
    elif objective == "availability_disruption":
        state.average_latency_ms += accepted * 5
        state.error_rate += accepted * 1.4
        state.service_availability -= accepted * 1.8
    elif objective == "credential_attack":
        state.failed_login_pressure += accepted * 4
        state.error_rate += accepted * 0.4
    elif objective == "oversized_payload_abuse":
        state.average_latency_ms += accepted * 6
        state.error_rate += accepted * 2.0
        state.message_queue_pollution += accepted * 2
        state.message_queue_size += accepted
    elif objective == "reconnaissance":
        state.reconnaissance_exposure += accepted * 4
    elif objective == "stealthy_low_and_slow":
        state.reconnaissance_exposure += accepted * 3
        state.failed_login_pressure += accepted * 0.5

    allowlist_relief = defenses.allowlist_normal_user_patterns * 1.8
    state.false_positive_rate += max(0, defenses.rate_limiting * 1.2 - allowlist_relief)
    state.false_positive_rate += max(0, defenses.account_lockout * 1.5 - allowlist_relief)
    state.false_positive_rate += max(0, defenses.payload_validation * 1.0 - allowlist_relief)
    state.false_positive_rate += max(0, defenses.aggressive_blocking * 3.0 - allowlist_relief)
    state.normal_user_success_rate -= max(0, defenses.rate_limiting * 1.0 - allowlist_relief)
    state.normal_user_success_rate -= max(0, defenses.account_lockout * 1.5 - allowlist_relief)
    state.normal_user_success_rate -= max(0, defenses.payload_validation * 1.0 - allowlist_relief)
    state.normal_user_success_rate -= max(0, defenses.aggressive_blocking * 3.0 - allowlist_relief)

    state.error_rate += damage_factor * 2
    state.service_availability = _clamp(state.service_availability, 0, 100)
    state.average_latency_ms = _clamp(state.average_latency_ms, 5, 250)
    state.error_rate = _clamp(state.error_rate, 0, 100)
    state.message_queue_pollution = _clamp(state.message_queue_pollution, 0, 100)
    state.message_queue_size = _clamp(state.message_queue_size, 0, 500)
    state.failed_login_pressure = _clamp(state.failed_login_pressure, 0, 100)
    state.reconnaissance_exposure = _clamp(state.reconnaissance_exposure, 0, 100)
    state.false_positive_rate = _clamp(state.false_positive_rate, 0, 100)
    state.false_positive_blocks = _clamp(state.false_positive_blocks, 0, 500)
    state.normal_user_success_rate = _clamp(state.normal_user_success_rate, 0, 100)
    state.normal_user_latency_ms = _clamp(state.normal_user_latency_ms, 5, 300)


def _simulate_normal_user_traffic(
    state: BattleState,
    defenses: DefensePosture,
) -> NormalTrafficResult:
    """Simulate legitimate logins, sends, and reads during each battle round.

    The business goal is simple: normal users should still authenticate, send
    public/private messages, and read the channel while blue is defending.
    Overly strict controls create false-positive blocks and higher latency.
    """

    attempted_actions = len(NORMAL_USERS) * 3
    false_positive_blocks = 0
    false_positive_blocks += defenses.rate_limiting
    false_positive_blocks += defenses.account_lockout
    false_positive_blocks += defenses.payload_validation
    false_positive_blocks += defenses.aggressive_blocking * 2
    false_positive_blocks -= defenses.allowlist_normal_user_patterns * 3
    if state.message_queue_pollution >= 50:
        false_positive_blocks += 1
    if state.error_rate >= 20:
        false_positive_blocks += 1

    false_positive_blocks = max(0, min(attempted_actions, false_positive_blocks))
    successful_actions = attempted_actions - false_positive_blocks
    public_messages_sent = max(0, 2 - defenses.rate_limiting // 2)
    private_messages_sent = max(0, 2 - defenses.payload_validation // 2)
    messages_read = max(0, 4 - int(state.message_queue_pollution // 35))
    normal_latency = (
        25
        + state.average_latency_ms * 0.35
        + defenses.rate_limiting * 6
        + defenses.payload_validation * 4
        + defenses.aggressive_blocking * 8
        - defenses.allowlist_normal_user_patterns * 8
    )

    state.message_queue_size += public_messages_sent + private_messages_sent
    state.false_positive_blocks += false_positive_blocks
    state.false_positive_rate = _clamp(
        (state.false_positive_blocks / max(attempted_actions * 6, 1)) * 100,
        0,
        100,
    )
    state.normal_user_success_rate = _clamp(
        (successful_actions / attempted_actions) * 100 - state.error_rate * 0.25,
        0,
        100,
    )
    state.normal_user_latency_ms = _clamp(normal_latency, 5, 300)
    return NormalTrafficResult(
        attempted_actions=attempted_actions,
        successful_actions=successful_actions,
        false_positive_blocks=false_positive_blocks,
        normal_user_success_rate=round(state.normal_user_success_rate, 2),
        normal_user_latency_ms=round(state.normal_user_latency_ms, 2),
        public_messages_sent=public_messages_sent,
        private_messages_sent=private_messages_sent,
        messages_read=messages_read,
    )


def _blue_observations(result: dict[str, Any], state: BattleState) -> tuple[list[str], list[str]]:
    observations: list[str] = []
    missed: list[str] = []
    if result["log_noise"] >= 4:
        observations.append("High request volume appeared in service logs.")
    if state.message_queue_pollution >= 15:
        observations.append("Message queue looks polluted with repeated sends.")
    if state.failed_login_pressure >= 12:
        observations.append("Failed login count is rising.")
    if state.error_rate >= 8:
        observations.append("Error rate is above normal.")
    if state.normal_user_success_rate < 85:
        observations.append("Normal-user success appears degraded.")
    if state.false_positive_blocks > 0:
        observations.append("Some legitimate user actions were blocked.")
    if result["objective"] in {"reconnaissance", "stealthy_low_and_slow"}:
        observations.append("A few unknown endpoints were requested.")
        if result["objective"] == "stealthy_low_and_slow":
            missed.append("Low-and-slow probing blended into normal traffic.")
    if not observations:
        observations.append("No obvious spike, but the logs show small anomalies.")
    if result["accepted"] > 0 and result["blocked"] == 0:
        missed.append("The exact red objective is not visible from logs alone.")
    return observations, missed


def _blue_decision(
    observations: list[str],
    defenses: DefensePosture,
    state: BattleState,
) -> dict[str, Any]:
    actions: list[str] = []
    reason = "Blue is using only log symptoms and can tune at most two controls this round."
    joined = " ".join(observations).lower()

    usability_crisis = state.normal_user_success_rate < 60 or state.false_positive_rate > 20
    if usability_crisis:
        reason = "Blue sees usability damage, so it recovers by loosening controls before adding more."
        if defenses.aggressive_blocking > 0 and len(actions) < 2:
            defenses.aggressive_blocking -= 1
            actions.append("reduce_aggressive_blocking")
        if defenses.rate_limiting > 1 and len(actions) < 2:
            defenses.rate_limiting -= 1
            actions.append("loosen_rate_limit")
        if defenses.account_lockout > 1 and len(actions) < 2:
            defenses.account_lockout -= 1
            actions.append("loosen_account_lockout")
        if defenses.allowlist_normal_user_patterns < 2 and len(actions) < 2:
            defenses.allowlist_normal_user_patterns += 1
            actions.append("allowlist_normal_user_patterns")
        return {
            "actions": actions or ["monitor usability recovery"],
            "reason": reason,
            "budget_used": min(2, len(actions)),
        }

    if ("message queue" in joined or "high request volume" in joined) and len(actions) < 2:
        if defenses.rate_limiting < 2:
            defenses.rate_limiting += 1
            actions.append("tune rate limiting")
    if "failed login" in joined and defenses.account_lockout < 2 and len(actions) < 2:
        defenses.account_lockout += 1
        actions.append("tighten account lockout")
    if "error rate" in joined and defenses.payload_validation < 2 and len(actions) < 2:
        defenses.payload_validation += 1
        actions.append("tighten payload validation")
    if "unknown endpoint" in joined and len(actions) < 2 and defenses.aggressive_blocking < 1:
        defenses.aggressive_blocking += 1
        actions.append("add light endpoint blocking")

    if not actions and defenses.rate_limiting < 1:
        defenses.rate_limiting += 1
        actions.append("add light rate limiting")
    return {
        "actions": actions or ["monitor without change"],
        "reason": reason,
        "budget_used": min(2, len(actions)),
    }


def _apply_blue_decision(defenses: DefensePosture, decision: dict[str, Any]) -> None:
    # Defense levels are updated inside _blue_decision so the decision can enforce
    # the 1-2 action budget while it reasons over the current posture.
    return None


def _apply_blue_recovery(
    state: BattleState,
    decision: dict[str, Any],
    defenses: DefensePosture,
) -> None:
    """Apply immediate usability recovery after blue loosens over-strict controls."""

    actions = set(decision["actions"])
    if "reduce_aggressive_blocking" in actions:
        state.false_positive_blocks = max(0, state.false_positive_blocks - 5)
        state.false_positive_rate = max(0, state.false_positive_rate - 8)
        state.normal_user_success_rate = min(100, state.normal_user_success_rate + 12)
    if "loosen_rate_limit" in actions:
        state.false_positive_blocks = max(0, state.false_positive_blocks - 4)
        state.false_positive_rate = max(0, state.false_positive_rate - 6)
        state.normal_user_success_rate = min(100, state.normal_user_success_rate + 10)
        state.normal_user_latency_ms = max(5, state.normal_user_latency_ms - 12)
    if "loosen_account_lockout" in actions:
        state.false_positive_blocks = max(0, state.false_positive_blocks - 3)
        state.false_positive_rate = max(0, state.false_positive_rate - 5)
        state.normal_user_success_rate = min(100, state.normal_user_success_rate + 8)
    if "allowlist_normal_user_patterns" in actions:
        state.false_positive_blocks = max(0, state.false_positive_blocks - 6)
        state.false_positive_rate = max(0, state.false_positive_rate - 10)
        state.normal_user_success_rate = min(100, state.normal_user_success_rate + 16)
        state.normal_user_latency_ms = max(5, state.normal_user_latency_ms - 10)


def _judge_score(result: dict[str, Any], state: BattleState, defenses: DefensePosture) -> RoundScore:
    attempts = max(result["attempts"], 1)
    accepted_ratio = result["accepted"] / attempts
    blocked_ratio = result["blocked"] / attempts

    # Red scoring rewards accepted attack traffic, operational disruption,
    # knowledge gained from reconnaissance, and stealth when few attempts were
    # blocked. These are capped so no single dimension dominates the battle.
    attack_success_points = accepted_ratio * 35
    disruption_points = min(
        25,
        state.message_queue_pollution * 0.08
        + state.failed_login_pressure * 0.08
        + max(0, state.average_latency_ms - 25) * 0.18
        + state.error_rate * 0.18
        + (100 - state.normal_user_success_rate) * 0.08,
    )
    reconnaissance_points = min(20, state.reconnaissance_exposure * 0.2)
    stealth_points = max(0, 20 - result["blocked"] * 3 - result["log_noise"] * 1.5)

    # Blue scoring rewards blocking red attempts while preserving availability,
    # normal-user success, low false positives, and efficient use of defenses.
    # The normal-user terms are intentionally prominent: a defense that stops
    # red but blocks real users is not considered a clean win.
    blocked_attack_points = blocked_ratio * 30
    availability_points = state.service_availability * 0.2
    normal_user_success_points = state.normal_user_success_rate * 0.2
    low_false_positive_points = max(0, 20 - state.false_positive_rate * 0.6)
    defense_efficiency_points = max(0, 10 - defenses.cost() * 1.2)
    return RoundScore(
        round(attack_success_points, 2),
        round(disruption_points, 2),
        round(reconnaissance_points, 2),
        round(stealth_points, 2),
        round(blocked_attack_points, 2),
        round(availability_points, 2),
        round(normal_user_success_points, 2),
        round(low_false_positive_points, 2),
        round(defense_efficiency_points, 2),
    )


def _write_battle_artifacts(report: dict[str, Any]) -> dict[str, Path]:
    RESULTS_DIR.mkdir(exist_ok=True)
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    data_path = RESULTS_DIR / "demo_results.json"
    history_path = RESULTS_DIR / "round_history.json"
    figure_paths = _generate_battle_charts(report)
    report_path = RESULTS_DIR / "demo_report.md"

    result_paths = {"data": data_path, "round_history": history_path, "report": report_path, **figure_paths}
    report["artifacts"] = {key: str(path) for key, path in result_paths.items()}
    data_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    history_path.write_text(json.dumps(report["rounds"], indent=2, sort_keys=True), encoding="utf-8")
    report_path.write_text(_build_battle_report(report, figure_paths), encoding="utf-8")
    return result_paths


def _generate_battle_charts(report: dict[str, Any]) -> dict[str, Path]:
    os.environ.setdefault("MPLCONFIGDIR", str(Path("/private/tmp/cyber_sim_matplotlib")))
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    rounds = report["rounds"]
    first = report["vulnerable"]
    last = report["defended"]
    charts = {
        "attack_success_chart": _battle_bar_chart(
            plt,
            "attack_success_before_after.png",
            "Attack Success: First vs Final Round",
            "Attack success (%)",
            [first["attack_success_rate"], last["attack_success_rate"]],
            (0, 100),
            "{:.1f}%",
        ),
        "blocked_requests_chart": _battle_bar_chart(
            plt,
            "blocked_requests_before_after.png",
            "Blocked Requests: First vs Final Round",
            "Blocked requests",
            [first["blocked"], last["blocked"]],
            None,
            "{:.0f}",
        ),
        "service_availability_chart": _battle_bar_chart(
            plt,
            "service_availability_before_after.png",
            "Service Availability: First vs Final Round",
            "Availability (%)",
            [first["service_availability"], last["service_availability"]],
            (0, 100),
            "{:.1f}%",
        ),
        "defense_score_chart": _battle_bar_chart(
            plt,
            "defense_score_before_after.png",
            "Blue Score: First vs Final Round",
            "Blue score",
            [first["blue_score"], last["blue_score"]],
            (0, 100),
            "{:.1f}",
        ),
        "score_timeline_chart": _line_chart(
            plt,
            "score_timeline.png",
            "Red and Blue Scores Across Rounds",
            "Score",
            [r["scores"]["red_total"] for r in rounds],
            [r["scores"]["blue_total"] for r in rounds],
        ),
        "system_state_timeline_chart": _state_chart(plt, rounds),
    }
    return charts


def _battle_bar_chart(
    plt: Any,
    filename: str,
    title: str,
    ylabel: str,
    values: list[float],
    ylim: tuple[int, int] | None,
    value_format: str,
) -> Path:
    path = FIGURES_DIR / filename
    _save_bar_chart(plt, path, title, ylabel, values, ylim, value_format)
    return path


def _line_chart(
    plt: Any,
    filename: str,
    title: str,
    ylabel: str,
    red_values: list[float],
    blue_values: list[float],
) -> Path:
    path = FIGURES_DIR / filename
    xs = list(range(1, len(red_values) + 1))
    fig, ax = plt.subplots(figsize=(9, 5), dpi=150)
    ax.plot(xs, red_values, marker="o", color="#d1495b", linewidth=2.5, label="Red score")
    ax.plot(xs, blue_values, marker="o", color="#2a9d8f", linewidth=2.5, label="Blue score")
    ax.set_title(title, fontsize=15, fontweight="bold", pad=14)
    ax.set_xlabel("Round", fontsize=12)
    ax.set_ylabel(ylabel, fontsize=12)
    ax.set_xticks(xs)
    ax.grid(True, linestyle="--", alpha=0.35)
    ax.legend()
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    return path


def _state_chart(plt: Any, rounds: list[dict[str, Any]]) -> Path:
    path = FIGURES_DIR / "system_state_timeline.png"
    xs = [r["round"] for r in rounds]
    fig, ax = plt.subplots(figsize=(10, 5.5), dpi=150)
    for key, label in [
        ("service_availability", "Availability"),
        ("normal_user_success_rate", "Normal users"),
        ("false_positive_rate", "False positives"),
        ("error_rate", "Error rate"),
        ("message_queue_pollution", "Message pollution"),
        ("reconnaissance_exposure", "Recon exposure"),
    ]:
        ax.plot(xs, [r["system_state"][key] for r in rounds], marker="o", linewidth=2, label=label)
    ax.set_title("System State Across Battle Rounds", fontsize=15, fontweight="bold", pad=14)
    ax.set_xlabel("Round", fontsize=12)
    ax.set_ylabel("State value", fontsize=12)
    ax.set_xticks(xs)
    ax.set_ylim(0, 105)
    ax.grid(True, linestyle="--", alpha=0.35)
    ax.legend(ncol=2)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    return path


def _round_metrics(round_record: dict[str, Any]) -> dict[str, Any]:
    result = round_record["red_result"]
    state = round_record["system_state"]
    scores = round_record["scores"]
    return {
        "attempts": result["attempts"],
        "accepted": result["accepted"],
        "blocked": result["blocked"],
        "attack_success_rate": result["accepted"] / max(result["attempts"], 1) * 100,
        "service_availability": state["service_availability"],
        "normal_user_success_rate": state["normal_user_success_rate"],
        "normal_user_latency_ms": state["normal_user_latency_ms"],
        "false_positive_blocks": state["false_positive_blocks"],
        "false_positive_rate": state["false_positive_rate"],
        "avg_response_time_ms": state["average_latency_ms"],
        "red_score": scores["red_total"],
        "blue_score": scores["blue_total"],
        "judge_score": scores["blue_total"],
    }


def _round_title(round_number: int, objective: str, fallback: str) -> str:
    names = {
        "reconnaissance": "Reconnaissance",
        "message_spam": "Flood Attempt",
        "availability_disruption": "Availability Disruption",
        "credential_attack": "Credential Pressure",
        "oversized_payload_abuse": "Payload Abuse",
        "stealthy_low_and_slow": "Low-and-Slow Probing",
    }
    return f"Round {round_number}: {names.get(objective, fallback)}"


def _objective_narration(objective: str, defenses: DefensePosture) -> str:
    return (
        f"Red objective: {_human_battle_objective(objective)}. "
        f"Current blue posture: rate limiting {defenses.rate_limiting}, account lockout {defenses.account_lockout}, "
        f"payload validation {defenses.payload_validation}, aggressive blocking {defenses.aggressive_blocking}, "
        f"normal-user allowlist {defenses.allowlist_normal_user_patterns}."
    )


def _human_battle_objective(objective: str) -> str:
    return {
        "reconnaissance": "map the API surface and learn where weak endpoints might be",
        "message_spam": "pollute the message queue with repeated sends",
        "availability_disruption": "increase latency and errors for normal users",
        "credential_attack": "create failed-login pressure against user accounts",
        "oversized_payload_abuse": "push very large messages through weak validation",
        "stealthy_low_and_slow": "probe slowly enough to blend into normal traffic",
    }[objective]


def _red_reveal(objective: str) -> str:
    return f"Red adapts to the current defenses and chooses to {_human_battle_objective(objective)}."


def _damage_panel(result: dict[str, Any], state: BattleState) -> Panel:
    return Panel(
        f"Accepted attempts: {result['accepted']}/{result['attempts']}\n"
        f"Blocked attempts: {result['blocked']}\n"
        f"Visible damage: queue size {state.message_queue_size:.0f}, pollution {state.message_queue_pollution:.1f}, "
        f"login pressure {state.failed_login_pressure:.1f}, "
        f"latency {state.average_latency_ms:.1f} ms, errors {state.error_rate:.1f}%",
        title="Visible System Damage",
        border_style="red",
    )


def _normal_user_panel(normal_traffic: NormalTrafficResult) -> Panel:
    return Panel(
        "Business goal: legitimate users should still log in, send messages, and read messages.\n"
        f"Normal actions attempted: {normal_traffic.attempted_actions}\n"
        f"Normal actions successful: {normal_traffic.successful_actions}\n"
        f"False-positive blocks: {normal_traffic.false_positive_blocks}\n"
        f"Normal-user success: {normal_traffic.normal_user_success_rate:.1f}%\n"
        f"Normal-user latency: {normal_traffic.normal_user_latency_ms:.1f} ms\n"
        f"Messages: {normal_traffic.public_messages_sent} public, {normal_traffic.private_messages_sent} private, "
        f"{normal_traffic.messages_read} read operations",
        title="Normal-User Simulator",
        border_style="green",
    )


def _observation_panel(observations: list[str], missed: list[str]) -> Panel:
    seen = "\n".join(f"- {item}" for item in observations)
    missed_text = "\n".join(f"- {item}" for item in missed) if missed else "- Nothing major missed this round."
    return Panel(f"Blue noticed:\n{seen}\n\nBlue missed:\n{missed_text}", title="Blue Limited Observations", border_style="blue")


def _decision_panel(decision: dict[str, Any], defenses: DefensePosture) -> Panel:
    actions = "\n".join(f"- {action}" for action in decision["actions"])
    return Panel(
        f"Budget used: {decision['budget_used']}/2\nActions:\n{actions}\n\n"
        f"Defense posture now: rate limit {defenses.rate_limiting}, lockout {defenses.account_lockout}, "
        f"validation {defenses.payload_validation}, blocking {defenses.aggressive_blocking}, "
        f"allowlist {defenses.allowlist_normal_user_patterns}",
        title="Blue Decision",
        border_style="cyan",
    )


def _print_health_bar(console: Console, state: BattleState) -> None:
    availability = int(state.service_availability)
    filled = max(0, min(20, round(availability / 5)))
    bar = "█" * filled + "░" * (20 - filled)
    console.print(f"[green]System health[/] [{bar}] {availability}% available | normal users {state.normal_user_success_rate:.1f}%")


def _print_judge_verdict(console: Console, round_record: dict[str, Any]) -> None:
    scores = round_record["scores"]
    table = Table(title=f"Judge Verdict: {round_record['title']}", border_style="yellow")
    table.add_column("Score Component")
    table.add_column("Red", justify="right")
    table.add_column("Blue", justify="right")
    table.add_row("Attack / blocked attempts", f"{scores['attack_success_points']:.1f}", f"{scores['blocked_attack_points']:.1f}")
    table.add_row("Disruption / availability", f"{scores['disruption_points']:.1f}", f"{scores['availability_points']:.1f}")
    table.add_row("Recon / normal users", f"{scores['reconnaissance_points']:.1f}", f"{scores['normal_user_success_points']:.1f}")
    table.add_row("Stealth / false positives", f"{scores['stealth_points']:.1f}", f"{scores['low_false_positive_points']:.1f}")
    table.add_row("Efficiency", "-", f"{scores['defense_efficiency_points']:.1f}")
    table.add_row("Total", f"{scores['red_total']:.1f}", f"{scores['blue_total']:.1f}")
    console.print(table)


def _print_battle_timeline(console: Console, history: list[dict[str, Any]]) -> None:
    table = Table(title="Final Battle Timeline", border_style="bright_magenta")
    table.add_column("Round")
    table.add_column("Red Objective")
    table.add_column("Blue Action")
    table.add_column("Red Score", justify="right")
    table.add_column("Blue Score", justify="right")
    for record in history:
        table.add_row(
            str(record["round"]),
            _round_title(record["round"], record["red_objective"], record["title"]).split(": ", 1)[1],
            ", ".join(record["blue_decision"]["actions"]),
            f"{record['scores']['red_total']:.1f}",
            f"{record['scores']['blue_total']:.1f}",
        )
    console.print(table)


def _print_multi_round_summary(console: Console, report: dict[str, Any]) -> None:
    first = report["vulnerable"]
    last = report["defended"]
    table = Table(title="First Round vs Final Round", border_style="bright_cyan")
    table.add_column("Metric")
    table.add_column("Round 1", justify="right")
    table.add_column(f"Round {report['round_count']}", justify="right")
    table.add_row("Attack success rate", f"{first['attack_success_rate']:.1f}%", f"{last['attack_success_rate']:.1f}%")
    table.add_row("Blocked requests", str(first["blocked"]), str(last["blocked"]))
    table.add_row("Service availability", f"{first['service_availability']:.1f}%", f"{last['service_availability']:.1f}%")
    table.add_row("Normal-user success", f"{first['normal_user_success_rate']:.1f}%", f"{last['normal_user_success_rate']:.1f}%")
    table.add_row("Normal-user latency", f"{first['normal_user_latency_ms']:.1f} ms", f"{last['normal_user_latency_ms']:.1f} ms")
    table.add_row("False-positive blocks", f"{first['false_positive_blocks']:.0f}", f"{last['false_positive_blocks']:.0f}")
    table.add_row("Red score", f"{first['red_score']:.1f}", f"{last['red_score']:.1f}")
    table.add_row("Blue score", f"{first['blue_score']:.1f}", f"{last['blue_score']:.1f}")
    console.print(table)


def _battle_round_intro(console: Console, title: str, explanation: str, presentation: bool) -> None:
    console.print(Panel(explanation, title=title, border_style="bright_cyan", padding=(1, 2)))
    _pause(presentation)


def _build_battle_report(report: dict[str, Any], figure_paths: dict[str, Path]) -> str:
    rounds = report["rounds"]
    timeline = "\n".join(
        f"| {r['round']} | {r['title']} | {', '.join(r['blue_decision']['actions'])} | "
        f"{r['scores']['red_total']:.1f} | {r['scores']['blue_total']:.1f} |"
        for r in rounds
    )
    return f"""# AI vs AI Multi-Round Cyber Battle Report

## Project Overview

This is a local-only educational cyber range. The arena is a toy FastAPI communication channel: users log in, send messages, read messages, and expose a health endpoint. The battle is not a real penetration test. It is a classroom simulation that shows how attack pressure, defensive tradeoffs, and scoring can evolve over multiple rounds.

## Technical Arena

The toy service has `POST /login`, `POST /send_message`, `GET /messages`, and `GET /health`. It models four users: `alice` and `bob` as regular users, `admin` as an administrator, and `guest` as a low-privilege user. Messages can be public or private, users receive auth tokens after login, and the health endpoint exposes the current message queue size.

The simulation tracks state around that service: service availability, latency, error rate, message queue pollution, message queue size, failed-login pressure, reconnaissance exposure, false positives, false-positive blocks, normal-user latency, and normal-user success. These state variables make attacks matter beyond a simple accepted/blocked counter.

## Normal-User Simulator

During every round, legitimate users attempt to log in, send public/private messages, and read messages. This represents the business goal of the system: normal users should still be able to communicate while blue is defending the service. The judge penalizes blue when defenses cause false-positive blocks, increase normal-user latency, or reduce normal-user success.

## Red Agent Strategy

The red agent runs 6 bounded local rounds. Objectives include reconnaissance, message spam, credential pressure, payload abuse, availability disruption, and low-and-slow probing. Red adapts: if one path is heavily blocked, it shifts toward another objective such as payload abuse or stealthy probing.

## Blue Agent Strategy

The blue agent does not see the judge's ground truth before choosing. It sees only log-style symptoms: volume spikes, failed login pressure, queue pollution, error increases, unknown endpoint activity, and normal-user degradation alerts. Each round it can tune only 1-2 defenses, so it must choose between rate limiting, account lockout, payload validation, and endpoint blocking.

## Defense Tradeoffs

- Rate limiting can reduce spam and availability attacks, but it may slow or block normal-user sends and reads. If usability drops too far, blue can `loosen_rate_limit`.
- Account lockout can reduce credential attacks, but it can lock out valid users after mistakes or pressure. If false positives rise, blue can `loosen_account_lockout`.
- Payload validation blocks oversized messages, but strict validation can reject legitimate long messages.
- Aggressive blocking can reduce reconnaissance, but it has a higher false-positive and defense-cost penalty. Blue can `reduce_aggressive_blocking`.
- Allowlisting normal-user patterns can recover legitimate traffic, but it consumes part of blue's limited action budget.

## Judge Scoring System

The judge has full ground truth after each round. Red receives attack success, disruption, reconnaissance, and stealth points. Blue receives blocked attack, availability, normal-user success, low false-positive, and defense-efficiency points.

The scoring formula is intentionally presentation-friendly: each component is capped, and totals are shown separately for red and blue so the audience can see the tradeoff between stopping attacks and preserving service quality. Normal-user success, normal-user latency, and false-positive blocks are part of the judge's ground truth, but blue only sees symptoms before it chooses defenses.

## Round Timeline

| Round | Battle Phase | Blue Action | Red Score | Blue Score |
|---:|---|---|---:|---:|
{timeline}

## Final System State

```json
{json.dumps(report["final_state"], indent=2)}
```

## Charts

![Attack Success]({_report_chart_link(figure_paths["attack_success_chart"])})

Shows first-round versus final-round red attack success.

![Blocked Requests]({_report_chart_link(figure_paths["blocked_requests_chart"])})

Shows how blue's blocking changed from the opening round to the final round.

![Service Availability]({_report_chart_link(figure_paths["service_availability_chart"])})

Shows whether the service stayed usable while defenses were added.

![Blue Score]({_report_chart_link(figure_paths["defense_score_chart"])})

Shows the judge's blue score at the start and end of the battle.

![Score Timeline]({_report_chart_link(figure_paths["score_timeline_chart"])})

Shows red and blue score changes across all rounds.

![System State Timeline]({_report_chart_link(figure_paths["system_state_timeline_chart"])})

Shows the evolving service state: availability, normal-user success, error rate, message pollution, and reconnaissance exposure.

## Limitations and Safety Statement

This is a toy local simulation. It uses bounded request patterns and a simplified scoring model. It must never target public systems, third-party services, classmates' machines, or any system you do not own and explicitly control. The goal is to explain defensive reasoning and tradeoffs, not to validate production security.
"""


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the local AI-vs-AI cybersecurity demo.")
    parser.add_argument(
        "--presentation",
        action="store_true",
        help="Use narrated classroom mode with short pauses between phases.",
    )
    parser.add_argument(
        "--no-live-server",
        action="store_true",
        help="Use the in-process app instead of binding a localhost port. Mainly useful for tests.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    run_demo(use_live_server=not args.no_live_server, presentation=args.presentation)


if __name__ == "__main__":
    main()
