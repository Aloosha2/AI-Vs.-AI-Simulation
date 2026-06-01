"""Reliable classroom demo mode for the local AI-vs-AI simulation."""

from __future__ import annotations

import argparse
from contextlib import AbstractContextManager
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
        "report": "Markdown report",
        "attack_success_chart": "Attack success chart",
        "blocked_requests_chart": "Blocked requests chart",
        "service_availability_chart": "Service availability chart",
        "defense_score_chart": "Defense score chart",
    }
    for key, path in result_paths.items():
        table.add_row(labels.get(key, key), str(path))
    console.print(table)


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
