from fastapi.testclient import TestClient

from agents.blue_agent import BlueAgent
from agents.judge import Judge
from agents.red_agent import SAFE_STRATEGIES, RedAgent
from app import security
from app.server import app, reset_app_state


def setup_function():
    reset_app_state(clear_log=True)


def test_red_agent_runs_only_bounded_local_scenarios():
    client = TestClient(app)

    summary = RedAgent(client, max_attempts=4).run_loop("test_red_round")
    results = summary.results

    assert {result.name for result in results} == {
        "repeated_failed_logins",
        "burst_message_spam",
        "oversized_payload",
        "malformed_json",
        "endpoint_probing",
    }
    assert summary.strategies_run == SAFE_STRATEGIES
    assert len(summary.findings) == len(SAFE_STRATEGIES)
    assert sum(result.attempts for result in results) <= 4 + 1 + 4 + 1 + 4


def test_blue_agent_loop_summarizes_suspicious_logs_and_enables_defenses(tmp_path):
    security.configure_log_file(tmp_path / "security.log")
    client = TestClient(app)
    red_summary = RedAgent(client, max_attempts=4, log_file=tmp_path / "red.jsonl").run_loop("test_red")
    blue = BlueAgent(
        tmp_path / "security.log",
        client=client,
        agent_log_file=tmp_path / "blue.jsonl",
    )

    summary = blue.run_loop("test_blue", red_summary.results)

    assert summary.observation.total_events > 0
    assert any("failed logins" in finding for finding in summary.findings)
    assert summary.decision.action == "enable_standard_defenses"
    assert summary.defenses_enabled["rate_limit_enabled"] is True
    assert summary.defenses_enabled["safer_errors_enabled"] is True
    assert all(result.passed for result in summary.validation_results)
    assert (tmp_path / "blue.jsonl").exists()


def test_judge_defended_round_scores_higher_than_baseline(tmp_path):
    report = Judge(tmp_path / "security.log").run()

    assert report["baseline"]["score"] < report["defended"]["score"]
    assert report["improvement"] > 0
    assert report["baseline"]["red_summary"]["strategies_run"] == SAFE_STRATEGIES
    assert report["defended"]["blue_summary"]["decision"]["action"] == "no_change"
    assert security.config.rate_limit_enabled is True
    assert (tmp_path / "round_reports.jsonl").exists()
