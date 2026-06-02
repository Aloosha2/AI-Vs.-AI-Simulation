from pathlib import Path

from agents.demo import run_demo


def test_demo_mode_runs_before_after_flow():
    report = run_demo(use_live_server=False)

    assert report["vulnerable"]["attack_success_rate"] > report["defended"]["attack_success_rate"]
    assert report["round_count"] == 6
    assert report["defended"]["blue_score"] > 0
    assert "rounds" in report
    assert any(
        "allowlist_normal_user_patterns" in round_data["blue_decision"]["actions"]
        or "loosen_rate_limit" in round_data["blue_decision"]["actions"]
        or "loosen_account_lockout" in round_data["blue_decision"]["actions"]
        or "reduce_aggressive_blocking" in round_data["blue_decision"]["actions"]
        for round_data in report["rounds"]
    )
    assert report["rounds"][-1]["system_state"]["normal_user_success_rate"] > report["rounds"][-2]["system_state"]["normal_user_success_rate"]
    assert report["artifacts"]["data"].endswith("results/demo_results.json")
    assert report["artifacts"]["round_history"].endswith("results/round_history.json")
    assert report["artifacts"]["report"].endswith("results/demo_report.md")
    for chart_name in [
        "attack_success_chart",
        "blocked_requests_chart",
        "service_availability_chart",
        "defense_score_chart",
        "score_timeline_chart",
        "system_state_timeline_chart",
    ]:
        assert report["artifacts"][chart_name].endswith(".png")
        assert Path(report["artifacts"][chart_name]).exists()
    assert Path(report["artifacts"]["data"]).exists()
    assert Path(report["artifacts"]["round_history"]).exists()
    report_text = Path(report["artifacts"]["report"]).read_text(encoding="utf-8")
    assert "Technical Arena" in report_text
    assert "Red Agent Strategy" in report_text
    assert "Blue Agent Strategy" in report_text
    assert "Defense Tradeoffs" in report_text
    assert "Limitations and Safety Statement" in report_text
