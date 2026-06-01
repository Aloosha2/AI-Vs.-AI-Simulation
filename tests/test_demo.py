from pathlib import Path

from agents.demo import run_demo


def test_demo_mode_runs_before_after_flow():
    report = run_demo(use_live_server=False)

    assert report["vulnerable"]["attack_success_rate"] > report["defended"]["attack_success_rate"]
    assert report["defended"]["blocked"] > report["vulnerable"]["blocked"]
    assert report["blue_decision"] == "enable_standard_defenses"
    assert report["validation_passed"] is True
    assert report["artifacts"]["data"].endswith("results/demo_results.json")
    assert report["artifacts"]["report"].endswith("results/demo_report.md")
    for chart_name in [
        "attack_success_chart",
        "blocked_requests_chart",
        "service_availability_chart",
        "defense_score_chart",
    ]:
        assert report["artifacts"][chart_name].endswith(".png")
        assert Path(report["artifacts"][chart_name]).exists()
    assert Path(report["artifacts"]["data"]).exists()
    report_text = Path(report["artifacts"]["report"]).read_text(encoding="utf-8")
    assert "What the Toy Communication Channel Represents" in report_text
    assert "Red Agent Strategy" in report_text
    assert "Blue Agent Strategy" in report_text
    assert "Limitations and Safety Statement" in report_text
