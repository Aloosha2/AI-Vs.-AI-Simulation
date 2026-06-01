# AI Cyber Range: Local Red-Team vs Blue-Team Simulation

This repository contains a local-only educational cybersecurity simulation for a class demo. It uses a toy FastAPI communication server, a bounded red-team agent, a blue-team log analysis agent, and a judge that scores attack/defense rounds.

## Safety Notice

This project must only run locally on your own machine. The red-team agent is intentionally bounded and uses FastAPI's in-process test client for the judge, but the code and techniques are for education only. Do not target public IPs, third-party systems, real services, classmates' machines, or any system you do not own and explicitly control.

## What It Demonstrates

- A vulnerable toy communication API with `/login`, `/send_message`, `/messages`, and `/health`.
- Baseline weaknesses: no rate limiting, weak payload validation, no message size limit, and verbose errors.
- Safe local red-team scenarios: failed login bursts, message spam, oversized payloads, malformed JSON, and endpoint probing.
- Blue-team response: log review, suspicious behavior summaries, rate limiting, account lockout, payload validation, and safer errors.
- A judge that compares a vulnerable baseline round with a defended round.
- A Rich terminal dashboard with cyber-themed panels, an event feed, service health, and a live scoreboard.
- Explicit agent loops that are easy to explain in a presentation.

## Agent Loops

The red agent runs a fixed safe local loop:

```text
observe service state -> choose safe attack strategy -> execute bounded attack -> record findings
```

The blue agent runs a defensive loop:

```text
observe logs and attack results -> identify suspicious behavior -> choose defense action -> apply defense -> rerun validation tests
```

Each agent writes structured JSON-lines logs:

- `logs/red_agent.jsonl`
- `logs/blue_agent.jsonl`
- `logs/round_reports.jsonl`

## Project Structure

```text
app/
  server.py       FastAPI toy communication API
  security.py     Defense toggles, local state, and JSON-lines logging
agents/
  red_agent.py    Bounded local attack simulation
  blue_agent.py   Log analysis and defense activation
  judge.py        Runs attack/defense rounds and scores results
  dashboard.py    Rich terminal visual demo
  demo.py         One-command classroom demo mode
tests/
  test_agents.py
  test_server.py
requirements.txt
README.md
demo.py
```

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run the Toy API Locally

The server should only be bound to localhost:

```bash
uvicorn app.server:app --host 127.0.0.1 --port 8000 --reload
```

Try a health check:

```bash
curl http://127.0.0.1:8000/health
```

## Run the AI vs AI Simulation

The judge uses the app in-process and does not contact external hosts.

```bash
python -m agents.judge
```

Example output includes a baseline score, a defended score, and blue-team findings. Logs are written locally as JSON lines in `logs/security.log`.

## Run the Classroom Demo

Use this single command for a reliable before/after presentation:

```bash
python demo.py --presentation
```

Demo mode:

- Starts the FastAPI server on an automatically selected `127.0.0.1` localhost port.
- Narrates each phase with presentation-friendly explanations and short pauses.
- Runs one vulnerable red-team round and shows successful attacks.
- Runs the blue-team agent to analyze logs, choose a defense action, apply defenses, and validate them.
- Runs a second red-team round against the defended service.
- Prints a clean before/after summary with attack success rate, blocked requests, average response time, service availability, and judge score.
- Automatically saves demo data, charts, and a Markdown report.

It is designed to finish under 60 seconds and writes demo logs under `logs/demo_*`.

Demo artifacts are saved here:

- `results/demo_results.json`: structured before/after metrics and artifact paths.
- `results/demo_report.md`: presentation-ready report explaining the scenario, technical setup, agent strategies, scoring, charts, limitations, and safety statement.
- `results/figures/attack_success_before_after.png`
- `results/figures/blocked_requests_before_after.png`
- `results/figures/service_availability_before_after.png`
- `results/figures/defense_score_before_after.png`

For fast testing without narration:

```bash
python -m agents.demo
```

## Launch the Visual Demo

The Rich dashboard is an optional animated view:

```bash
python -m agents.dashboard
```

It runs fully locally and shows:

- Red-team actions as they execute.
- Blue-team findings and enabled defenses.
- Service health.
- Event feed entries such as `RED AGENT: burst login attack`, `BLUE AGENT: enabled rate limiter`, and `JUDGE: attack partially mitigated`.
- Scoreboard metrics for attack success rate, blocked requests, average response time, service availability, and defense actions enabled.

## Run Tests

```bash
pytest
```

## Demo Notes

1. Start with the baseline server state and show `/health` reporting disabled defenses.
2. Run `python demo.py --presentation` for the narrated classroom before/after demo.
3. Discuss which red-team scenarios were accepted by the vulnerable baseline.
4. Review `logs/security.log` to show what the blue agent sees.
5. Explain how the defended round changes outcomes through rate limiting, account lockout, payload validation, and safer errors.

This is a deliberately simplified model. It is useful for learning defensive reasoning and secure design basics, not for testing real systems.
