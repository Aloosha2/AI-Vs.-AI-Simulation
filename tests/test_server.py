from fastapi.testclient import TestClient

from app import security
from app.server import MESSAGES, app, reset_app_state


def setup_function():
    reset_app_state(clear_log=True)


def _login(client: TestClient) -> str:
    response = client.post("/login", json={"username": "alice", "password": "wonderland"})
    assert response.status_code == 200
    return response.json()["token"]


def test_health_endpoint_reports_default_vulnerable_controls():
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["defenses"]["rate_limit_enabled"] is False
    assert body["defenses"]["payload_validation_enabled"] is False


def test_baseline_allows_oversized_message_payload():
    client = TestClient(app)
    token = _login(client)

    response = client.post(
        "/send_message",
        json={"token": token, "recipient": "bob", "content": "A" * 5_000},
    )

    assert response.status_code == 200
    assert MESSAGES[-1]["size"] == 5_000


def test_defenses_reject_oversized_message_payload():
    client = TestClient(app)
    security.apply_defense_profile()
    token = _login(client)

    response = client.post(
        "/send_message",
        json={"token": token, "recipient": "bob", "content": "A" * 5_000},
    )

    assert response.status_code == 413
    assert response.json()["detail"] == "Payload rejected."


def test_defenses_lock_account_after_repeated_failed_logins():
    client = TestClient(app)
    security.apply_defense_profile()

    statuses = [
        client.post("/login", json={"username": "alice", "password": "bad"}).status_code
        for _ in range(4)
    ]

    assert statuses[:3] == [401, 401, 401]
    assert statuses[3] == 423


def test_defenses_rate_limit_message_spam():
    client = TestClient(app)
    security.apply_defense_profile()
    token = _login(client)

    statuses = [
        client.post(
            "/send_message",
            json={"token": token, "recipient": "bob", "content": f"msg {index}"},
        ).status_code
        for index in range(10)
    ]

    assert 429 in statuses
    assert statuses.count(200) == security.config.max_requests_per_window


def test_safer_errors_hide_verbose_validation_details():
    client = TestClient(app)
    security.apply_defense_profile()

    response = client.post(
        "/login",
        content='{"username": "alice", "password": ',
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 422
    assert response.json() == {"error": "Invalid request."}
