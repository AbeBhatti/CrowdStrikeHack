"""Mock security API state transitions."""

from __future__ import annotations

from fastapi.testclient import TestClient

from mock_security_api.app import app


def test_block_and_isolate_cycle() -> None:
    client = TestClient(app)
    client.post("/reset")
    assert client.post("/block_ip", json={"ip": "1.2.3.4"}).json()["ok"] is True
    assert client.post("/isolate_host", json={"host": "webserver"}).json()["ok"] is True
    state = client.get("/state").json()
    assert "1.2.3.4" in state["blocked_ips"]
    assert "webserver" in state["isolated_hosts"]
    client.post("/unblock_ip", json={"ip": "1.2.3.4"})
    client.post("/release_host", json={"host": "webserver"})
    state = client.get("/state").json()
    assert "1.2.3.4" not in state["blocked_ips"]
    assert "webserver" not in state["isolated_hosts"]
