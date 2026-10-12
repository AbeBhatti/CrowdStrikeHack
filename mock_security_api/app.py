"""Local mock firewall/EDR API. Binds to 127.0.0.1 only."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

app = FastAPI(title="Mock Security API", version="0.1.0")

_state: dict[str, Any] = {
    "blocked_ips": set(),
    "isolated_hosts": set(),
    "blocked_dns": set(),
    "log": [],
}


def _log(action: str, payload: dict[str, Any]) -> None:
    _state["log"].append(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "payload": payload,
        }
    )


class IpBody(BaseModel):
    ip: str = Field(min_length=3, max_length=64)


class HostBody(BaseModel):
    host: str = Field(min_length=1, max_length=128)
    host_role: str = "unknown"


class DnsBody(BaseModel):
    domain: str = Field(min_length=1, max_length=253)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/state")
def state() -> dict[str, Any]:
    return {
        "blocked_ips": sorted(_state["blocked_ips"]),
        "isolated_hosts": sorted(_state["isolated_hosts"]),
        "blocked_dns": sorted(_state["blocked_dns"]),
        "log": list(_state["log"][-200:]),
    }


@app.post("/block_ip")
def block_ip(body: IpBody) -> dict[str, Any]:
    _state["blocked_ips"].add(body.ip)
    _log("block_ip", body.model_dump())
    return {"ok": True, "blocked_ips": sorted(_state["blocked_ips"])}


@app.post("/unblock_ip")
def unblock_ip(body: IpBody) -> dict[str, Any]:
    _state["blocked_ips"].discard(body.ip)
    _log("unblock_ip", body.model_dump())
    return {"ok": True}


@app.post("/isolate_host")
def isolate_host(body: HostBody) -> dict[str, Any]:
    _state["isolated_hosts"].add(body.host)
    _log("isolate_host", body.model_dump())
    return {"ok": True}


@app.post("/release_host")
def release_host(body: HostBody) -> dict[str, Any]:
    _state["isolated_hosts"].discard(body.host)
    _log("release_host", body.model_dump())
    return {"ok": True}


@app.post("/block_dns_egress")
def block_dns_egress(body: DnsBody) -> dict[str, Any]:
    _state["blocked_dns"].add(body.domain)
    _log("block_dns_egress", body.model_dump())
    return {"ok": True}


@app.post("/reset")
def reset() -> dict[str, bool]:
    _state["blocked_ips"].clear()
    _state["isolated_hosts"].clear()
    _state["blocked_dns"].clear()
    _state["log"].clear()
    return {"ok": True}


def create_app() -> FastAPI:
    return app


def main() -> None:
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8101, log_level="info")


if __name__ == "__main__":
    main()
