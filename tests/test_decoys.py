"""Decoy localhost binding and trip detection."""

from __future__ import annotations

import asyncio

import pytest

from decoys.services import DecoyManager


@pytest.mark.asyncio
async def test_http_decoy_trip_and_localhost() -> None:
    trips: list[dict] = []
    mgr = DecoyManager(on_trip=lambda e: trips.append(e))
    mgr.assert_localhost_only()
    inst = await mgr.deploy(
        "http_login",
        "webserver",
        {"next_stage": "reverse_shell"},
    )
    assert inst.port == 8081
    # simulated attacker touch
    reader, writer = await asyncio.open_connection("127.0.0.1", inst.port)
    body = f"user={inst.honeytoken_user}&pass={inst.__dict__['_password']}"
    req = (
        f"POST /login HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n{body}"
    )
    writer.write(req.encode())
    await writer.drain()
    await reader.read(512)
    writer.close()
    await writer.wait_closed()
    await asyncio.sleep(0.2)
    await mgr.remove(inst.id)
    assert trips, "real decoy service must detect the trip"
    assert trips[0]["decoy_id"] == inst.id
