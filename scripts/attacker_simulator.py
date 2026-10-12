#!/usr/bin/env python3
"""SIMULATED attacker: follows a forecast and touches the deployed decoy for real.

This is labeled simulated in the UI, README, and DEMO.md. The trip must come
from the real decoy service, not a faked backend event.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

import httpx


async def touch_http(port: int, user: str, password: str) -> None:
    async with httpx.AsyncClient(timeout=5.0) as client:
        await client.post(
            f"http://127.0.0.1:{port}/login",
            data={"user": user, "pass": password},
        )


async def touch_ssh(port: int, user: str, password: str) -> None:
    try:
        import asyncssh
    except ImportError:
        # Fallback TCP connect still generates a trip if server counts any auth attempt
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.close()
        await writer.wait_closed()
        return
    try:
        async with asyncssh.connect(
            "127.0.0.1",
            port=port,
            username=user,
            password=password,
            known_hosts=None,
        ):
            pass
    except Exception:
        # Auth failure is expected; decoy should still have logged the attempt.
        pass


async def main_async() -> int:
    p = argparse.ArgumentParser(description="SIMULATED attacker decoy touch")
    p.add_argument("--kind", required=True, choices=["http_login", "ssh", "canary_dns", "fileshare"])
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--user", default="decoy")
    p.add_argument("--password", default="x")
    args = p.parse_args()
    print(f"SIMULATED attacker touching {args.kind} on 127.0.0.1:{args.port}", flush=True)
    if args.kind in {"http_login", "fileshare"}:
        # raw TCP POST so simple asyncio decoy sees credentials
        reader, writer = await asyncio.open_connection("127.0.0.1", args.port)
        body = f"user={args.user}&pass={args.password}"
        req = (
            f"POST /login HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}"
        )
        writer.write(req.encode())
        await writer.drain()
        await reader.read(1024)
        writer.close()
        await writer.wait_closed()
    elif args.kind == "ssh":
        await touch_ssh(args.port, args.user, args.password)
    elif args.kind == "canary_dns":
        # UDP query to canary port
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol, remote_addr=("127.0.0.1", args.port)
        )
        transport.sendto(b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        transport.close()
    print("SIMULATED touch complete", flush=True)
    return 0


def main() -> None:
    raise SystemExit(asyncio.run(main_async()))


if __name__ == "__main__":
    main()
