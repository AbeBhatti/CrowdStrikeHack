"""Local decoy listeners bound to 127.0.0.1 only."""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from common.config import get_decoys_config


TripCallback = Callable[[dict[str, Any]], None]


@dataclass
class DecoyInstance:
    id: str
    kind: str
    host_role: str
    port: int
    honeytoken_user: str
    honeytoken_hash: str
    forecast: dict[str, Any]
    expires_at: float
    tripped: bool = False
    server: Any = None


@dataclass
class DecoyManager:
    bind_host: str = "127.0.0.1"
    on_trip: TripCallback | None = None
    active: dict[str, DecoyInstance] = field(default_factory=dict)
    _tasks: list[asyncio.Task] = field(default_factory=list)

    def __post_init__(self) -> None:
        cfg = get_decoys_config()
        self.bind_host = str(cfg.get("bind_host", "127.0.0.1"))
        if self.bind_host != "127.0.0.1":
            raise RuntimeError("decoys must bind to 127.0.0.1 only")
        self.ports = dict(cfg.get("ports", {}))
        self.max_per_role = int(cfg.get("max_active_per_role", 2))
        self.expire_minutes = float(cfg.get("expire_replay_minutes", 60))

    def _honeytoken(self) -> tuple[str, str, str]:
        user = f"decoy_{secrets.token_hex(3)}"
        password = secrets.token_urlsafe(12)
        digest = hashlib.sha256(f"{user}:{password}".encode()).hexdigest()
        return user, password, digest

    async def deploy(
        self,
        kind: str,
        host_role: str,
        forecast: dict[str, Any],
        now: float | None = None,
    ) -> DecoyInstance:
        role_count = sum(1 for d in self.active.values() if d.host_role == host_role and not d.tripped)
        if role_count >= self.max_per_role:
            raise RuntimeError("max active decoys for role")
        port_key = {
            "http_login": "http",
            "ssh": "ssh",
            "canary_dns": "dns",
            "fileshare": "fileshare",
        }.get(kind, "http")
        port = int(self.ports[port_key])
        user, password, digest = self._honeytoken()
        decoy_id = f"decoy-{secrets.token_hex(4)}"
        now = now or time.time()
        inst = DecoyInstance(
            id=decoy_id,
            kind=kind,
            host_role=host_role,
            port=port,
            honeytoken_user=user,
            honeytoken_hash=digest,
            forecast=forecast,
            expires_at=now + self.expire_minutes * 60,
        )
        if kind in {"http_login", "fileshare"}:
            inst.server = await self._start_http(inst, password)
        elif kind == "ssh":
            inst.server = await self._start_ssh(inst, password)
        elif kind == "canary_dns":
            inst.server = await self._start_dns(inst)
        else:
            raise ValueError(f"unknown decoy kind {kind}")
        self.active[decoy_id] = inst
        # stash plaintext only in memory for simulator; never log it as a real cred
        inst.__dict__["_password"] = password  # noqa: SLF001
        return inst

    def _emit_trip(self, inst: DecoyInstance, source: str, detail: str) -> None:
        inst.tripped = True
        event = {
            "type": "decoy_trip",
            "decoy_id": inst.id,
            "kind": inst.kind,
            "host_role": inst.host_role,
            "source": source,
            "detail": detail,
            "honeytoken_user": inst.honeytoken_user,
            "forecast": inst.forecast,
            "simulated": "simulated" in detail.lower(),
            "priority": "highest",
        }
        if self.on_trip:
            self.on_trip(event)

    async def _start_http(self, inst: DecoyInstance, password: str) -> asyncio.AbstractServer:
        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            peer = writer.get_extra_info("peername")
            source = str(peer[0]) if peer else "unknown"
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=2.0)
                text = data.decode("utf-8", errors="ignore")
                if inst.honeytoken_user in text or password in text or "Authorization" in text:
                    self._emit_trip(inst, source, "http auth attempt")
                body = (
                    "<html><body><h1>Admin Login</h1>"
                    "<form method='POST'><input name='user'/><input name='pass'/></form>"
                    "</body></html>"
                )
                resp = (
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                    f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}"
                )
                writer.write(resp.encode())
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(handle, self.bind_host, inst.port)
        return server

    async def _start_ssh(self, inst: DecoyInstance, password: str) -> Any:
        try:
            import asyncssh
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("asyncssh required") from exc

        class Server(asyncssh.SSHServer):
            def password_auth_supported(self) -> bool:
                return True

            def validate_password(self, username: str, password_attempt: str) -> bool:
                ok = username == inst.honeytoken_user or password_attempt == password
                self_outer = self

                def _trip() -> None:
                    self_outer_mgr._emit_trip(inst, "127.0.0.1", "ssh auth attempt")

                # bind manager
                return False  # never open a shell; still count attempt below

        self_outer_mgr = self

        async def _process(process: asyncssh.SSHServerProcess) -> None:
            process.exit(0)

        def server_factory() -> asyncssh.SSHServer:
            class TripServer(asyncssh.SSHServer):
                def password_auth_supported(self) -> bool:
                    return True

                def validate_password(self, username: str, password_attempt: str) -> bool:
                    self_outer_mgr._emit_trip(
                        inst, "127.0.0.1", f"ssh auth attempt user={username}"
                    )
                    return False

                def begin_auth(self, username: str) -> bool:
                    return True

            return TripServer()

        key = asyncssh.generate_private_key("ssh-ed25519")
        return await asyncssh.create_server(
            server_factory,
            self.bind_host,
            inst.port,
            server_host_keys=[key],
            process_factory=_process,
        )

    async def _start_dns(self, inst: DecoyInstance) -> asyncio.DatagramTransport:
        class Proto(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                self_outer_mgr._emit_trip(inst, addr[0], "canary dns lookup")

        self_outer_mgr = self
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            Proto, local_addr=(self.bind_host, inst.port)
        )
        return transport

    async def remove(self, decoy_id: str) -> None:
        inst = self.active.pop(decoy_id, None)
        if not inst:
            return
        server = inst.server
        if server is None:
            return
        if hasattr(server, "close"):
            server.close()
            wait = getattr(server, "wait_closed", None)
            if wait:
                await wait()

    def assert_localhost_only(self) -> None:
        if self.bind_host != "127.0.0.1":
            raise AssertionError("decoy bind host must be 127.0.0.1")
