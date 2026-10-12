"""Group relevant alerts into incidents by source, host role, and time proximity."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from common.config import get_thresholds
from common.stages import is_attack_stage


@dataclass
class Incident:
    id: str
    sources: list[str]
    hosts: list[str]
    host_roles: list[str]
    stages: list[str]
    first_time: int
    last_time: int
    alert_counts: dict[str, int]
    severity: float
    incident_type: str  # intrusion | exfil
    alert_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "sources": self.sources,
            "hosts": self.hosts,
            "host_roles": self.host_roles,
            "stages": self.stages,
            "first_time": self.first_time,
            "last_time": self.last_time,
            "alert_counts": self.alert_counts,
            "severity": self.severity,
            "incident_type": self.incident_type,
            "alert_ids": self.alert_ids,
        }


SEVERITY_BY_STAGE = {
    "recon": 0.2,
    "web_scan": 0.35,
    "webshell": 0.75,
    "cracking": 0.55,
    "reverse_shell": 0.9,
    "privilege_escalation": 0.95,
    "service_stop": 0.6,
    "exfil": 0.85,
}


class IncidentGrouper:
    def __init__(self, proximity_seconds: int | None = None) -> None:
        thr = get_thresholds()["incidents"]
        self.proximity = int(proximity_seconds or thr["proximity_seconds"])
        self.min_alerts = int(thr.get("min_alerts", 1))
        self._open: dict[str, Incident] = {}
        self._closed: list[Incident] = []
        self._seq = 0

    def _key(self, alert: dict[str, Any], incident_type: str) -> str:
        source = str(alert.get("ip") or alert.get("host") or "unknown")
        role = str(alert.get("host_role", "unknown"))
        return f"{incident_type}|{source}|{role}"

    def _severity(self, counts: dict[str, int], stages: list[str]) -> float:
        base = max((SEVERITY_BY_STAGE.get(s, 0.1) for s in stages), default=0.1)
        return float(min(1.0, base + 0.02 * sum(counts.values()) ** 0.5))

    def push(self, alert: dict[str, Any], relevant: bool = True) -> Incident | None:
        stage = str(alert.get("pred_stage") or alert.get("stage") or "none")
        if not relevant and not is_attack_stage(stage):
            return None
        if not is_attack_stage(stage):
            return None
        incident_type = "exfil" if stage == "exfil" else "intrusion"
        key = self._key(alert, incident_type)
        ts = int(alert["time"])
        source = str(alert.get("ip") or alert.get("host") or "unknown")
        host = str(alert.get("host", ""))
        role = str(alert.get("host_role", "unknown"))
        aid = str(alert.get("alert_id", ""))

        cur = self._open.get(key)
        if cur and ts - cur.last_time <= self.proximity and cur.incident_type == incident_type:
            if stage not in cur.stages:
                cur.stages.append(stage)
            cur.last_time = ts
            cur.alert_counts[stage] = cur.alert_counts.get(stage, 0) + 1
            if source not in cur.sources:
                cur.sources.append(source)
            if host and host not in cur.hosts:
                cur.hosts.append(host)
            if role not in cur.host_roles:
                cur.host_roles.append(role)
            if aid:
                cur.alert_ids.append(aid)
            cur.severity = self._severity(cur.alert_counts, cur.stages)
            return cur

        if cur:
            self._closed.append(cur)
        self._seq += 1
        inc = Incident(
            id=f"inc-{self._seq}",
            sources=[source],
            hosts=[host] if host else [],
            host_roles=[role],
            stages=[stage],
            first_time=ts,
            last_time=ts,
            alert_counts={stage: 1},
            severity=self._severity({stage: 1}, [stage]),
            incident_type=incident_type,
            alert_ids=[aid] if aid else [],
        )
        self._open[key] = inc
        return inc

    def flush(self) -> list[Incident]:
        self._closed.extend(self._open.values())
        self._open = {}
        out = [i for i in self._closed if sum(i.alert_counts.values()) >= self.min_alerts]
        self._closed = []
        return out

    def group_alerts(self, alerts: list[dict[str, Any]]) -> list[Incident]:
        for a in sorted(alerts, key=lambda x: int(x["time"])):
            self.push(a)
        return self.flush()


def collapse_report(scenario: str, alerts: list[dict[str, Any]], incidents: list[Incident]) -> str:
    return (
        f"{scenario}: {len(alerts)} alerts -> {len(incidents)} incidents "
        f"(intrusion={sum(1 for i in incidents if i.incident_type=='intrusion')}, "
        f"exfil={sum(1 for i in incidents if i.incident_type=='exfil')})"
    )
