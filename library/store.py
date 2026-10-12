"""Shared defense library in SQLite. Rules only; never logs."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from common.config import HELD_OUT_SCENARIOS, project_root


class DefenseLibrary:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (project_root() / "models" / "defense_library.sqlite")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    def _init(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS rules (
                    id TEXT PRIMARY KEY,
                    rule_json TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    origin_company TEXT NOT NULL,
                    created_time REAL NOT NULL,
                    validation_json TEXT NOT NULL,
                    shared INTEGER NOT NULL DEFAULT 0
                )
                """
            )

    def add_rule(
        self,
        rule: dict[str, Any],
        *,
        origin_company: str,
        validation: dict[str, Any],
        shared: bool,
    ) -> str:
        if origin_company in HELD_OUT_SCENARIOS:
            raise AssertionError("held-out scenario cannot originate a library rule")
        validated = validation.get("companies", [])
        if any(c in HELD_OUT_SCENARIOS for c in validated):
            raise AssertionError("held-out scenario cannot appear in validation set")
        rid = rule.get("id") or f"rule-{origin_company}-{int(time.time() * 1000)}"
        rule = {**rule, "id": rid, "origin_company": origin_company}
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO rules VALUES (?,?,?,?,?,?,?)",
                (
                    rid,
                    json.dumps(rule),
                    rule.get("stage_detected", ""),
                    origin_company,
                    time.time(),
                    json.dumps(validation),
                    1 if shared else 0,
                ),
            )
        return rid

    def shared_rules(self) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT rule_json, origin_company, validation_json FROM rules WHERE shared=1"
            ).fetchall()
        out = []
        for rule_json, origin, validation_json in rows:
            rule = json.loads(rule_json)
            rule["origin_company"] = origin
            rule["validation"] = json.loads(validation_json)
            out.append(rule)
        return out

    def all_rules(self) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT rule_json, origin_company, shared, validation_json FROM rules"
            ).fetchall()
        out = []
        for rule_json, origin, shared, validation_json in rows:
            rule = json.loads(rule_json)
            rule["origin_company"] = origin
            rule["shared"] = bool(shared)
            rule["validation"] = json.loads(validation_json)
            out.append(rule)
        return out

    def assert_no_held_out_contamination(self) -> None:
        for rule in self.all_rules():
            if rule.get("origin_company") in HELD_OUT_SCENARIOS:
                raise AssertionError("held-out origin in library")
            comps = rule.get("validation", {}).get("companies", [])
            if any(c in HELD_OUT_SCENARIOS for c in comps):
                raise AssertionError("held-out in validation set")
