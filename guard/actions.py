"""Allowlisted, Pydantic-validated actions. Models never generate code."""

from __future__ import annotations

from typing import Annotated, Literal, Union

from pydantic import BaseModel, Field, TypeAdapter


class BlockIp(BaseModel):
    action: Literal["block_ip"] = "block_ip"
    ip: str = Field(min_length=3, max_length=64)
    reversible: bool = True


class UnblockIp(BaseModel):
    action: Literal["unblock_ip"] = "unblock_ip"
    ip: str = Field(min_length=3, max_length=64)
    reversible: bool = True


class IsolateHost(BaseModel):
    action: Literal["isolate_host"] = "isolate_host"
    host: str
    host_role: str = "unknown"
    reversible: bool = False


class ReleaseHost(BaseModel):
    action: Literal["release_host"] = "release_host"
    host: str
    host_role: str = "unknown"
    reversible: bool = True


class BlockDnsEgress(BaseModel):
    action: Literal["block_dns_egress"] = "block_dns_egress"
    domain: str
    reversible: bool = True


class DeployDetectionRule(BaseModel):
    action: Literal["deploy_detection_rule"] = "deploy_detection_rule"
    rule: dict
    reversible: bool = True


class DeployDecoy(BaseModel):
    action: Literal["deploy_decoy"] = "deploy_decoy"
    decoy_kind: str
    host_role: str
    reversible: bool = True


class RemoveDecoy(BaseModel):
    action: Literal["remove_decoy"] = "remove_decoy"
    decoy_id: str
    reversible: bool = True


class NotifyHuman(BaseModel):
    action: Literal["notify_human"] = "notify_human"
    summary: str = Field(max_length=500)
    reversible: bool = True


class RequestApproval(BaseModel):
    action: Literal["request_approval"] = "request_approval"
    pending_action: str
    reversible: bool = True


class PagerDutyTrigger(BaseModel):
    action: Literal["pagerduty_trigger"] = "pagerduty_trigger"
    dedup_key: str
    summary: str = Field(max_length=200)
    reversible: bool = True


class PagerDutyAcknowledge(BaseModel):
    action: Literal["pagerduty_acknowledge"] = "pagerduty_acknowledge"
    dedup_key: str
    reversible: bool = True


class PagerDutyResolve(BaseModel):
    action: Literal["pagerduty_resolve"] = "pagerduty_resolve"
    dedup_key: str
    reversible: bool = True


# Explicitly rejected if ever proposed
class AllowIp(BaseModel):
    action: Literal["allow_ip", "whitelist_ip"] = "allow_ip"
    ip: str


Action = Annotated[
    Union[
        BlockIp,
        UnblockIp,
        IsolateHost,
        ReleaseHost,
        BlockDnsEgress,
        DeployDetectionRule,
        DeployDecoy,
        RemoveDecoy,
        NotifyHuman,
        RequestApproval,
        PagerDutyTrigger,
        PagerDutyAcknowledge,
        PagerDutyResolve,
    ],
    Field(discriminator="action"),
]

ACTION_ADAPTER: TypeAdapter[Action] = TypeAdapter(Action)

ALLOWLIST = {
    "block_ip",
    "unblock_ip",
    "isolate_host",
    "release_host",
    "block_dns_egress",
    "deploy_detection_rule",
    "deploy_decoy",
    "remove_decoy",
    "notify_human",
    "request_approval",
    "pagerduty_trigger",
    "pagerduty_acknowledge",
    "pagerduty_resolve",
}
