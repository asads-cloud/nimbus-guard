from __future__ import annotations
"""
Nimbus Guard; VPC checks (Default VPC Flow Logs)
=================================================
Public entry point:
    run(client_factory, regions) -> List[Dict[str, Any]]
"""
from typing import Any, Callable, Dict, Iterable, List, Optional

#------------- Pagination helper ---------------------------------------------------------------------------------

def _paginate(client: Any, method: str, result_key: str, **kwargs) -> Iterable[Dict[str, Any]]:
    """
    Generic paginator for EC2 describe_* calls (NextToken/MaxResults).
    Yields items under `result_key` across all pages. Returns early on errors.
    """
    token: Optional[str] = None
    while True:
        params = dict(MaxResults=1000, **kwargs)
        if token:
            params["NextToken"] = token
        try:
            resp = getattr(client, method)(**params)
        except Exception:
            return
        for item in resp.get(result_key, []) or []:
            yield item
        token = resp.get("NextToken")
        if not token:
            return

#------------- VPC helpers ---------------------------------------------------------------------------------

def _get_default_vpcs(ec2: Any) -> List[Dict[str, Any]]:
    """
    Return all default VPCs in the current region, or an empty list on failure.
    """
    try:
        resp = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
    except Exception:
        return []
    return resp.get("Vpcs", []) or []

def _has_active_flow_log_for_vpc(ec2: Any, vpc_id: str) -> bool:
    """
    True iff there is at least one ACTIVE flow log attached to the given VPC.
    """
    try:
        for fl in _paginate(
            ec2,
            "describe_flow_logs",
            "FlowLogs",
            Filter=[{"Name": "resource-id", "Values": [vpc_id]}],
        ):
            if (fl.get("ResourceId") == vpc_id) and (fl.get("FlowLogStatus") == "ACTIVE"):
                return True
    except Exception:
        return False
    return False

#------------- Entry point ---------------------------------------------------------------------------------

def run(client_factory: Callable[[str, Optional[str]], Any], regions: List[str]) -> List[Dict[str, Any]]:
    """
    For each region, evaluate default VPCs for ACTIVE Flow Logs and emit HIGH
    findings if missing. Returns a flat list of findings.
    """
    findings: List[Dict[str, Any]] = []

    for region in regions:
        ec2 = client_factory("ec2", region)
        try:
            defaults = _get_default_vpcs(ec2)
        except Exception:
            # Per constraints: do not crash on region failure
            defaults = []

        for vpc in defaults:
            vpc_id = vpc.get("VpcId") or "unknown"
            has_active = _has_active_flow_log_for_vpc(ec2, vpc_id)

            if not has_active:
                findings.append({
                    "service": "vpc",
                    "resource_id": vpc_id,
                    "title": "Default VPC missing ACTIVE Flow Logs",
                    "severity": "HIGH",
                    "region": region,
                    "details": {
                        "vpc_id": vpc_id,
                        "cidr_block": vpc.get("CidrBlock"),
                        "tags": vpc.get("Tags", []),
                        "is_default": True,
                        "reason": "No ACTIVE flow logs found for default VPC",
                    },
                })

    return findings
