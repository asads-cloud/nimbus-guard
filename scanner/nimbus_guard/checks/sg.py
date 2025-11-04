from __future__ import annotations
"""
Nimbus Guard; Security Group checks (EC2)
==========================================
Public entry point:
    run(client_factory, regions) -> List[Dict[str, Any]]
"""
from typing import Any, Callable, Dict, Iterable, List, Optional

#------------- Constants ---------------------------------------------------------------------------------

SENSITIVE_PORTS = {22, 3389}  # SSH, RDP

#------------- Helpers ---------------------------------------------------------------------------------

def _paginate(client: Any, method: str, result_key: str, **kwargs) -> Iterable[Dict[str, Any]]:
    """
    Generic paginator for EC2 describe_* calls using NextToken/MaxResults.
    Yields individual items from `result_key` across all pages.
    Returns early on API exceptions to keep the scanner resilient.
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

def _is_world_cidr(cidr: Optional[str]) -> bool:
    """
    True if the CIDR represents the IPv4 or IPv6 universal "any" network.
    """
    if not cidr:
        return False
    c = cidr.strip()
    return c == "0.0.0.0/0" or c == "::/0"

def _perm_port_span(perm: Dict[str, Any]) -> Optional[tuple]:
    """
    Return (from_port, to_port) for a permission. If IpProtocol == "-1" (all),
    return None to indicate "all ports". If ports are omitted for a protocol,
    conservatively treat as 0-65535.
    """
    proto = perm.get("IpProtocol")
    if proto == "-1":
        return None
    if "FromPort" not in perm or "ToPort" not in perm:
        return (0, 65535)
    return (int(perm.get("FromPort", 0)), int(perm.get("ToPort", 65535)))

def _classify_severity(perm: Dict[str, Any]) -> str:
    """
    Severity classification for world-open rules:
      - CRITICAL for all protocols/ports, or if the span covers 0–65535,
        or if it includes sensitive admin ports (22/3389).
      - HIGH otherwise.
    """
    proto = perm.get("IpProtocol")
    if proto == "-1":
        return "CRITICAL"

    span = _perm_port_span(perm)
    if span is None:
        return "CRITICAL"

    f, t = span
    if f <= 0 and t >= 65535:
        return "CRITICAL"

    for p in SENSITIVE_PORTS:
        if f <= p <= t:
            return "CRITICAL"

    return "HIGH"

def _sg_name(sg: Dict[str, Any]) -> str:
    return sg.get("GroupName") or sg.get("GroupId") or "unknown"


def _collect_world_rules(sg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Scan a single Security Group for world-open ingress rules and emit findings.
    The caller is expected to stamp `RegionName` on `sg` before calling this.
    """
    findings: List[Dict[str, Any]] = []
    perms = sg.get("IpPermissions", []) or []

    for perm in perms:
        world_hit = False

        # IPv4 ranges
        for r in perm.get("IpRanges", []) or []:
            if _is_world_cidr(r.get("CidrIp")):
                world_hit = True
                break

        # IPv6 ranges
        if not world_hit:
            for r in perm.get("Ipv6Ranges", []) or []:
                if _is_world_cidr(r.get("CidrIpv6")):
                    world_hit = True
                    break

        if not world_hit:
            continue

        sev = _classify_severity(perm)
        span = _perm_port_span(perm)
        ports = "ALL" if span is None else f"{span[0]}-{span[1]}"

        findings.append({
            "service": "sg",
            "resource_id": sg.get("GroupId") or _sg_name(sg),
            "title": f"Security Group open to world on ports {ports}",
            "severity": sev,
            "region": sg.get("RegionName"),  # region stamped by caller
            "details": {
                "group_id": sg.get("GroupId"),
                "group_name": sg.get("GroupName"),
                "vpc_id": sg.get("VpcId"),
                "ip_protocol": perm.get("IpProtocol"),
                "from_port": None if span is None else span[0],
                "to_port": None if span is None else span[1],
                "world_ipv4": any(_is_world_cidr(r.get("CidrIp")) for r in perm.get("IpRanges", []) or []),
                "world_ipv6": any(_is_world_cidr(r.get("CidrIpv6")) for r in perm.get("Ipv6Ranges", []) or []),
                "prefix_list_ids": [pl.get("PrefixListId") for pl in perm.get("PrefixListIds", []) or []],
                "user_id_group_pairs": [p.get("GroupId") for p in perm.get("UserIdGroupPairs", []) or []],
                "description": perm.get("Description"),
            }
        })

    return findings

#------------- Entry point ---------------------------------------------------------------------------------

def run(client_factory: Callable[[str, Optional[str]], Any], regions: List[str]) -> List[Dict[str, Any]]:
    """
    Evaluate all Security Groups in each region and flag world-open ingress rules.
    Returns a flat list of findings.
    """
    all_findings: List[Dict[str, Any]] = []

    for region in regions:
        ec2 = client_factory("ec2", region)
        try:
            for sg in _paginate(ec2, "describe_security_groups", "SecurityGroups"):
                # Stamp region for reporting; preserved from original behavior
                sg["RegionName"] = region
                all_findings.extend(_collect_world_rules(sg))
        except Exception:
            # If a region errors (e.g., no permissions/endpoints), continue scanning others
            continue

    return all_findings
