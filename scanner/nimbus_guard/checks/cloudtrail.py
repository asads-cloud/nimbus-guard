from __future__ import annotations
"""
Nimbus Guard; CloudTrail checks
================================
Public entry point:
    run(client_factory, regions) -> List[Dict[str, Any]]
"""
from typing import Any, Callable, Dict, List, Optional

#------------- Safe call helper ---------------------------------------------------------------------------------

def _safe(fn, *args, **kwargs):
    """
    Wrap an AWS SDK call and return None on exception.
    Keeps the checks resilient to AccessDenied and transient API issues.
    """
    try:
        return fn(*args, **kwargs)
    except Exception:
        return None

#------------- CloudTrail helpers ---------------------------------------------------------------------------------

def _describe_trails(ct: Any) -> List[Dict[str, Any]]:
    """Return the trail list or an empty list on failure."""
    resp = _safe(ct.describe_trails, includeShadowTrails=True)
    if not resp:
        return []
    return resp.get("trailList", []) or []

def _get_trail_status(ct: Any, name_or_arn: str) -> Dict[str, Any]:
    """Return get_trail_status payload or empty dict on failure."""
    resp = _safe(ct.get_trail_status, Name=name_or_arn)
    return resp or {}

def _trail_is_logging(ct: Any, trail: Dict[str, Any]) -> bool:
    """
    Best-effort logging status for a given trail using its ARN or Name.
    """
    name = trail.get("TrailARN") or trail.get("Name")
    if not name:
        return False
    status = _get_trail_status(ct, name)
    return bool(status.get("IsLogging"))

#------------- Entry point ---------------------------------------------------------------------------------

def run(client_factory: Callable[[str, Optional[str]], Any], regions: List[str]) -> List[Dict[str, Any]]:
    """
    Evaluate CloudTrail configuration for account-wide and per-region coverage.
    Returns a flat list of findings with stable titles/severities.
    """
    findings: List[Dict[str, Any]] = []

    # We’ll determine account-wide multi-region coverage by querying the first region that works.
    any_multi_region_logging = False
    checked_account_once = False

    # Pass 1: determine if any multi-region trail is actively logging (account-wide)
    for probe_region in regions:
        ct = client_factory("cloudtrail", probe_region)
        trails = _describe_trails(ct)
        if not trails:
            continue

        for t in trails:
            if t.get("IsMultiRegionTrail") is True and _trail_is_logging(ct, t):
                any_multi_region_logging = True
                break
        checked_account_once = True
        if any_multi_region_logging:
            break

    # If we could query at least once and found no multi-region logging, raise HIGH once (global)
    if checked_account_once and not any_multi_region_logging:
        findings.append({
            "service": "cloudtrail",
            "resource_id": "cloudtrail",
            "title": "No multi-region CloudTrail is actively logging",
            "severity": "HIGH",
            "region": None,
            "details": {"hint": "Enable a multi-region trail for full coverage"},
        })

    # Pass 2: per-region coverage & non-multi-region trail notes
    for region in regions:
        ct = client_factory("cloudtrail", region)
        trails = _describe_trails(ct) or []

        region_has_logging = False

        # Evaluate each trail visible in this region
        for t in trails:
            is_multi = bool(t.get("IsMultiRegionTrail"))
            name = t.get("Name") or t.get("TrailARN") or "unknown"
            home = t.get("HomeRegion")

            # Note any single-region trails (MEDIUM)
            if not is_multi:
                findings.append({
                    "service": "cloudtrail",
                    "resource_id": name,
                    "title": "CloudTrail trail is not multi-region",
                    "severity": "MEDIUM",
                    "region": home or region,
                    "details": {
                        "trail_name": name,
                        "home_region": home,
                        "is_multi_region": is_multi,
                    },
                })

            # Coverage for this region:
            # - Any multi-region trail logging covers all regions.
            # - Otherwise, a single-region trail covers only its HomeRegion if logging.
            is_logging = _trail_is_logging(ct, t)
            if is_logging and (is_multi or (home == region)):
                region_has_logging = True

        if not region_has_logging:
            findings.append({
                "service": "cloudtrail",
                "resource_id": f"region:{region}",
                "title": "No active CloudTrail logging for region",
                "severity": "HIGH",
                "region": region,
                "details": {"region": region, "reason": "No logging multi-region or regional trail detected"},
            })

    return findings
