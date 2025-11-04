from __future__ import annotations
"""
Nimbus Guard; Account checks (Root MFA)
=======================================
Public entry point:
    run(client_factory, regions) -> List[Dict[str, Any]]
"""
from typing import Any, Callable, Dict, List, Optional
import csv
import io
import time

#------------- Safe call helper ---------------------------------------------------------------------------------

def _safe(fn, *args, **kwargs):
    """
    Wrap an AWS SDK call; return None on exception.
    Keeps the check resilient to AccessDenied and transient errors.
    """
    try:
        return fn(*args, **kwargs)
    except Exception:
        return None

#------------- Credential report helpers ---------------------------------------------------------------------------------

def _get_or_generate_credential_report(iam: Any) -> Optional[bytes]:
    """
    Fetch the IAM credential report. If it doesn't exist or is expired,
    request a new one and poll briefly until it is ready.
    Returns the CSV bytes on success; otherwise None.
    """
    # 1) Try existing
    resp = _safe(iam.get_credential_report)
    if resp and resp.get("Content"):
        return resp["Content"]

    # 2) Generate and poll
    gen = _safe(iam.generate_credential_report)
    if not gen:
        return None

    for _ in range(10):  # ~10 seconds worst case
        time.sleep(1)
        resp = _safe(iam.get_credential_report)
        if resp and resp.get("Content"):
            return resp["Content"]
    return None

def _root_mfa_from_credential_report(iam: Any) -> Optional[bool]:
    """
    Parse the IAM credential report CSV and return:
      - True  -> root MFA enabled
      - False -> root MFA disabled
      - None  -> undetermined (e.g., missing permission/format errors)
    """
    content = _get_or_generate_credential_report(iam)
    if not content:
        return None

    try:
        text = content.decode("utf-8")
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            # Root row has user == "<root_account>"
            if (row.get("user") or "").strip() == "<root_account>":
                mfa_val = (row.get("mfa_active") or "").strip().lower()
                if mfa_val in ("true", "false"):
                    return mfa_val == "true"
                return None
    except Exception:
        return None

    return None

def _root_mfa_from_account_summary(iam: Any) -> Optional[bool]:
    """
    Fallback approach using GetAccountSummary:
    SummaryMap.AccountMFAEnabled represents the root MFA state (0/1).
    """
    resp = _safe(iam.get_account_summary)
    if not resp:
        return None

    smap = resp.get("SummaryMap") or {}
    val = smap.get("AccountMFAEnabled")
    if val is None:
        return None

    try:
        return bool(int(val))
    except Exception:
        return None

#------------- Entry point ---------------------------------------------------------------------------------

def run(client_factory: Callable[[str, Optional[str]], Any], regions: List[str]) -> List[Dict[str, Any]]:
    """
    Check whether the root user has MFA enabled, using the most reliable
    available data source. Emit a single HIGH finding if MFA is disabled.
    Returns a flat list of findings (possibly empty).
    """
    findings: List[Dict[str, Any]] = []
    iam = client_factory("iam", None)  # Global service

    # Prefer credential report; fall back to account summary.
    root_mfa = _root_mfa_from_credential_report(iam)
    if root_mfa is None:
        root_mfa = _root_mfa_from_account_summary(iam)

    if root_mfa is False:
        findings.append({
            "service": "account",
            "resource_id": "root",
            "title": "Root user does not have MFA enabled",
            "severity": "HIGH",
            "region": None,
            "details": {"source": "credential_report_or_summary"},
        })

    # If True or None (undetermined due to permissions), emit nothing to avoid noise.
    return findings
