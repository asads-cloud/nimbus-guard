from __future__ import annotations
"""
Nimbus Guard; S3 checks
========================
This module expects a `client_factory(service_name: str, region: Optional[str]) -> boto3.Client`
callable, identical to the one provided by the runner.
"""
from typing import Any, Callable, Dict, List, Optional, Set
import json

#------------- Heuristic action sets ---------------------------------------------------------------------------------

# NOTE: Keep values and case identical to preserve original matching behavior.
WRITE_ACTIONS: Set[str] = {
    "s3:PutObject", "s3:PutObjectAcl", "s3:DeleteObject", "s3:AbortMultipartUpload",
    "s3:PutBucketPolicy", "s3:DeleteBucketPolicy"
}
READ_ACTIONS: Set[str] = {"s3:GetObject", "s3:GetObjectVersion"}

# Precomputed lowercase variants for case-insensitive comparison
_WRITE_ACTIONS_L = {x.lower() for x in WRITE_ACTIONS}
_READ_ACTIONS_L = {x.lower() for x in READ_ACTIONS}

#------------- Safe AWS call helper ---------------------------------------------------------------------------------

def _safe_call(fn, *args, **kwargs):
    """
    Wrap an AWS SDK call and return None on any exception.
    This keeps the checks resilient to permission and transient errors.
    """
    try:
        return fn(*args, **kwargs)
    except Exception:
        return None

#------------- Small utilities ---------------------------------------------------------------------------------

def _get_account_id(client_factory: Callable[[str, Optional[str]], Any]) -> Optional[str]:
    """Return the AWS account ID of the current caller, or None on failure."""
    sts = client_factory("sts", None)
    resp = _safe_call(sts.get_caller_identity)
    if resp:
        return resp.get("Account")
    return None

def _bool(v: Any) -> bool:
    """
    Strict truthiness gate used by PAB flags.
    Keeps original semantics: only a Python-true value is accepted as True.
    """
    return bool(v) is True

#------------- Account-level checks ---------------------------------------------------------------------------------

def _check_account_pab(
    client_factory: Callable[[str, Optional[str]], Any],
    region: str,
    account_id: Optional[str],
) -> List[Dict[str, Any]]:
    """
    Verify Account-level S3 Public Access Block (PAB) via s3control in the given region.
    Emits MEDIUM findings when missing/incomplete.
    """
    findings: List[Dict[str, Any]] = []
    if not account_id:
        return findings

    s3c = client_factory("s3control", region)
    resp = _safe_call(s3c.get_public_access_block, AccountId=account_id)
    if not resp or "PublicAccessBlockConfiguration" not in resp:
        findings.append({
            "service": "s3",
            "resource_id": f"account:{account_id}",
            "title": "Account-level Public Access Block not configured",
            "severity": "MEDIUM",
            "region": region,
            "details": {"reason": "get_public_access_block returned none"},
        })
        return findings

    cfg = resp["PublicAccessBlockConfiguration"]
    required = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]
    missing_or_false = [k for k in required if not _bool(cfg.get(k))]
    if missing_or_false:
        findings.append({
            "service": "s3",
            "resource_id": f"account:{account_id}",
            "title": "Account-level PAB incomplete",
            "severity": "MEDIUM",
            "region": region,
            "details": {"flags_false": missing_or_false, "config": cfg},
        })
    return findings

#------------- Bucket discovery helpers ---------------------------------------------------------------------------------

def _bucket_region(client_factory: Callable[[str, Optional[str]], Any], bucket: str) -> Optional[str]:
    """
    Resolve the bucket's region via get_bucket_location, normalizing legacy returns.
    """
    s3 = client_factory("s3", None)
    resp = _safe_call(s3.get_bucket_location, Bucket=bucket)
    if not resp:
        return None

    loc = resp.get("LocationConstraint")
    # Legacy/edge cases normalization
    if loc is None:
        return "us-east-1"
    if loc == "EU":
        return "eu-west-1"
    return loc

def _list_buckets(client_factory: Callable[[str, Optional[str]], Any]) -> List[str]:
    """Return a simple list of bucket names or an empty list on failure."""
    s3 = client_factory("s3", None)
    resp = _safe_call(s3.list_buckets)
    if not resp:
        return []
    return [b["Name"] for b in resp.get("Buckets", [])]

#------------- Bucket-level checks ---------------------------------------------------------------------------------

def _bucket_pab(client_factory: Callable[[str, Optional[str]], Any], bucket: str) -> Optional[Dict[str, Any]]:
    """Return the bucket-level Public Access Block configuration, or None on failure."""
    s3 = client_factory("s3", None)
    resp = _safe_call(s3.get_public_access_block, Bucket=bucket)
    if not resp:
        return None
    return resp.get("PublicAccessBlockConfiguration")

def _bucket_acl_public(client_factory: Callable[[str, Optional[str]], Any], bucket: str) -> Optional[Dict[str, Any]]:
    """
    Detect whether the bucket ACL grants to AllUsers or AuthenticatedUsers groups.
    Returns a dict with booleans and raw grant entries if public, else None.
    """
    s3 = client_factory("s3", None)
    resp = _safe_call(s3.get_bucket_acl, Bucket=bucket)
    if not resp:
        return None

    grants = resp.get("Grants", []) or []
    pub = {"all_users": False, "auth_users": False, "grants": []}

    for g in grants:
        gr = g.get("Grantee", {}) or {}
        uri = (gr.get("URI") or "").lower()
        if "allusers" in uri:
            pub["all_users"] = True
            pub["grants"].append(g)
        elif "authenticatedusers" in uri:
            pub["auth_users"] = True
            pub["grants"].append(g)

    if pub["all_users"] or pub["auth_users"]:
        return pub
    return None

def _policy_allows_public(policy_doc: Dict[str, Any], bucket: str) -> Optional[Dict[str, Any]]:
    """
    Heuristic for public bucket policy:
      - Principal == "*" (or {"AWS": "*"}) and Effect == "Allow"
      - Resource targets the bucket or bucket/*
      - Actions include any of READ_ACTIONS or WRITE_ACTIONS (or s3:*)
    Returns a summary dict if public access is detected; otherwise None.
    """
    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    pub_read = False
    pub_write = False
    matched: List[Dict[str, Any]] = []

    bucket_arn = f"arn:aws:s3:::{bucket}"
    bucket_objs = f"{bucket_arn}/*"

    def _as_list(x: Any) -> List[Any]:
        if x is None:
            return []
        if isinstance(x, list):
            return x
        return [x]

    for st in statements:
        effect = st.get("Effect")
        principal = st.get("Principal")
        # Normalize actions/resources
        actions = {a.lower() for a in _as_list(st.get("Action"))}
        resources = {r for r in _as_list(st.get("Resource"))}

        is_public_principal = (
            principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*")
        )
        if effect != "Allow" or not is_public_principal:
            continue

        targets_bucket = any(r in (bucket_arn, bucket_objs) for r in resources)
        if not targets_bucket:
            continue

        # classify actions
        has_read = any((a in _READ_ACTIONS_L) or (a == "s3:*") for a in actions)
        has_write = any((a in _WRITE_ACTIONS_L) or (a == "s3:*") for a in actions)

        if has_read:
            pub_read = True
        if has_write:
            pub_write = True

        matched.append(st)

    if pub_read or pub_write:
        return {"public_read": pub_read, "public_write": pub_write, "statements": matched}
    return None

def _bucket_policy_public(client_factory: Callable[[str, Optional[str]], Any], bucket: str) -> Optional[Dict[str, Any]]:
    """Load and parse the bucket policy, then evaluate with `_policy_allows_public`."""
    s3 = client_factory("s3", None)
    txt = _safe_call(s3.get_bucket_policy, Bucket=bucket)
    if not txt or "Policy" not in txt:
        return None
    try:
        doc = json.loads(txt["Policy"])
    except Exception:
        return None
    return _policy_allows_public(doc, bucket)

#------------- Entry point for this check module ---------------------------------------------------------------------------------

def run(client_factory: Callable[[str, Optional[str]], Any], regions: List[str]) -> List[Dict[str, Any]]:
    """
    Run S3-related checks:
      1) Account-level Public Access Block per-region visibility
      2) Bucket-level PAB presence/flags
      3) Bucket ACL public exposure
      4) Bucket policy public exposure (read/write classification)

    Returns a list of findings in the agreed schema.
    """
    findings: List[Dict[str, Any]] = []

    # 1) Account-level PAB per region
    account_id = _get_account_id(client_factory)
    for region in regions:
        findings.extend(_check_account_pab(client_factory, region, account_id))

    # 2) Bucket-level checks — only buckets in target regions
    all_buckets = _list_buckets(client_factory)
    if not all_buckets:
        return findings

    # Build map bucket->region & filter
    bucket_regions: Dict[str, Optional[str]] = {}
    for b in all_buckets:
        r = _bucket_region(client_factory, b)
        bucket_regions[b] = r

    target_buckets = [b for b, r in bucket_regions.items() if r in set(regions)]

    for bucket in target_buckets:
        region = bucket_regions.get(bucket)

        # 2a) Bucket-level PAB presence & flags
        pab = _bucket_pab(client_factory, bucket)
        if not pab:
            findings.append({
                "service": "s3",
                "resource_id": bucket,
                "title": "Bucket Public Access Block not configured",
                "severity": "HIGH",
                "region": region,
                "details": {"reason": "get_public_access_block returned none"},
            })
        else:
            missing = [
                k for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
                if not _bool(pab.get(k))
            ]
            if missing:
                findings.append({
                    "service": "s3",
                    "resource_id": bucket,
                    "title": "Bucket Public Access Block incomplete",
                    "severity": "HIGH",
                    "region": region,
                    "details": {"flags_false": missing, "config": pab},
                })

        # 2b) ACL public
        acl_pub = _bucket_acl_public(client_factory, bucket)
        if acl_pub:
            findings.append({
                "service": "s3",
                "resource_id": bucket,
                "title": "Bucket ACL grants public access",
                "severity": "HIGH",
                "region": region,
                "details": acl_pub,
            })

        # 2c) Policy public (read/write classification)
        pol_pub = _bucket_policy_public(client_factory, bucket)
        if pol_pub:
            sev = "CRITICAL" if pol_pub.get("public_write") else "HIGH"
            findings.append({
                "service": "s3",
                "resource_id": bucket,
                "title": "Bucket policy allows public access",
                "severity": sev,
                "region": region,
                "details": pol_pub,
            })

    return findings
