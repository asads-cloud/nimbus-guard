from __future__ import annotations
"""
Nimbus Guard; IAM checks
=========================
This module expects a `client_factory(service_name: str, region: Optional[str]) -> boto3.Client`.
"""
from typing import Any, Callable, Dict, Iterable, List, Optional
import json

#------------- Constants ---------------------------------------------------------------------------------

ADMIN_POLICY_NAME = "AdministratorAccess"  # AWS-managed policy name

#------------- Utilities ---------------------------------------------------------------------------------

def _safe(fn, *args, **kwargs):
    """
    Wrap an AWS SDK call; return None on exception.
    Keeps checks resilient to AccessDenied and transient API errors.
    """
    try:
        return fn(*args, **kwargs)
    except Exception:
        return None

def _paginate(client: Any, method_name: str, result_key: str, **kwargs) -> Iterable[Dict[str, Any]]:
    """
    Simple IAM paginator that yields items under `result_key`.
    Uses classic Marker/IsTruncated pagination used by IAM.
    """
    token: Optional[str] = None
    while True:
        params = dict(MaxItems=1000, **kwargs)
        if token:
            params["Marker"] = token
        resp = _safe(getattr(client, method_name), **params)
        if not resp:
            return
        for item in resp.get(result_key, []):
            yield item
        if not resp.get("IsTruncated"):
            return
        token = resp.get("Marker") or resp.get("NextMarker")

def _as_list(x: Any) -> List[Any]:
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]

def _statement_is_allow(stmt: Dict[str, Any]) -> bool:
    return stmt.get("Effect") == "Allow"

def _has_wildcard_action(stmt: Dict[str, Any]) -> bool:
    acts = {a.lower() for a in _as_list(stmt.get("Action"))}
    return any(a == "*" or a.endswith(":*") for a in acts)

def _resource_is_star(stmt: Dict[str, Any]) -> bool:
    res = _as_list(stmt.get("Resource"))
    return any(r == "*" for r in res)

def _policy_full_admin(stmt: Dict[str, Any]) -> bool:
    """
    Full admin if Effect=Allow and Action="*" and Resource="*".
    """
    return _statement_is_allow(stmt) and _has_wildcard_action(stmt) and _resource_is_star(stmt)

def _policy_over_permissive(stmt: Dict[str, Any]) -> bool:
    """
    High risk if Effect=Allow and (Action wildcard OR Resource="*").
    """
    return _statement_is_allow(stmt) and (_has_wildcard_action(stmt) or _resource_is_star(stmt))

def _parse_policy_doc(txt: str) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(txt)
    except Exception:
        return None

def _evaluate_policy(
    findings: List[Dict[str, Any]],
    *,
    entity_type: str,
    entity_name: str,
    region: Optional[str],
    policy_name: str,
    policy_doc: Dict[str, Any],
) -> None:
    """
    Inspect a single policy document and append findings onto the provided list.
    Emits CRITICAL for full admin, HIGH for over-permissive wildcards.
    """
    stmts = policy_doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]

    had_full_admin = False
    had_high = False

    for st in stmts:
        if _policy_full_admin(st):
            had_full_admin = True
        elif _policy_over_permissive(st):
            had_high = True

    if had_full_admin:
        findings.append({
            "service": "iam",
            "resource_id": f"{entity_type}:{entity_name}",
            "title": f"Full admin permissions via policy '{policy_name}'",
            "severity": "CRITICAL",
            "region": region,
            "details": {"policy": policy_name, "reason": "Effect=Allow with Action='*' and Resource='*'"},
        })
    elif had_high:
        findings.append({
            "service": "iam",
            "resource_id": f"{entity_type}:{entity_name}",
            "title": f"Over-permissive wildcard in policy '{policy_name}'",
            "severity": "HIGH",
            "region": region,
            "details": {"policy": policy_name, "reason": "Wildcard Action and/or Resource='*'"},
        })

def _check_admin_policy_attachment(
    iam: Any,
    findings: List[Dict[str, Any]],
    *,
    entity_type: str,
    entity_name: str,
    region: Optional[str],
) -> None:
    """
    Detect attachment of AWS-managed 'AdministratorAccess' policy to the entity.
    """
    method = {
        "user": "list_attached_user_policies",
        "role": "list_attached_role_policies",
        "group": "list_attached_group_policies",
    }[entity_type]

    for pol in _paginate(iam, method, "AttachedPolicies", **{f"{entity_type.capitalize()}Name": entity_name}):
        if pol.get("PolicyName") == ADMIN_POLICY_NAME:
            findings.append({
                "service": "iam",
                "resource_id": f"{entity_type}:{entity_name}",
                "title": f"'{ADMIN_POLICY_NAME}' attached",
                "severity": "CRITICAL",
                "region": region,
                "details": {"policy_arn": pol.get("PolicyArn")},
            })

def _check_attached_managed_policies(
    iam: Any,
    findings: List[Dict[str, Any]],
    *,
    entity_type: str,
    entity_name: str,
    region: Optional[str],
) -> None:
    """
    Evaluate attached managed policies by fetching their default versions.
    """
    method = {
        "user": "list_attached_user_policies",
        "role": "list_attached_role_policies",
        "group": "list_attached_group_policies",
    }[entity_type]

    for pol in _paginate(iam, method, "AttachedPolicies", **{f"{entity_type.capitalize()}Name": entity_name}):
        arn = pol.get("PolicyArn")
        meta = _safe(iam.get_policy, PolicyArn=arn) or {}
        default_ver_id = (meta.get("Policy") or {}).get("DefaultVersionId")
        if not default_ver_id:
            continue

        ver = _safe(iam.get_policy_version, PolicyArn=arn, VersionId=default_ver_id)
        if not ver:
            continue

        doc_txt = (ver.get("PolicyVersion") or {}).get("Document")
        if not doc_txt:
            continue

        # get_policy_version may already return a dict; if it is a string, parse JSON.
        doc = doc_txt if isinstance(doc_txt, dict) else _parse_policy_doc(doc_txt)
        if not doc:
            continue

        _evaluate_policy(
            findings,
            entity_type=entity_type,
            entity_name=entity_name,
            region=region,
            policy_name=pol.get("PolicyName") or arn,
            policy_doc=doc,
        )

def _check_inline_policies(
    iam: Any,
    findings: List[Dict[str, Any]],
    *,
    entity_type: str,
    entity_name: str,
    region: Optional[str],
) -> None:
    """
    Evaluate inline policies attached directly to the entity.
    """
    list_method = {
        "user": "list_user_policies",
        "role": "list_role_policies",
        "group": "list_group_policies",
    }[entity_type]
    get_method = {
        "user": "get_user_policy",
        "role": "get_role_policy",
        "group": "get_group_policy",
    }[entity_type]

    for pname in _paginate(iam, list_method, "PolicyNames", **{f"{entity_type.capitalize()}Name": entity_name}):
        # paginator yields strings for PolicyNames
        name = pname if isinstance(pname, str) else str(pname)

        doc_resp = _safe(getattr(iam, get_method), **{f"{entity_type.capitalize()}Name": entity_name, "PolicyName": name})
        if not doc_resp:
            continue

        # get_*_policy returns "PolicyDocument", possibly already a dict
        doc_txt = doc_resp.get("PolicyDocument")
        doc = doc_txt if isinstance(doc_txt, dict) else _parse_policy_doc(doc_txt)
        if not doc:
            continue

        _evaluate_policy(
            findings,
            entity_type=entity_type,
            entity_name=entity_name,
            region=region,
            policy_name=name,
            policy_doc=doc,
        )

def _check_role_trust_policies(
    iam: Any,
    findings: List[Dict[str, Any]],
    *,
    role_name: str,
    region: Optional[str],
) -> None:
    """
    Flag overly broad assume-role trust policies (Principal '*') for the role.
    """
    role = _safe(iam.get_role, RoleName=role_name)
    if not role:
        return

    assume = (role.get("Role") or {}).get("AssumeRolePolicyDocument")
    doc = assume if isinstance(assume, dict) else _parse_policy_doc(assume) or {}
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]

    for st in stmts:
        if st.get("Effect") != "Allow":
            continue

        princ = st.get("Principal")
        is_star = (
            princ == "*"
            or (isinstance(princ, dict) and any(v == "*" for v in _as_list(princ.get("AWS"))))
        )
        acts = {a for a in _as_list(st.get("Action"))}

        if is_star and ("sts:AssumeRole" in acts or "sts:*" in acts or "*" in acts):
            findings.append({
                "service": "iam",
                "resource_id": f"role:{role_name}",
                "title": "Role trust policy allows any principal to assume role",
                "severity": "MEDIUM",
                "region": region,
                "details": {"statement": st},
            })

#------------- Entry point ---------------------------------------------------------------------------------

def run(client_factory: Callable[[str, Optional[str]], Any], regions: List[str]) -> List[Dict[str, Any]]:
    """
    Run IAM checks across users, roles, and groups.

    Notes:
    - IAM is a global service, so we use region=None for a consistent finding shape.
    - Each check appends into `findings` directly to avoid extra allocations.
    """
    findings: List[Dict[str, Any]] = []
    region: Optional[str] = None  # IAM is global
    iam = client_factory("iam", region)

    # USERS
    for u in _paginate(iam, "list_users", "Users"):
        uname = u.get("UserName")
        if not uname:
            continue
        _check_admin_policy_attachment(iam, findings, entity_type="user", entity_name=uname, region=region)
        _check_attached_managed_policies(iam, findings, entity_type="user", entity_name=uname, region=region)
        _check_inline_policies(iam, findings, entity_type="user", entity_name=uname, region=region)

    # ROLES
    for r in _paginate(iam, "list_roles", "Roles"):
        rname = r.get("RoleName")
        if not rname:
            continue
        _check_admin_policy_attachment(iam, findings, entity_type="role", entity_name=rname, region=region)
        _check_attached_managed_policies(iam, findings, entity_type="role", entity_name=rname, region=region)
        _check_inline_policies(iam, findings, entity_type="role", entity_name=rname, region=region)
        _check_role_trust_policies(iam, findings, role_name=rname, region=region)

    # GROUPS
    for g in _paginate(iam, "list_groups", "Groups"):
        gname = g.get("GroupName")
        if not gname:
            continue
        _check_admin_policy_attachment(iam, findings, entity_type="group", entity_name=gname, region=region)
        _check_attached_managed_policies(iam, findings, entity_type="group", entity_name=gname, region=region)
        _check_inline_policies(iam, findings, entity_type="group", entity_name=gname, region=region)

    return findings
