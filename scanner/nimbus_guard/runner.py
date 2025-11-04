from __future__ import annotations

"""
Nimbus Guard; lightweight AWS checks runner

"""

import importlib
import json
import os
import sys
import pathlib
from dataclasses import asdict, dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Union, cast

import boto3
from botocore.config import Config

from . import report

#------------- Configuration & constants ---------------------------------------------------------------------------------

# Environment variable names
ENV_REGIONS = "NG_REGIONS"
ENV_FAIL_ON = "NG_FAIL_ON"
ENV_OUT_DIR = "NG_OUT"

# Defaults
DEFAULT_REGIONS: Optional[List[str]] = None  # triggers discovery
DEFAULT_FAIL_ON = "HIGH"

# Compute base path one folder above the scanner directory
PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_OUT_DIR = str(PROJECT_ROOT / "out")

# Severity & checks
SEVERITY_ORDER: List[str] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
CHECK_MODULES: List[str] = ["s3", "iam", "sg", "cloudtrail", "account", "vpc"]

# User agent decoration for AWS API calls
USER_AGENT_EXTRA = "nimbus-guard/phase3"

# Output file names (kept identical)
FNAME_JSON = "nimbus-guard-findings.json"
FNAME_MD = "nimbus-guard-report.md"
FNAME_HTML = "nimbus-guard-report.html"

#------------- Data models -----------------------------------------------------------------------------------------------

@dataclass
class Finding:
    """
    A single security/configuration finding emitted by a check.

    Attributes:
        service:     AWS service or logical area, e.g. 's3', 'iam'.
        resource_id: Identifier of the affected resource (bucket/policy/sg id).
        title:       Short human-readable title.
        severity:    One of SEVERITY_ORDER (case-insensitive on input).
        region:      AWS region or None for global checks.
        details:     JSON-serializable dictionary with extra context.
    """
    service: str
    resource_id: str
    title: str
    severity: str
    region: Optional[str]
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Stable JSON shape used in reports."""
        return asdict(self)

#------------- Environment helpers ---------------------------------------------------------------------------------------------

def env_regions() -> Optional[List[str]]:
    """
    Parse NG_REGIONS as a comma-separated list.
    Empty/absent returns None to trigger discovery.
    """
    raw = os.getenv(ENV_REGIONS, "").strip()
    if not raw:
        return None
    parts = [part.strip() for part in raw.split(",") if part.strip()]
    return parts or None

def env_fail_on() -> str:
    """
    Read NG_FAIL_ON and normalize to a valid severity.
    Falls back (with warning) to DEFAULT_FAIL_ON if invalid.
    """
    val = os.getenv(ENV_FAIL_ON, DEFAULT_FAIL_ON).strip().upper()
    if val not in SEVERITY_ORDER:
        print(
            f"[WARN] {ENV_FAIL_ON} '{val}' not in {SEVERITY_ORDER}; "
            f"defaulting to {DEFAULT_FAIL_ON}",
            file=sys.stderr,
        )
        return DEFAULT_FAIL_ON
    return val


def env_out_dir() -> str:
    """Read NG_OUT, falling back to DEFAULT_OUT_DIR."""
    value = os.getenv(ENV_OUT_DIR, DEFAULT_OUT_DIR).strip()
    return value or DEFAULT_OUT_DIR

#------------- Severity helpers --------------------------------------------------------------------------------------------------------

def severity_index(level: str) -> int:
    """
    Map a severity string to its index in SEVERITY_ORDER.
    Unknowns are treated as 'LOW' to avoid false failures.
    """
    try:
        return SEVERITY_ORDER.index(level.upper())
    except ValueError:
        return SEVERITY_ORDER.index("LOW")

def severity_gte(a: str, b: str) -> bool:
    """Return True if severity a >= b."""
    return severity_index(a) >= severity_index(b)

def fail_threshold_triggered(findings: Iterable[Finding], threshold: str) -> bool:
    """True if any finding meets or exceeds the threshold."""
    return any(severity_gte(f.severity, threshold) for f in findings)

#------------- AWS clients & regions ----------------------------------------------------------------------------------------------------------

def make_client_factory() -> Callable[[str, Optional[str]], Any]:
    """
    Return a function that builds boto3 clients with sensible retry config.

    Usage in checks:
        ec2 = client_factory("ec2", region)
    """
    cfg = Config(
        retries={"max_attempts": 10, "mode": "standard"},
        user_agent_extra=USER_AGENT_EXTRA,
    )
    session = boto3.Session()

    def _factory(service_name: str, region_name: Optional[str] = None) -> Any:
        return session.client(service_name, region_name=region_name, config=cfg)

    return _factory

def discover_regions(primary_hint: Optional[Sequence[str]] = None) -> List[str]:
    """
    Discover enabled regions via EC2 DescribeRegions.
    If permission/endpoint is missing, fall back to hints/defaults.
    """
    if primary_hint:
        return list(primary_hint)

    try:
        # Use a stable AWS region as the discovery anchor.
        ec2 = boto3.client("ec2", region_name="eu-west-2")
        resp = ec2.describe_regions(AllRegions=False)
        regions = sorted([r["RegionName"] for r in resp.get("Regions", [])])
        if regions:
            return regions
    except Exception as e:
        print(f"[WARN] Region discovery failed: {e}", file=sys.stderr)

    # Conservative, stable fallback (kept identical to original)
    return ["eu-west-2", "eu-west-1"]

#------------- Check loading & execution ----------------------------------------------------------------------------------------------------------

def load_check_module(name: str):
    """
    Dynamically import a check module from .checks.<name>.
    The module must expose: run(client_factory, regions) -> Iterable[Finding|dict]
    """
    return importlib.import_module(f".checks.{name}", package=__package__)

def _coerce_to_finding(item: Union[Finding, Dict[str, Any]], default_service: str) -> Finding:
    """
    Accept either a Finding instance or a plain dict from a check,
    returning a validated Finding. Missing fields fall back to defaults.
    """
    if isinstance(item, Finding):
        return item

    data = cast(Dict[str, Any], item)
    return Finding(
        service=str(data.get("service", default_service)),
        resource_id=str(data.get("resource_id", "unknown")),
        title=str(data.get("title", "Untitled")),
        severity=str(data.get("severity", "LOW")).upper(),
        region=data.get("region"),
        details=cast(Dict[str, Any], data.get("details", {})),
    )

def run_checks(regions: List[str]) -> List[Finding]:
    """
    Import and run all checks listed in CHECK_MODULES across the given regions.
    Collects and normalizes their outputs into a single findings list.
    """
    client_factory = make_client_factory()
    all_findings: List[Finding] = []

    for mod_name in CHECK_MODULES:
        try:
            mod = load_check_module(mod_name)
        except Exception as e:
            print(f"[ERROR] Failed to import check module '{mod_name}': {e}", file=sys.stderr)
            continue

        try:
            results = getattr(mod, "run")(client_factory, regions)  # type: ignore[no-any-return]
            for item in results or []:
                all_findings.append(_coerce_to_finding(item, default_service=mod_name))
        except Exception as e:
            print(f"[ERROR] Check '{mod_name}' failed: {e}", file=sys.stderr)

    return all_findings

#------------- Reporting ---------------------------------------------------------------------------------------------------------------------

def write_reports(out_dir: str, findings: List[Finding]) -> None:
    """
    Write findings to:
      - JSON (for machines)
      - Markdown (for quick reading)
      - HTML (for sharing)
    Paths and filenames are preserved.
    """
    os.makedirs(out_dir, exist_ok=True)

    # JSON
    raw_path = os.path.join(out_dir, FNAME_JSON)
    with open(raw_path, "w", encoding="utf-8") as f:
        json.dump([f.to_dict() for f in findings], f, indent=2)

    # Markdown
    md = report.render_markdown([f.to_dict() for f in findings])
    md_path = os.path.join(out_dir, FNAME_MD)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md)

    # HTML
    html = report.render_html([f.to_dict() for f in findings])
    html_path = os.path.join(out_dir, FNAME_HTML)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    # Preserve the original user-facing prints
    print(f"[OK] Wrote: {md_path}")
    print(f"[OK] Wrote: {html_path}")
    print(f"[OK] Wrote: {raw_path}")

def summarize_console(findings: List[Finding]) -> None:
    """
    Print a short human summary by severity, preserving original format.
    """
    by_sev: Dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        s = f.severity.upper()
        by_sev[s] = by_sev.get(s, 0) + 1

    total = len(findings)
    print("\n==== Nimbus Guard Summary ====")
    print(f"Total findings: {total}")
    for s in reversed(SEVERITY_ORDER):
        if by_sev.get(s, 0):
            print(f"  {s:9s}: {by_sev[s]}")
    print("==============================\n")

#------------- Entry point ---------------------------------------------------------------------------------------------------------------------

def main() -> int:
    """
    Orchestrate:
      1) Resolve configuration
      2) Discover regions (or use hints)
      3) Run checks
      4) Write reports
      5) Summarize & exit with threshold-based status code
    """
    regions_hint = env_regions()
    fail_on = env_fail_on()
    out_dir = env_out_dir()

    regions = discover_regions(regions_hint)
    print(f"[INFO] Regions: {', '.join(regions)}")
    print(f"[INFO] Fail threshold: {fail_on}")
    print(f"[INFO] Output dir: {out_dir}")

    findings = run_checks(regions)
    write_reports(out_dir, findings)
    summarize_console(findings)

    if fail_threshold_triggered(findings, fail_on):
        print(f"[FAIL] Findings at or above '{fail_on}' detected.")
        return 2

    print("[PASS] No findings at/above threshold.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
