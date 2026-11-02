"""
Source/Runtime Difference and Discrepancy Analyzer.
Compares source definitions and runtime observations to highlight coverage gaps,
shadow APIs, authentication divergences, and parameter mismatches.
"""
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

@dataclass
class DiscrepancyItem:
    discrepancy_type: str
    severity: str  # INFO, LOW, MEDIUM, HIGH
    path: str
    method: str
    description: str
    source_evidence: Optional[Dict[str, Any]] = None
    runtime_evidence: Optional[Dict[str, Any]] = None

class DifferenceAnalyzer:
    """
    Performs multi-dimensional difference analysis between source-defined routes
    and runtime-observed traffic.
    """

    @classmethod
    def analyze_discrepancies(
        cls,
        source_routes: List[Dict[str, Any]],
        runtime_endpoints: List[Dict[str, Any]],
        matches: List[Dict[str, Any]]
    ) -> List[DiscrepancyItem]:
        discrepancies: List[DiscrepancyItem] = []

        matched_source_keys = {m["source_key"] for m in matches}
        matched_runtime_keys = {m["runtime_key"] for m in matches}

        # 1. Source Endpoints Not Observed at Runtime (Uncovered / Dead Code / Hidden Attack Surface)
        for s in source_routes:
            s_key = f"{s['method']} {s['path']}"
            if s_key not in matched_source_keys:
                discrepancies.append(DiscrepancyItem(
                    discrepancy_type="UNCOVERED_SOURCE_ROUTE",
                    severity="LOW",
                    path=s["path"],
                    method=s["method"],
                    description=(
                        f"Source-defined route '{s['method']} {s['path']}' in {s.get('source_file')}:{s.get('line_start')} "
                        "was not observed or exercised during the runtime web crawl."
                    ),
                    source_evidence={"file": s.get("source_file"), "line": s.get("line_start"), "framework": s.get("framework")}
                ))

        # 2. Runtime Endpoints Not Identified in Source (Shadow / Unmanaged APIs)
        for r in runtime_endpoints:
            r_key = f"{r['method']} {r['path']}"
            if r_key not in matched_runtime_keys:
                discrepancies.append(DiscrepancyItem(
                    discrepancy_type="SHADOW_RUNTIME_ENDPOINT",
                    severity="MEDIUM",
                    path=r["path"],
                    method=r["method"],
                    description=(
                        f"Runtime endpoint '{r['method']} {r['path']}' responded with HTTP {r.get('status_code')} "
                        "but has no corresponding route definition in the analyzed source code."
                    ),
                    runtime_evidence={"url": r.get("url"), "status_code": r.get("status_code"), "source": r.get("source")}
                ))

        # 3. Analyze Matched Endpoints for Authentication, Parameter, and Method Differences
        for m in matches:
            s = m["source"]
            r = m["runtime"]
            path = s["path"]
            method = s["method"]

            # A. Authentication Discrepancies
            # Source requires auth, but runtime accessed without auth and received 200 OK!
            s_auth = s.get("auth_required", False)
            r_status = r.get("status_code", 200)
            if s_auth and r_status == 200:
                discrepancies.append(DiscrepancyItem(
                    discrepancy_type="AUTHENTICATION_DISCREPANCY",
                    severity="HIGH",
                    path=path,
                    method=method,
                    description=(
                        f"Endpoint '{method} {path}' is defined in source with authentication requirements, "
                        "but answered HTTP 200 during unauthenticated runtime discovery."
                    ),
                    source_evidence={"file": s.get("source_file"), "auth_required": True},
                    runtime_evidence={"status_code": r_status}
                ))

            # B. Parameter Mismatches
            s_params = {p["name"]: p for p in s.get("parameters", []) if p.get("is_required")}
            r_params = set(r.get("query_parameters", []))
            missing_required = [pname for pname in s_params if pname not in r_params and s_params[pname]["location"] == "query"]
            if missing_required:
                discrepancies.append(DiscrepancyItem(
                    discrepancy_type="PARAMETER_MISMATCH",
                    severity="LOW",
                    path=path,
                    method=method,
                    description=(
                        f"Source definition for '{method} {path}' declares required parameter(s) {missing_required}, "
                        "which were absent in observed runtime requests."
                    ),
                    source_evidence={"missing_required_params": missing_required}
                ))

            # C. API Version Divergence
            if "/v1/" in r["path"] and "/v2/" in s["path"]:
                discrepancies.append(DiscrepancyItem(
                    discrepancy_type="VERSION_MISMATCH",
                    severity="LOW",
                    path=path,
                    method=method,
                    description=f"Runtime relies on legacy API version ('{r['path']}') while source repository exposes v2 ('{s['path']}')."
                ))

        return discrepancies
