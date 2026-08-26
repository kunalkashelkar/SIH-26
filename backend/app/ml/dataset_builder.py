from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import pandas as pd

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core.database import AsyncSessionLocal

from app.models.models import (
    Endpoint,
    Finding,
    FuzzResult,
    Scan,
    Subdomain,
    VirtualHost,
)

from app.ml.feature_extractor import (
    build_pre_fuzz_graph,
    endpoint_host,
    extract_endpoint_features,
)


OUTPUT_DIR = Path("ml_data")


def endpoint_key(
    target_id,
    endpoint
):
    """
    Identifies the same logical endpoint
    across different scans.
    """
    return (
        target_id,
        endpoint_host(endpoint.url),
        (endpoint.method or "GET").upper(),
        endpoint.path or "/",
    )


async def build_dataset():
    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # =====================================
    # LOAD DATABASE
    # =====================================
    async with AsyncSessionLocal() as db:
        scans = (
            await db.execute(
                select(Scan).options(selectinload(Scan.target))
            )
        ).scalars().all()

        endpoints = (
            await db.execute(
                select(Endpoint).options(selectinload(Endpoint.parameters))
            )
        ).scalars().all()

        subdomains = (
            await db.execute(select(Subdomain))
        ).scalars().all()

        vhosts = (
            await db.execute(select(VirtualHost))
        ).scalars().all()

        findings = (
            await db.execute(select(Finding))
        ).scalars().all()

        fuzz_results = (
            await db.execute(select(FuzzResult))
        ).scalars().all()

    # =====================================
    # ORGANIZE DATA
    # =====================================
    scans_by_id = {scan.id: scan for scan in scans}

    endpoints_by_scan = defaultdict(list)
    for endpoint in endpoints:
        endpoints_by_scan[endpoint.scan_id].append(endpoint)

    subdomains_by_scan = defaultdict(list)
    for subdomain in subdomains:
        subdomains_by_scan[subdomain.scan_id].append(subdomain)

    vhosts_by_scan = defaultdict(list)
    for vhost in vhosts:
        vhosts_by_scan[vhost.scan_id].append(vhost)

    # =====================================
    # GROUND TRUTH
    # =====================================
    finding_endpoints = {
        finding.endpoint_id
        for finding in findings
        if finding.endpoint_id
    }

    # =====================================
    # HISTORICAL DATA
    # =====================================
    history = defaultdict(list)
    for endpoint in endpoints:
        scan = scans_by_id.get(endpoint.scan_id)
        if scan:
            key = endpoint_key(scan.target_id, endpoint)
            history[key].append(endpoint)

    anomaly_by_endpoint = defaultdict(int)
    for result in fuzz_results:
        if result.endpoint_id and result.anomaly_detected:
            anomaly_by_endpoint[result.endpoint_id] += 1

    # =====================================
    # BUILD DATASET
    # =====================================
    rows = []
    post_fuzz_rows = []

    scan_order = sorted(
        scans,
        key=lambda scan: (
            scan.started_at or datetime.min,
            scan.id
        )
    )

    for scan in scan_order:
        scan_endpoints = endpoints_by_scan.get(scan.id, [])
        if not scan_endpoints:
            continue

        # =================================
        # PRE-FUZZ ATTACK SURFACE GRAPH
        # =================================
        (
            graph,
            endpoint_nodes,
            host_parent,
            subdomain_set,
            vhost_set,
        ) = build_pre_fuzz_graph(
            scan,
            scan_endpoints,
            subdomains_by_scan.get(scan.id, []),
            vhosts_by_scan.get(scan.id, []),
        )

        # =================================
        # RELATED ENDPOINTS
        # =================================
        related_by_parent = defaultdict(set)
        for endpoint in scan_endpoints:
            host = endpoint_host(endpoint.url)
            parent = host_parent.get(host)
            related_by_parent[parent].add(endpoint.id)

        api_count = sum(
            1
            for endpoint in scan_endpoints
            if endpoint.is_api
        )

        # =================================
        # EACH ENDPOINT
        # =================================
        for endpoint in scan_endpoints:
            key = endpoint_key(scan.target_id, endpoint)
            current_time = scan.started_at or datetime.max

            # IMPORTANT: Only scans BEFORE this scan.
            previous = [
                previous_endpoint
                for previous_endpoint in history[key]
                if previous_endpoint.scan_id != scan.id
                and (
                    scans_by_id[previous_endpoint.scan_id].started_at
                    or datetime.min
                ) < current_time
            ]

            previous_anomalies = sum(
                anomaly_by_endpoint.get(previous_endpoint.id, 0)
                for previous_endpoint in previous
            )

            previous_scan_count = len({
                previous_endpoint.scan_id
                for previous_endpoint in previous
            })

            # =================================
            # FEATURE VECTOR
            # =================================
            features = extract_endpoint_features(
                scan=scan,
                endpoint=endpoint,
                graph=graph,
                endpoint_nodes=endpoint_nodes,
                host_parent=host_parent,
                subdomain_set=subdomain_set,
                vhost_set=vhost_set,
                related_endpoints_by_parent=related_by_parent,
                api_endpoint_count=api_count,
                historical_anomaly_count=previous_anomalies,
                historical_scan_count=previous_scan_count,
            )

            # =================================
            # LABEL
            # =================================
            features["validated_vulnerability"] = int(
                endpoint.id in finding_endpoints
            )

            rows.append(features)

    # =====================================
    # POST-FUZZ DATASET
    # =====================================
    for result in fuzz_results:
        post_fuzz_rows.append({
            "fuzz_result_id": result.id,
            "scan_id": result.scan_id,
            "endpoint_id": result.endpoint_id,
            "parameter_id": result.parameter_id,
            "category": result.category,
            "status_code": result.status_code,
            "response_time_ms": result.response_time_ms,
            "anomaly_detected": int(bool(result.anomaly_detected)),
            "validated_vulnerability": int(
                result.endpoint_id in finding_endpoints
                if result.endpoint_id
                else 0
            ),
        })

    # =====================================
    # DATAFRAMES
    # =====================================
    pre_df = pd.DataFrame(rows)
    post_df = pd.DataFrame(post_fuzz_rows)

    if pre_df.empty:
        raise RuntimeError(
            "No endpoints found. Run at least one scanner scan first."
        )

    # =====================================
    # FINAL COLUMN ORDER
    # =====================================
    columns = [
        "endpoint_id",
        "scan_id",
        "target_id",
        "http_method",
        "endpoint_depth",
        "endpoint_type",
        "parameter_count",
        "query_parameter_count",
        "body_parameter_count",
        "authentication_required",
        "external_exposure",
        "graph_degree",
        "related_endpoint_count",
        "api_relationship_count",
        "subdomain_relationship",
        "vhost_relationship",
        "historical_anomaly_count",
        "historical_scan_count",
        "validated_vulnerability",
    ]

    pre_df = pre_df[columns].drop_duplicates(subset=["endpoint_id"])

    # =====================================
    # SAVE
    # =====================================
    pre_path = OUTPUT_DIR / "pre_fuzz_dataset.csv"
    post_path = OUTPUT_DIR / "post_fuzz_evidence.csv"

    pre_df.to_csv(pre_path, index=False)
    post_df.to_csv(post_path, index=False)

    # =====================================
    # CHECKPOINT
    # =====================================
    print()
    print("=" * 70)
    print("PHASE 5 — REAL SCANNER DATASET")
    print("=" * 70)
    print(f"Dataset shape: {pre_df.shape}")
    print(f"Positive labels: {int(pre_df['validated_vulnerability'].sum())}")
    print(f"Negative labels: {int((pre_df['validated_vulnerability'] == 0).sum())}")
    print()
    print("Columns:")
    for column in pre_df.columns:
        print(f"  ✓ {column}")
    print()
    print("Missing values:")
    print(pre_df.isna().sum())
    print()
    print("Label distribution:")
    print(pre_df["validated_vulnerability"].value_counts())
    print()
    print(f"Saved: {pre_path}")
    print(f"Saved: {post_path}")
    print()
    print("STATUS: PHASE 5 COMPLETE")


if __name__ == "__main__":
    asyncio.run(build_dataset())
