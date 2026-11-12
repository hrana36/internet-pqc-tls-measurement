"""
benchmarks/run_empirical_study.py
Executes the Internet-Scale Post-Quantum TLS 1.3 & ECH Empirical Study.
Ingests domain cohort, measures live endpoints, computes CDF distributions, and exports artifacts.
"""

from __future__ import annotations
import asyncio
import csv
import sys
import os
import json
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pqc_measurement import (
    PQCMeasurementEngine,
    StatisticalAnalyzer,
    ECHStatus,
)


async def main():
    print("\n" + "=" * 78)
    print(" 🌐 INTERNET POST-QUANTUM TLS & ECH MEASUREMENT STUDY")
    print("=" * 78)

    csv_path = os.path.join(os.path.dirname(__file__), "..", "datasets", "tranco_sample.csv")
    domains_to_scan = []

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            domains_to_scan.append({
                "domain": row["domain"],
                "rank": int(row["rank"]),
                "category": row.get("category", "")
            })

    total = len(domains_to_scan)
    print(f"Loaded {total} domains from Tranco sample dataset.")
    print("Beginning high-throughput asynchronous network measurement scan...\n")

    engine = PQCMeasurementEngine(max_concurrency=10, probe_timeout=4.0, dns_timeout=3.0)

    start_time = time.perf_counter()
    telemetries = await engine.scan_domain_cohort(domains_to_scan)
    elapsed_time = time.perf_counter() - start_time

    # Sort by rank
    telemetries.sort(key=lambda t: t.rank)

    # Print live telemetry table
    print(f"{'Rank':<5} | {'Domain':<20} | {'TLS':<8} | {'PQC Group':<26} | {'ECH':<12} | {'Handshake':<10}")
    print("-" * 90)
    for t in telemetries:
        if t.error_message:
            pqc_str = f"ERR: {t.error_message[:20]}"
            tls_str = "ERR"
            hs_str = "--"
        else:
            pqc_str = t.pqc_group.value[:25]
            tls_str = t.tls_version.value
            hs_str = f"{t.handshake_latency_ms:.1f} ms"

        ech_str = "SUPPORTED" if t.ech_status == ECHStatus.SUPPORTED else "NO_ECH"
        print(f"{t.rank:<5} | {t.domain:<20} | {tls_str:<8} | {pqc_str:<26} | {ech_str:<12} | {hs_str:<10}")

    # Statistical Aggregation
    summary = StatisticalAnalyzer.analyze_cohort(telemetries)

    print("\n" + "=" * 78)
    print(" 📊 EMPIRICAL STATISTICAL SUMMARY")
    print("=" * 78)
    print(f"{'Metric':<40} | {'Empirical Value':<20}")
    print("-" * 65)
    print(f"{'Total Domains Probed':<40} | {summary.total_scanned}")
    print(f"{'Successful Probes':<40} | {summary.successful_probes} ({(summary.successful_probes/total)*100:.1f}%)")
    print(f"{'TLS 1.3 Adoption Rate':<40} | {summary.tls13_adoption_percentage}%")
    print(f"{'Post-Quantum (PQC) Adoption Rate':<40} | {summary.pqc_adoption_percentage}%")
    print(f"{'Encrypted Client Hello (ECH) Adoption':<40} | {summary.ech_adoption_percentage}%")
    print(f"{'Median Handshake Latency (p50)':<40} | {summary.latency_p50_ms} ms")
    print(f"{'95th Percentile Handshake Latency (p95)':<40} | {summary.latency_p95_ms} ms")
    print(f"{'PQC vs. Classical Mean Overhead Delta':<40} | +{summary.mean_pqc_overhead_delta_ms} ms")
    print(f"{'Total Scan Duration':<40} | {elapsed_time:.2f} seconds")
    print("=" * 78)

    # Export CDF Plot
    pqc_latencies = [t.handshake_latency_ms for t in telemetries if t.pqc_supported and t.handshake_latency_ms > 0]
    classical_latencies = [t.handshake_latency_ms for t in telemetries if not t.pqc_supported and t.handshake_latency_ms > 0]
    
    cdf_png_path = os.path.join(os.path.dirname(__file__), "handshake_latency_cdf.png")
    StatisticalAnalyzer.plot_cdf(classical_latencies, pqc_latencies, cdf_png_path)
    print(f"📈 Empirical CDF Plot generated: {cdf_png_path}")

    # Export JSON Artifacts
    export_payload = {
        "study_timestamp_utc": time.time(),
        "summary": {
            "total_scanned": summary.total_scanned,
            "successful_probes": summary.successful_probes,
            "pqc_adoption_percentage": summary.pqc_adoption_percentage,
            "ech_adoption_percentage": summary.ech_adoption_percentage,
            "tls13_adoption_percentage": summary.tls13_adoption_percentage,
            "latency_p50_ms": summary.latency_p50_ms,
            "latency_p95_ms": summary.latency_p95_ms,
            "mean_pqc_overhead_delta_ms": summary.mean_pqc_overhead_delta_ms,
            "breakdown_by_pqc_group": summary.breakdown_by_pqc_group,
            "breakdown_by_tls_version": summary.breakdown_by_tls_version,
        },
        "raw_telemetry": [t.to_dict() for t in telemetries],
    }

    out_json = os.path.join(os.path.dirname(__file__), "empirical_telemetry_results.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(export_payload, f, indent=2)
    print(f"📄 Full JSON Telemetry Dataset exported: {out_json}\n")


if __name__ == "__main__":
    asyncio.run(main())
