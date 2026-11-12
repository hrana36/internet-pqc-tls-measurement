"""
pqc_measurement/statistical_analyzer.py
Empirical Telemetry and Statistical Analyzer.
Computes Cumulative Distribution Functions (CDF), latency percentiles, and adoption ratios.
"""

from __future__ import annotations
from typing import List, Dict, Any, Tuple
import statistics
import json
import os
from .models import DomainTelemetry, EmpiricalStudySummary, TLSVersion, PQCKeyExchange, ECHStatus


class StatisticalAnalyzer:
    """
    Analyzes raw measurement telemetry cohorts and outputs formal statistical models.
    """

    @staticmethod
    def analyze_cohort(telemetries: List[DomainTelemetry]) -> EmpiricalStudySummary:
        total = len(telemetries)
        if total == 0:
            raise ValueError("Telemetry cohort is empty.")

        successful = [t for t in telemetries if not t.error_message and t.tls_version != TLSVersion.UNKNOWN]
        failed_count = total - len(successful)

        pqc_count = sum(1 for t in successful if t.pqc_supported)
        ech_count = sum(1 for t in successful if t.ech_status == ECHStatus.SUPPORTED)
        tls13_count = sum(1 for t in successful if t.tls_version == TLSVersion.TLS_1_3)

        success_count = max(1, len(successful))
        pqc_pct = (pqc_count / success_count) * 100.0
        ech_pct = (ech_count / success_count) * 100.0
        tls13_pct = (tls13_count / success_count) * 100.0

        # Latency statistics
        latencies = [t.handshake_latency_ms for t in successful if t.handshake_latency_ms > 0]
        if latencies:
            latencies_sorted = sorted(latencies)
            p50 = statistics.median(latencies_sorted)
            p90 = latencies_sorted[int(len(latencies_sorted) * 0.90)]
            p95 = latencies_sorted[int(len(latencies_sorted) * 0.95)]
            p99 = latencies_sorted[min(len(latencies_sorted) - 1, int(len(latencies_sorted) * 0.99))]
            mean_handshake = statistics.mean(latencies_sorted)
        else:
            p50 = p90 = p95 = p99 = mean_handshake = 0.0

        # PQC vs Classical Latency Delta
        pqc_latencies = [t.handshake_latency_ms for t in successful if t.pqc_supported and t.handshake_latency_ms > 0]
        classical_latencies = [t.handshake_latency_ms for t in successful if not t.pqc_supported and t.handshake_latency_ms > 0]

        mean_pqc = statistics.mean(pqc_latencies) if pqc_latencies else 0.0
        mean_classic = statistics.mean(classical_latencies) if classical_latencies else 0.0
        pqc_overhead_delta = max(0.0, mean_pqc - mean_classic)

        # Categorical breakdowns
        pqc_groups: Dict[str, int] = {}
        for t in successful:
            g = t.pqc_group.value
            pqc_groups[g] = pqc_groups.get(g, 0) + 1

        tls_versions: Dict[str, int] = {}
        for t in successful:
            v = t.tls_version.value
            tls_versions[v] = tls_versions.get(v, 0) + 1

        return EmpiricalStudySummary(
            total_scanned=total,
            successful_probes=len(successful),
            failed_probes=failed_count,
            pqc_adoption_percentage=round(pqc_pct, 2),
            ech_adoption_percentage=round(ech_pct, 2),
            tls13_adoption_percentage=round(tls13_pct, 2),
            latency_p50_ms=round(p50, 3),
            latency_p90_ms=round(p90, 3),
            latency_p95_ms=round(p95, 3),
            latency_p99_ms=round(p99, 3),
            mean_handshake_ms=round(mean_handshake, 3),
            mean_pqc_overhead_delta_ms=round(pqc_overhead_delta, 3),
            breakdown_by_pqc_group=pqc_groups,
            breakdown_by_tls_version=tls_versions,
        )

    @staticmethod
    def generate_cdf_data(latencies: List[float]) -> Tuple[List[float], List[float]]:
        """
        Computes empirical Cumulative Distribution Function (CDF):
        F(x) = P(X <= x)
        """
        if not latencies:
            return [], []

        sorted_vals = sorted(latencies)
        n = len(sorted_vals)
        cdf = [(i + 1) / n for i in range(n)]
        return sorted_vals, cdf

    @staticmethod
    def plot_cdf(
        classical_latencies: List[float],
        pqc_latencies: List[float],
        output_png_path: str,
    ) -> None:
        """Generates publication-quality CDF plot comparing PQC vs Classical Handshake Latency."""
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt

            plt.figure(figsize=(8, 5))
            if classical_latencies:
                x_c, y_c = StatisticalAnalyzer.generate_cdf_data(classical_latencies)
                plt.plot(x_c, y_c, label="Classical ECDHE (X25519 / P-256)", color="#2563eb", linewidth=2)

            if pqc_latencies:
                x_p, y_p = StatisticalAnalyzer.generate_cdf_data(pqc_latencies)
                plt.plot(x_p, y_p, label="Post-Quantum Hybrid (X25519Kyber768)", color="#dc2626", linewidth=2, linestyle="--")

            plt.title("Empirical CDF: TLS 1.3 Handshake Latency (PQC Hybrid vs. Classical)", fontsize=12, fontweight="bold")
            plt.xlabel("Handshake Latency (ms)", fontsize=11)
            plt.ylabel("Cumulative Probability P(X <= x)", fontsize=11)
            plt.grid(True, linestyle=":", alpha=0.6)
            plt.legend(loc="lower right", frameon=True)
            plt.tight_layout()
            plt.savefig(output_png_path, dpi=300)
            plt.close()
        except Exception:
            pass
