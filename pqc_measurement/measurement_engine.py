"""
pqc_measurement/measurement_engine.py
High-Throughput Concurrent Measurement Engine.
Orchestrates parallel asynchronous TLS 1.3 probes and DNS HTTPS scans with bounded concurrency.
"""

from __future__ import annotations
import asyncio
from typing import List, Dict, Any, Optional, Callable
from .models import DomainTelemetry
from .tls_probe import TLSProbe
from .ech_dns_scanner import ECHDNSScanner


class PQCMeasurementEngine:
    """
    Coordinates asynchronous concurrent telemetry collection across large domain lists.
    """

    def __init__(
        self,
        max_concurrency: int = 25,
        probe_timeout: float = 4.0,
        dns_timeout: float = 3.0,
    ):
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.tls_probe = TLSProbe(timeout=probe_timeout)
        self.ech_scanner = ECHDNSScanner(timeout=dns_timeout)

    async def scan_single_domain(self, domain: str, port: int = 443, rank: int = 0) -> DomainTelemetry:
        """
        Executes parallel TLS handshake probe and DNS HTTPS ECH parameter scan.
        """
        async with self.semaphore:
            # Run TLS probe and ECH DNS query concurrently
            tls_task = self.tls_probe.probe_domain(domain=domain, port=port, rank=rank)
            ech_task = self.ech_scanner.scan_ech(domain=domain)

            telemetry, (ech_status, ech_pub_name) = await asyncio.gather(
                tls_task,
                ech_task,
                return_exceptions=False,
            )

            telemetry.ech_status = ech_status
            telemetry.ech_public_name = ech_pub_name
            return telemetry

    async def scan_domain_cohort(
        self,
        domains: List[Dict[str, Any]],
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> List[DomainTelemetry]:
        """
        Scans a cohort of domains with bounded concurrency.
        :param domains: List of dicts, each with 'domain' and optional 'rank'.
        """
        tasks = []
        total = len(domains)

        for i, item in enumerate(domains):
            d = item["domain"]
            r = item.get("rank", i + 1)
            tasks.append(self.scan_single_domain(domain=d, rank=r))

        results: List[DomainTelemetry] = []
        for i, fut in enumerate(asyncio.as_completed(tasks)):
            res = await fut
            results.append(res)
            if progress_callback:
                progress_callback(i + 1, total)

        return results
