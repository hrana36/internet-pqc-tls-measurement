"""
tests/test_pqc_measurement.py
Comprehensive Pytest test suite for Internet Post-Quantum TLS & ECH Measurement Scanner.
"""

import pytest
import asyncio
from pqc_measurement import (
    DomainTelemetry,
    EmpiricalStudySummary,
    PQCKeyExchange,
    TLSVersion,
    ECHStatus,
    StatisticalAnalyzer,
    ECHDNSScanner,
    TLSProbe,
    PQCMeasurementEngine,
)


@pytest.fixture
def mock_telemetry_cohort():
    return [
        DomainTelemetry(
            domain="cloudflare.com",
            rank=1,
            tls_version=TLSVersion.TLS_1_3,
            cipher_suite="TLS_AES_256_GCM_SHA384",
            pqc_supported=True,
            pqc_group=PQCKeyExchange.X25519_KYBER768_DRAFT00,
            ech_status=ECHStatus.SUPPORTED,
            handshake_latency_ms=85.0,
            tcp_connect_ms=20.0,
        ),
        DomainTelemetry(
            domain="google.com",
            rank=2,
            tls_version=TLSVersion.TLS_1_3,
            cipher_suite="TLS_AES_128_GCM_SHA256",
            pqc_supported=True,
            pqc_group=PQCKeyExchange.X25519_KYBER768_DRAFT00,
            ech_status=ECHStatus.NOT_CONFIGURED,
            handshake_latency_ms=95.0,
            tcp_connect_ms=22.0,
        ),
        DomainTelemetry(
            domain="classical-site.org",
            rank=3,
            tls_version=TLSVersion.TLS_1_3,
            cipher_suite="TLS_AES_256_GCM_SHA384",
            pqc_supported=False,
            pqc_group=PQCKeyExchange.CLASSICAL_X25519,
            ech_status=ECHStatus.NOT_CONFIGURED,
            handshake_latency_ms=75.0,
            tcp_connect_ms=18.0,
        ),
        DomainTelemetry(
            domain="legacy-site.net",
            rank=4,
            tls_version=TLSVersion.TLS_1_2,
            cipher_suite="ECDHE-RSA-AES256-GCM-SHA384",
            pqc_supported=False,
            pqc_group=PQCKeyExchange.CLASSICAL_SECP256R1,
            ech_status=ECHStatus.NOT_CONFIGURED,
            handshake_latency_ms=120.0,
            tcp_connect_ms=30.0,
        ),
    ]


def test_domain_telemetry_serialization():
    t = DomainTelemetry(
        domain="example.com",
        rank=10,
        tls_version=TLSVersion.TLS_1_3,
        cipher_suite="TLS_AES_128_GCM_SHA256",
        pqc_supported=True,
        pqc_group=PQCKeyExchange.X25519_MLKEM768,
        ech_status=ECHStatus.SUPPORTED,
        handshake_latency_ms=92.4567,
    )
    d = t.to_dict()
    assert d["domain"] == "example.com"
    assert d["tls_version"] == "TLSv1.3"
    assert d["pqc_supported"] is True
    assert d["handshake_latency_ms"] == 92.457


def test_statistical_aggregation(mock_telemetry_cohort):
    summary = StatisticalAnalyzer.analyze_cohort(mock_telemetry_cohort)
    assert summary.total_scanned == 4
    assert summary.successful_probes == 4
    assert summary.pqc_adoption_percentage == 50.0  # 2 of 4
    assert summary.ech_adoption_percentage == 25.0  # 1 of 4
    assert summary.tls13_adoption_percentage == 75.0  # 3 of 4
    assert summary.latency_p50_ms == 90.0  # median of [75, 85, 95, 120]


def test_cdf_generation():
    latencies = [10.0, 20.0, 30.0, 40.0, 50.0]
    sorted_vals, cdf_probs = StatisticalAnalyzer.generate_cdf_data(latencies)
    assert sorted_vals == [10.0, 20.0, 30.0, 40.0, 50.0]
    assert cdf_probs == [0.2, 0.4, 0.6, 0.8, 1.0]


def test_live_tls_probe_connection():
    probe = TLSProbe(timeout=5.0)
    # Probe a reliable high-availability target
    telemetry = asyncio.run(probe.probe_domain("github.com"))
    assert telemetry.tls_version in (TLSVersion.TLS_1_3, TLSVersion.TLS_1_2)
    assert telemetry.handshake_latency_ms > 0.0
    assert telemetry.ip_address != ""


def test_measurement_engine_single_scan():
    engine = PQCMeasurementEngine(probe_timeout=5.0)
    telemetry = asyncio.run(engine.scan_single_domain("github.com", rank=1))
    assert telemetry.domain == "github.com"
    assert telemetry.rank == 1
    assert telemetry.tls_version != TLSVersion.UNKNOWN
