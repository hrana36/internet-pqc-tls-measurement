"""
pqc_measurement/models.py
Data models and telemetry schemas for Internet-Scale Post-Quantum TLS & ECH Measurements.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, Optional, List
import time


class PQCKeyExchange(str, Enum):
    X25519_KYBER768_DRAFT00 = "X25519Kyber768Draft00 (0x6399)"
    X25519_MLKEM768 = "X25519MLKEM768 (0x11ec)"
    SECP256R1_MLKEM768 = "SecP256r1MLKEM768 (0x11ed)"
    CLASSICAL_X25519 = "X25519 (Classical 0x001d)"
    CLASSICAL_SECP256R1 = "secp256r1 (Classical 0x0017)"
    CLASSICAL_SECP384R1 = "secp384r1 (Classical 0x0018)"
    UNKNOWN = "Unknown / Legacy"


class TLSVersion(str, Enum):
    TLS_1_3 = "TLSv1.3"
    TLS_1_2 = "TLSv1.2"
    TLS_1_1 = "TLSv1.1"
    TLS_1_0 = "TLSv1.0"
    UNKNOWN = "Unknown"


class ECHStatus(str, Enum):
    SUPPORTED = "SUPPORTED"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    DNS_ERROR = "DNS_ERROR"


@dataclass
class DomainTelemetry:
    """Individual measurement telemetry captured for a target domain."""
    domain: str
    rank: int = 0
    ip_address: str = ""
    tls_version: TLSVersion = TLSVersion.UNKNOWN
    cipher_suite: str = ""
    pqc_supported: bool = False
    pqc_group: PQCKeyExchange = PQCKeyExchange.UNKNOWN
    ech_status: ECHStatus = ECHStatus.NOT_CONFIGURED
    ech_public_name: Optional[str] = None
    handshake_latency_ms: float = 0.0
    tcp_connect_ms: float = 0.0
    alpn_negotiated: str = ""
    certificate_issuer: str = ""
    error_message: Optional[str] = None
    scanned_at_utc: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "rank": self.rank,
            "ip_address": self.ip_address,
            "tls_version": self.tls_version.value,
            "cipher_suite": self.cipher_suite,
            "pqc_supported": self.pqc_supported,
            "pqc_group": self.pqc_group.value,
            "ech_status": self.ech_status.value,
            "ech_public_name": self.ech_public_name,
            "handshake_latency_ms": round(self.handshake_latency_ms, 3),
            "tcp_connect_ms": round(self.tcp_connect_ms, 3),
            "alpn_negotiated": self.alpn_negotiated,
            "certificate_issuer": self.certificate_issuer,
            "error_message": self.error_message,
        }


@dataclass
class EmpiricalStudySummary:
    """Aggregated statistical telemetry across a domain cohort."""
    total_scanned: int
    successful_probes: int
    failed_probes: int
    pqc_adoption_percentage: float
    ech_adoption_percentage: float
    tls13_adoption_percentage: float
    latency_p50_ms: float
    latency_p90_ms: float
    latency_p95_ms: float
    latency_p99_ms: float
    mean_handshake_ms: float
    mean_pqc_overhead_delta_ms: float
    breakdown_by_pqc_group: Dict[str, int]
    breakdown_by_tls_version: Dict[str, int]
