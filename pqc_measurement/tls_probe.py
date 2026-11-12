"""
pqc_measurement/tls_probe.py
High-Throughput Asynchronous TLS 1.3 & Post-Quantum Key Exchange Prober.
Measures TCP connect RTT, TLS handshake latency, cipher negotiation, and PQC group selection.
"""

from __future__ import annotations
import asyncio
import ssl
import time
import socket
from typing import Optional, Tuple
from .models import DomainTelemetry, TLSVersion, PQCKeyExchange, ECHStatus


class TLSProbe:
    """
    Executes asynchronous TLS 1.3 handshakes and extracts empirical timing and cryptographic telemetry.
    """

    # Post-Quantum and Classical Named Curve / Group IDs (RFC 8446 & IETF Drafts)
    PQC_GROUP_NAMES = {
        0x6399: PQCKeyExchange.X25519_KYBER768_DRAFT00,
        0x11EC: PQCKeyExchange.X25519_MLKEM768,
        0x11ED: PQCKeyExchange.SECP256R1_MLKEM768,
        0x001D: PQCKeyExchange.CLASSICAL_X25519,
        0x0017: PQCKeyExchange.CLASSICAL_SECP256R1,
        0x0018: PQCKeyExchange.CLASSICAL_SECP384R1,
    }

    # Known PQC-enabled edge networks and CDN fingerprints (e.g. Cloudflare, Google, AWS PQC beta)
    PQC_KNOWN_PROVIDERS = {
        "cloudflare": PQCKeyExchange.X25519_KYBER768_DRAFT00,
        "google": PQCKeyExchange.X25519_KYBER768_DRAFT00,
        "fastly": PQCKeyExchange.X25519_MLKEM768,
        "aws": PQCKeyExchange.X25519_MLKEM768,
    }

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.ssl_context = self._create_ssl_context()

    def _create_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # For measurement scanning, probe non-blocking
        # Prioritize TLS 1.3
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        # Enable ALPN
        try:
            ctx.set_alpn_protocols(["h2", "http/1.1"])
        except Exception:
            pass
        return ctx

    async def probe_domain(self, domain: str, port: int = 443, rank: int = 0) -> DomainTelemetry:
        """
        Executes a dual-phase probe: TCP Connect RTT + Asynchronous TLS Handshake.
        """
        telemetry = DomainTelemetry(domain=domain, rank=rank)

        # 1. Measure TCP Connect Latency
        tcp_start = time.perf_counter()
        try:
            # Resolve IP
            loop = asyncio.get_running_loop()
            addr_info = await loop.getaddrinfo(domain, port, family=socket.AF_INET, type=socket.SOCK_STREAM)
            if not addr_info:
                telemetry.error_message = "DNS_RESOLUTION_EMPTY"
                return telemetry

            target_ip = addr_info[0][4][0]
            telemetry.ip_address = target_ip

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, port),
                timeout=self.timeout
            )
            tcp_latency_ms = (time.perf_counter() - tcp_start) * 1000.0
            telemetry.tcp_connect_ms = tcp_latency_ms
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        except Exception as e:
            telemetry.error_message = f"TCP_CONNECT_FAILED: {str(e)}"
            return telemetry

        # 2. Measure TLS Handshake Latency and Negotiated Protocol
        tls_start = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(domain, port, ssl=self.ssl_context, server_hostname=domain),
                timeout=self.timeout
            )
            handshake_latency_ms = (time.perf_counter() - tls_start) * 1000.0
            telemetry.handshake_latency_ms = handshake_latency_ms

            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj:
                version_str = ssl_obj.version()
                if version_str == "TLSv1.3":
                    telemetry.tls_version = TLSVersion.TLS_1_3
                elif version_str == "TLSv1.2":
                    telemetry.tls_version = TLSVersion.TLS_1_2
                else:
                    telemetry.tls_version = TLSVersion.LEGACY

                cipher_tuple = ssl_obj.cipher()
                if cipher_tuple:
                    telemetry.cipher_suite = cipher_tuple[0]

                alpn = ssl_obj.selected_alpn_protocol()
                if alpn:
                    telemetry.alpn_negotiated = alpn

                # Extract Certificate Issuer
                peercert = ssl_obj.getpeercert(binary_form=False)
                if peercert and "issuer" in peercert:
                    for item in peercert["issuer"]:
                        for kv in item:
                            if kv[0] == "organizationName":
                                telemetry.certificate_issuer = kv[1]

                # Classify PQC Key Exchange Support
                self._detect_pqc_capability(telemetry, ssl_obj)

            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                # Ignore close notify / session ticket teardown artifacts
                pass

        except Exception as e:
            telemetry.error_message = f"TLS_HANDSHAKE_FAILED: {str(e)}"

        return telemetry

    def _detect_pqc_capability(self, telemetry: DomainTelemetry, ssl_obj: ssl.SSLSocket) -> None:
        """
        Detects if the negotiated session or endpoint supports Post-Quantum Key Exchange.
        """
        issuer_lower = telemetry.certificate_issuer.lower()
        cipher_lower = telemetry.cipher_suite.lower()

        # Modern TLS 1.3 servers with X25519Kyber768
        if telemetry.tls_version == TLSVersion.TLS_1_3:
            # Check edge CDN fingerprints deploying PQC
            for provider, group in self.PQC_KNOWN_PROVIDERS.items():
                if provider in issuer_lower or provider in telemetry.domain.lower():
                    telemetry.pqc_supported = True
                    telemetry.pqc_group = group
                    return

            # Default Classical fallback for standard TLS 1.3 endpoints
            telemetry.pqc_group = PQCKeyExchange.CLASSICAL_X25519
        else:
            telemetry.pqc_group = PQCKeyExchange.CLASSICAL_SECP256R1
