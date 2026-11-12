"""
examples/single_domain_probe.py
Interactive CLI Tool: Probe any target domain for Post-Quantum TLS 1.3 & ECH posture.
Usage: python single_domain_probe.py <domain>
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pqc_measurement import PQCMeasurementEngine, ECHStatus


async def probe(domain: str):
    print("\n" + "=" * 70)
    print(f" 🔍 Post-Quantum & ECH Telemetry Probe: {domain}")
    print("=" * 70)

    engine = PQCMeasurementEngine(probe_timeout=5.0, dns_timeout=3.0)
    telemetry = await engine.scan_single_domain(domain=domain)

    if telemetry.error_message:
        print(f"❌ Probe Failed: {telemetry.error_message}")
        return

    print(f"Resolved IP Address      : {telemetry.ip_address}")
    print(f"Negotiated TLS Version   : {telemetry.tls_version.value}")
    print(f"Negotiated Cipher Suite   : {telemetry.cipher_suite}")
    print(f"ALPN Protocol            : {telemetry.alpn_negotiated or 'None'}")
    print(f"TCP Connect Latency      : {telemetry.tcp_connect_ms:.2f} ms")
    print(f"TLS Handshake Latency    : {telemetry.handshake_latency_ms:.2f} ms")
    print("-" * 70)
    print(f"PQC Support Detected     : {'✅ YES' if telemetry.pqc_supported else '❌ NO (Classical)'}")
    print(f"PQC Key Exchange Group   : {telemetry.pqc_group.value}")
    print(f"Encrypted Client Hello   : {'✅ SUPPORTED' if telemetry.ech_status == ECHStatus.SUPPORTED else '❌ NOT_CONFIGURED'}")
    if telemetry.ech_public_name:
        print(f"ECH Public Name (SNI)    : {telemetry.ech_public_name}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "cloudflare.com"
    asyncio.run(probe(target))
