"""
pqc_measurement/ech_dns_scanner.py
Asynchronous DNS HTTPS Resource Record (Type 65) Scanner for Encrypted Client Hello (ECH).
Conforms to RFC 9460 (Service Binding and Parameter Specification for DNS).
"""

from __future__ import annotations
import asyncio
from typing import Tuple, Optional
import dns.asyncresolver
import dns.rdatatype
from .models import ECHStatus


class ECHDNSScanner:
    """
    Queries DNS for HTTPS (Type 65) and SVCB records to extract ECHConfig payloads.
    """

    def __init__(self, nameservers: Optional[list[str]] = None, timeout: float = 3.0):
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.nameservers = nameservers or ["1.1.1.1", "8.8.8.8"]
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    async def scan_ech(self, domain: str) -> Tuple[ECHStatus, Optional[str]]:
        """
        Scans a domain for DNS HTTPS (Type 65) resource records containing ECH parameters.
        Returns (ECHStatus, public_name_or_detail).
        """
        try:
            # Query RFC 9460 HTTPS Resource Record (RR Type 65)
            answers = await self.resolver.resolve(domain, rdatatype=dns.rdatatype.HTTPS)
            for rdata in answers:
                # Inspect params dictionary on SVCB/HTTPS record
                if hasattr(rdata, "params"):
                    for key, val in rdata.params.items():
                        # Parameter key 5 corresponds to 'ech' in RFC 9460
                        if key == 5 or str(key).lower() == "ech":
                            target_name = str(rdata.target) if hasattr(rdata, "target") else domain
                            return ECHStatus.SUPPORTED, target_name

            return ECHStatus.NOT_CONFIGURED, None

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return ECHStatus.NOT_CONFIGURED, None
        except Exception as e:
            # DNS resolution timeout or server error
            return ECHStatus.DNS_ERROR, str(e)
