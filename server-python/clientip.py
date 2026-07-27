"""
Client IP resolution.

Every IP-derived signal in FCaptcha - datacenter ranges, Tor/VPN, rate limiting,
token IP binding, PoW difficulty - is only as trustworthy as the address it is
handed. X-Forwarded-For and X-Real-IP are set by whoever is on the other end of
the socket, so honouring them unconditionally lets any caller claim a clean
residential IP and walk past all of it. They are credible only when the peer
that sent them is a proxy we put there.

TRUSTED_PROXIES holds the peers allowed to speak for someone else, as a
comma-separated list of CIDRs and bare IPs. Unset means the private and loopback
defaults below. "*" trusts every peer (only correct when an edge you control
always overwrites the headers). "none" trusts nobody, so the socket address is
always used.
"""

import ipaddress
import os
from typing import List, Optional

# Fallback trust set: loopback plus the private and link-local ranges. A server
# exposed directly to the internet sees public peer addresses, which are not in
# this set, so forged headers are ignored. A server behind a sidecar or
# in-cluster reverse proxy (nginx, Railway, Fly, Kubernetes ingress) sees a
# loopback or private peer and behaves as before.
DEFAULT_TRUSTED_PROXY_CIDRS = [
    "127.0.0.0/8",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "fe80::/10",
    "fc00::/7",
]


def _host_only(value: str) -> str:
    """Strip a trailing :port or wrapping brackets from an address.

    FastAPI's request.client.host carries no port, but X-Forwarded-For hops
    sometimes do.
    """
    s = value.strip()
    if s.startswith("["):
        end = s.find("]")
        return s if end == -1 else s[1:end]
    # A bare IPv6 address has several colons; only strip a port from host:port.
    if s.count(":") == 1:
        return s.split(":", 1)[0]
    return s


def _parse_ip(value: Optional[str]) -> Optional[ipaddress._BaseAddress]:
    """Parse an address, un-mapping IPv4-mapped IPv6 (::ffff:1.2.3.4) so the
    CIDR checks in detection.py match either spelling. None if not an IP."""
    if not value:
        return None
    try:
        addr = ipaddress.ip_address(_host_only(value))
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return addr.ipv4_mapped
    return addr


def normalize_ip(value: Optional[str]) -> Optional[str]:
    """Validate and canonicalise an address, or None if it is not an IP."""
    addr = _parse_ip(value)
    return str(addr) if addr is not None else None


# Bounds the misconfiguration hint below. A directly exposed server sees spoof
# attempts continuously, and that is working as intended - the operator needs the
# hint once, not a running commentary.
MAX_PROXY_MISCONFIG_WARNINGS = 10


class ProxyTrust:
    """Decides which peers may set client-identifying headers."""

    def __init__(self, spec: str):
        """spec is a comma-separated list of CIDRs and bare IPs, or "*" / "none".

        Invalid entries are warned about and skipped rather than raised: a typo
        in one entry should narrow trust, not take the server down.
        """
        self.trust_all = False
        self.networks: List[ipaddress._BaseNetwork] = []
        self.warnings = 0

        for raw in (spec or "").split(","):
            entry = raw.strip()
            if not entry or entry.lower() == "none":
                continue
            if entry == "*":
                self.trust_all = True
                continue
            try:
                # strict=False so 10.0.0.5/8 is accepted as its containing network.
                self.networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                print(f'warning: ignoring invalid TRUSTED_PROXIES entry "{raw}"')

    @classmethod
    def from_env(cls, env=None) -> "ProxyTrust":
        """Build the trust set from TRUSTED_PROXIES, defaulting when unset. An
        explicitly empty value means "trust nothing", so unset and empty differ."""
        env = os.environ if env is None else env
        spec = env.get("TRUSTED_PROXIES")
        if spec is None:
            spec = ",".join(DEFAULT_TRUSTED_PROXY_CIDRS)
        return cls(spec)

    def describe(self) -> str:
        """Render the trust set for the startup log."""
        if self.trust_all:
            return "* (all peers)"
        if not self.networks:
            return "none (forwarding headers ignored)"
        return ", ".join(str(n) for n in self.networks)

    def trusts(self, ip: Optional[str]) -> bool:
        """Report whether an address belongs to a configured proxy."""
        addr = _parse_ip(ip)
        if addr is None:
            return False
        if self.trust_all:
            return True
        return any(addr in net for net in self.networks if net.version == addr.version)

    def peer_trusted(self, request) -> bool:
        """Report whether the immediate peer may speak for another client."""
        peer = request.client.host if request.client else None
        return self.trusts(peer)

    def trusted_header(self, request, name: str) -> str:
        """Return a header value only when the peer is a trusted proxy, and ""
        otherwise. Used for X-JA3-Hash: a client free to state its own TLS
        fingerprint would just present a stock Chrome one and erase the signal.
        """
        if not self.peer_trusted(request):
            return ""
        return request.headers.get(name, "")

    def _warn_untrusted_forwarding(self, peer: str, request) -> None:
        """Flag the one misconfiguration this design can cause.

        A peer that sends forwarding headers but is not in the trust set is
        either a real reverse proxy the operator forgot to list - in which case
        every visitor is now collapsed onto that proxy's address, silently
        wrecking rate limiting and IP reputation - or a client spoofing them,
        which is exactly what we want ignored. The two are indistinguishable
        here, so say both and name the peer so it can be pasted into
        TRUSTED_PROXIES.
        """
        if not request.headers.get("X-Forwarded-For", "") and not request.headers.get("X-Real-IP", ""):
            return
        if self.warnings >= MAX_PROXY_MISCONFIG_WARNINGS:
            return
        self.warnings += 1
        suffix = " (further warnings suppressed)" if self.warnings == MAX_PROXY_MISCONFIG_WARNINGS else ""
        print(
            f"warning: ignoring forwarding headers from untrusted peer {peer}. "
            f"If that is your reverse proxy, add it to TRUSTED_PROXIES - until then "
            f"every visitor is attributed to {peer}. If not, a client is spoofing them "
            f"and they are correctly ignored.{suffix}",
            flush=True,
        )

    def client_ip(self, request) -> str:
        """Resolve the address to attribute the request to. Forwarding headers
        are read only when the peer is trusted; otherwise the socket wins."""
        peer = normalize_ip(request.client.host if request.client else None)
        # No usable socket address means nothing to trust and nothing to forward.
        if peer is None:
            return "127.0.0.1"
        if not self.trusts(peer):
            self._warn_untrusted_forwarding(peer, request)
            return peer

        # A trusted proxy sets X-Real-IP to the address it accepted the
        # connection from, so it needs no chain walking.
        real_ip = normalize_ip(request.headers.get("X-Real-IP", ""))
        if real_ip:
            return real_ip

        # Otherwise walk X-Forwarded-For right to left. Each proxy appends the
        # peer it saw, so the rightmost entries are the ones our own
        # infrastructure wrote. The first entry that is not a proxy we trust is
        # the closest thing to a real client; everything to its left was
        # supplied by that client and cannot be believed.
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            for raw in reversed(forwarded.split(",")):
                entry = raw.strip()
                if not entry:
                    continue
                ip = normalize_ip(entry)
                # A malformed hop makes everything to its left unreadable, so
                # stop and fall back to the peer rather than guess.
                if ip is None:
                    break
                if self.trusts(ip):
                    continue
                return ip

        return peer
