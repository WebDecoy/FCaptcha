/**
 * Client IP resolution.
 *
 * Every IP-derived signal in FCaptcha — datacenter ranges, Tor/VPN, rate
 * limiting, token IP binding, PoW difficulty — is only as trustworthy as the
 * address it is handed. X-Forwarded-For and X-Real-IP are set by whoever is on
 * the other end of the socket, so honouring them unconditionally lets any
 * caller claim a clean residential IP and walk past all of it. They are
 * credible only when the peer that sent them is a proxy we put there.
 *
 * TRUSTED_PROXIES holds the peers allowed to speak for someone else, as a
 * comma-separated list of CIDRs and bare IPs. Unset means the private and
 * loopback defaults below. '*' trusts every peer (only correct when an edge you
 * control always overwrites the headers). 'none' trusts nobody, so the socket
 * address is always used.
 */

const ipaddr = require('ipaddr.js');

/**
 * Fallback trust set: loopback plus the private and link-local ranges. A server
 * exposed directly to the internet sees public peer addresses, which are not in
 * this set, so forged headers are ignored. A server behind a sidecar or
 * in-cluster reverse proxy (nginx, Railway, Fly, Kubernetes ingress) sees a
 * loopback or private peer and behaves as before.
 */
const DEFAULT_TRUSTED_PROXY_CIDRS = [
  '127.0.0.0/8',
  '::1/128',
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '169.254.0.0/16',
  'fe80::/10',
  'fc00::/7'
];

// hostOnly strips a trailing :port or wrapping brackets. Node's
// socket.remoteAddress carries no port, but X-Forwarded-For hops sometimes do.
function hostOnly(value) {
  const s = String(value).trim();
  if (s.startsWith('[')) {
    const end = s.indexOf(']');
    return end === -1 ? s : s.slice(1, end);
  }
  // A bare IPv6 address has several colons; only strip a port from host:port.
  const first = s.indexOf(':');
  if (first !== -1 && s.indexOf(':', first + 1) === -1) return s.slice(0, first);
  return s;
}

// normalizeIP validates an address and renders IPv4-mapped IPv6
// (::ffff:1.2.3.4) in dotted form, so the CIDR checks in detection.js match
// either spelling. Returns null when the value is not an IP.
function normalizeIP(value) {
  if (!value) return null;
  try {
    return ipaddr.process(hostOnly(value)).toString();
  } catch {
    return null;
  }
}

// Bind challenges to a coarse source network: tolerant of nearby mobile address
// rotation, but not transferable from an unrelated clean proxy.
function networkIdentity(value) {
  const normalized = normalizeIP(value);
  if (!normalized) return '';
  let addr = ipaddr.parse(normalized);
  if (addr.kind() === 'ipv6' && addr.isIPv4MappedAddress()) addr = addr.toIPv4Address();
  const bytes = addr.toByteArray();
  if (addr.kind() === 'ipv4') return `4:${bytes.slice(0, 3).join('.')}`;
  return `6:${bytes.slice(0, 7).map((b) => b.toString(16).padStart(2, '0')).join('')}`;
}

// Node merges repeated headers into one comma-joined string for everything
// except set-cookie, but accept an array defensively.
function headerValue(req, name) {
  const raw = req.headers?.[name];
  if (Array.isArray(raw)) return raw.join(',');
  return raw || '';
}

// Bounds the misconfiguration hint below. A directly exposed server sees spoof
// attempts continuously, and that is working as intended — the operator needs
// the hint once, not a running commentary.
const MAX_PROXY_MISCONFIG_WARNINGS = 10;

/** Decides which peers may set client-identifying headers. */
class ProxyTrust {
  /**
   * @param {string} spec comma-separated CIDRs and bare IPs, or '*' / 'none'.
   * Invalid entries are warned about and skipped rather than thrown: a typo in
   * one entry should narrow trust, not take the server down.
   */
  constructor(spec) {
    this.trustAll = false;
    this.ranges = [];
    this.warnings = 0;

    for (const raw of String(spec ?? '').split(',')) {
      const entry = raw.trim();
      if (!entry || entry.toLowerCase() === 'none') continue;
      if (entry === '*') {
        this.trustAll = true;
        continue;
      }
      try {
        if (entry.includes('/')) {
          this.ranges.push(ipaddr.parseCIDR(entry));
        } else {
          // A bare IP is a single-host range.
          const addr = ipaddr.process(entry);
          this.ranges.push([addr, addr.kind() === 'ipv4' ? 32 : 128]);
        }
      } catch {
        console.warn(`warning: ignoring invalid TRUSTED_PROXIES entry "${raw}"`);
      }
    }
  }

  /** Builds the trust set from TRUSTED_PROXIES, defaulting when unset. An
   * explicitly empty value means "trust nothing", so unset and empty differ. */
  static fromEnv(env = process.env) {
    const spec = env.TRUSTED_PROXIES === undefined
      ? DEFAULT_TRUSTED_PROXY_CIDRS.join(',')
      : env.TRUSTED_PROXIES;
    return new ProxyTrust(spec);
  }

  /** Renders the trust set for the startup log. */
  describe() {
    if (this.trustAll) return '* (all peers)';
    if (this.ranges.length === 0) return 'none (forwarding headers ignored)';
    return this.ranges.map(([addr, bits]) => `${addr.toString()}/${bits}`).join(', ');
  }

  /** Reports whether an address belongs to a configured proxy. */
  trusts(ip) {
    if (!ip) return false;
    if (this.trustAll) return true;
    let addr;
    try {
      addr = ipaddr.process(ip);
    } catch {
      return false;
    }
    for (const range of this.ranges) {
      // match() throws when the address families differ, so skip those.
      if (range[0].kind() !== addr.kind()) continue;
      if (addr.match(range)) return true;
    }
    return false;
  }

  /** Reports whether the immediate peer may speak for another client. */
  peerTrusted(req) {
    return this.trusts(normalizeIP(req.socket?.remoteAddress));
  }

  /**
   * Returns a header value only when the peer is a trusted proxy, and ''
   * otherwise. Used for X-JA3-Hash: a client free to state its own TLS
   * fingerprint would just present a stock Chrome one and erase the signal.
   */
  trustedHeader(req, name) {
    if (!this.peerTrusted(req)) return '';
    return headerValue(req, name);
  }

  /**
   * Flags the one misconfiguration this design can cause. A peer that sends
   * forwarding headers but is not in the trust set is either a real reverse
   * proxy the operator forgot to list — in which case every visitor is now
   * collapsed onto that proxy's address, silently wrecking rate limiting and IP
   * reputation — or a client spoofing them, which is exactly what we want
   * ignored. The two are indistinguishable here, so say both and name the peer
   * so it can be pasted into TRUSTED_PROXIES.
   */
  _warnUntrustedForwarding(peer, req) {
    if (!headerValue(req, 'x-forwarded-for') && !headerValue(req, 'x-real-ip')) return;
    if (this.warnings >= MAX_PROXY_MISCONFIG_WARNINGS) return;
    this.warnings++;
    const suffix = this.warnings === MAX_PROXY_MISCONFIG_WARNINGS
      ? ' (further warnings suppressed)'
      : '';
    console.warn(
      `warning: ignoring forwarding headers from untrusted peer ${peer}. ` +
      `If that is your reverse proxy, add it to TRUSTED_PROXIES — until then every ` +
      `visitor is attributed to ${peer}. If not, a client is spoofing them and they ` +
      `are correctly ignored.${suffix}`
    );
  }

  /**
   * Resolves the address to attribute the request to. Forwarding headers are
   * read only when the peer is trusted; otherwise the socket address wins.
   */
  clientIP(req) {
    const peer = normalizeIP(req.socket?.remoteAddress);
    // No usable socket address means nothing to trust and nothing to forward.
    if (!peer) return '127.0.0.1';
    if (!this.trusts(peer)) {
      this._warnUntrustedForwarding(peer, req);
      return peer;
    }

    // A trusted proxy sets X-Real-IP to the address it accepted the connection
    // from, so it needs no chain walking.
    const realIP = normalizeIP(headerValue(req, 'x-real-ip'));
    if (realIP) return realIP;

    // Otherwise walk X-Forwarded-For right to left. Each proxy appends the peer
    // it saw, so the rightmost entries are the ones our own infrastructure
    // wrote. The first entry that is not a proxy we trust is the closest thing
    // to a real client; everything to its left was supplied by that client and
    // cannot be believed.
    const forwarded = headerValue(req, 'x-forwarded-for');
    if (forwarded) {
      const parts = forwarded.split(',');
      for (let i = parts.length - 1; i >= 0; i--) {
        const entry = parts[i].trim();
        if (!entry) continue;
        const ip = normalizeIP(entry);
        // A malformed hop makes everything to its left unreadable, so stop and
        // fall back to the peer rather than guess.
        if (!ip) break;
        if (this.trusts(ip)) continue;
        return ip;
      }
    }

    return peer;
  }
}

module.exports = {
  ProxyTrust,
  DEFAULT_TRUSTED_PROXY_CIDRS,
  normalizeIP,
  networkIdentity
};
