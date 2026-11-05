import { BlockList, isIP } from 'node:net';

/**
 * Destinations a download may never connect to: private, loopback, link-local, shared, reserved,
 * documentation, benchmarking, multicast and translation ranges (IANA special-purpose registries
 * for IPv4 and IPv6). IPv4 addresses embedded in IPv6 (mapped, compatible, NAT64, 6to4, Teredo)
 * are checked as IPv4 too.
 */
const BLOCKED_IPV4: readonly (readonly [string, number])[] = [
  ['0.0.0.0', 8], // "this network"
  ['10.0.0.0', 8], // private
  ['100.64.0.0', 10], // carrier-grade NAT (shared address space)
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local (includes cloud metadata 169.254.169.254)
  ['172.16.0.0', 12], // private (includes Docker networks)
  ['192.0.0.0', 24], // IETF protocol assignments
  ['192.0.2.0', 24], // TEST-NET-1
  ['192.31.196.0', 24], // AS112
  ['192.52.193.0', 24], // AMT
  ['192.88.99.0', 24], // deprecated 6to4 relay anycast
  ['192.168.0.0', 16], // private
  ['192.175.48.0', 24], // AS112 direct delegation
  ['198.18.0.0', 15], // benchmarking
  ['198.51.100.0', 24], // TEST-NET-2
  ['203.0.113.0', 24], // TEST-NET-3
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved, includes broadcast 255.255.255.255
];

const BLOCKED_IPV6: readonly (readonly [string, number])[] = [
  ['::', 128], // unspecified
  ['::1', 128], // loopback
  ['::ffff:0:0', 96], // IPv4-mapped (checked as IPv4 below as well)
  ['::', 96], // IPv4-compatible (deprecated)
  ['64:ff9b::', 96], // NAT64
  ['64:ff9b:1::', 48], // local-use NAT64
  ['100::', 64], // discard-only
  ['2001::', 23], // IETF protocol assignments (Teredo, ORCHID, benchmarking, …)
  ['2001:db8::', 32], // documentation
  ['2002::', 16], // 6to4
  ['3fff::', 20], // documentation
  ['5f00::', 16], // segment routing SIDs
  ['fc00::', 7], // unique local
  ['fe80::', 10], // link-local
  ['fec0::', 10], // site-local (deprecated)
  ['ff00::', 8], // multicast
];

const blockList = new BlockList();
for (const [address, prefix] of BLOCKED_IPV4) blockList.addSubnet(address, prefix, 'ipv4');
for (const [address, prefix] of BLOCKED_IPV6) blockList.addSubnet(address, prefix, 'ipv6');

/** Expands an IPv6 address to eight 16-bit groups (no zone index). */
function ipv6Groups(address: string): number[] | null {
  let text = address.toLowerCase();
  const zone = text.indexOf('%');
  if (zone !== -1) text = text.slice(0, zone);
  // A trailing dotted IPv4 part (`::ffff:1.2.3.4`) becomes two groups.
  const dotted = /(\d+\.\d+\.\d+\.\d+)$/.exec(text);
  if (dotted?.[1] !== undefined) {
    const octets = dotted[1].split('.').map(Number);
    if (octets.some((octet) => octet > 255)) return null;
    const [a = 0, b = 0, c = 0, d = 0] = octets;
    text = `${text.slice(0, dotted.index)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const halves = text.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] === undefined || halves[0] === '' ? [] : halves[0].split(':');
  const tail = halves.length === 2 && halves[1] !== '' ? (halves[1] ?? '').split(':') : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 ? head.length !== 8 : missing < 1) return null;
  const groups = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill('0'), ...tail];
  const parsed = groups.map((group) => (/^[0-9a-f]{1,4}$/.test(group) ? parseInt(group, 16) : NaN));
  return parsed.some(Number.isNaN) ? null : parsed;
}

const ipv4FromGroups = (high: number, low: number) =>
  `${String(high >> 8)}.${String(high & 0xff)}.${String(low >> 8)}.${String(low & 0xff)}`;

/** IPv4 addresses an IPv6 address carries (mapped, compatible, NAT64, 6to4, Teredo). */
export function embeddedIpv4(address: string): string[] {
  const groups = ipv6Groups(address);
  if (groups === null) return [];
  const [g0 = 0, g1 = 0, g2 = 0, g3 = 0, g4 = 0, g5 = 0, g6 = 0, g7 = 0] = groups;
  const result: string[] = [];
  const zeroPrefix = g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0;
  if (zeroPrefix && (g5 === 0xffff || g5 === 0)) result.push(ipv4FromGroups(g6, g7));
  if (g0 === 0x64 && g1 === 0xff9b) result.push(ipv4FromGroups(g6, g7));
  if (g0 === 0x2002) result.push(ipv4FromGroups(g1, g2));
  // Teredo: the client address is stored inverted in the last 32 bits.
  if (g0 === 0x2001 && g1 === 0) result.push(ipv4FromGroups(g6 ^ 0xffff, g7 ^ 0xffff));
  return result;
}

export interface AddressCheck {
  readonly allowed: boolean;
  readonly reason?: string;
}

/**
 * Decides whether a download may connect to an address. Only public unicast destinations are
 * allowed. `exceptions` exist for tests (a local mock source); production wiring passes none.
 */
export class AddressPolicy {
  private readonly exceptions = new BlockList();
  private readonly hasExceptions: boolean;

  constructor(exceptions: readonly string[] = []) {
    for (const entry of exceptions) {
      const [address = '', prefix] = entry.split('/');
      const family = isIP(address);
      if (family === 0) throw new Error(`Invalid address exception "${entry}"`);
      this.exceptions.addSubnet(
        address,
        prefix === undefined ? (family === 4 ? 32 : 128) : Number(prefix),
        family === 4 ? 'ipv4' : 'ipv6',
      );
    }
    this.hasExceptions = exceptions.length > 0;
  }

  check(address: string): AddressCheck {
    const family = isIP(address);
    if (family === 0) return { allowed: false, reason: 'not an IP address' };
    const type = family === 4 ? 'ipv4' : 'ipv6';
    if (this.hasExceptions && this.exceptions.check(address, type)) return { allowed: true };
    if (blockList.check(address, type)) {
      return { allowed: false, reason: `${address} is in a private, loopback or reserved range` };
    }
    if (family === 6) {
      const groups = ipv6Groups(address);
      if (groups === null) return { allowed: false, reason: 'unparseable IPv6 address' };
      // Only global unicast (2000::/3) is routable on the public internet.
      if (((groups[0] ?? 0) & 0xe000) !== 0x2000) {
        return { allowed: false, reason: `${address} is not a global unicast address` };
      }
      for (const embedded of embeddedIpv4(address)) {
        if (blockList.check(embedded, 'ipv4')) {
          return { allowed: false, reason: `${address} embeds the blocked address ${embedded}` };
        }
      }
    }
    return { allowed: true };
  }
}
