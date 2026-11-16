export const SOURCE = 'https://internetdb.shodan.io/';

function v4(value) {
  const parts = value.split('.');
  if (parts.length !== 4 || parts.some(n => !/^(0|[1-9]\d{0,2})$/.test(n) || Number(n) > 255)) return null;
  return parts.map(Number);
}

function publicV4([a, b, c, d]) {
  return !(a === 0 || a === 10 || a === 127 || a >= 224
    || a === 100 && b >= 64 && b <= 127
    || a === 169 && b === 254
    || a === 172 && b >= 16 && b <= 31
    || a === 192 && (b === 168 || b === 0 && c === 0 && d !== 9 && d !== 10 || b === 0 && c === 2 || b === 88 && c === 99)
    || a === 198 && (b === 18 || b === 19 || b === 51 && c === 100)
    || a === 203 && b === 0 && c === 113);
}

export function parseIP(raw) {
  const input = String(raw).trim();
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(input)) {
    const parts = v4(input);
    if (parts) return {address: parts.join('.'), version: 4, public: publicV4(parts)};
  }
  const value = input.replace(/^\[([^\]]+)\]$/, '$1');
  if (value.includes(':') && /^[\da-f:.]+$/i.test(value)) {
    try {
      const address = new URL(`http://[${value}]/`).hostname.slice(1, -1);
      const [prefix = '', second = ''] = address.split(':');
      const first = parseInt(prefix, 16), next = parseInt(second, 16);
      const global = first >= 0x2000 && first <= 0x3fff
        && !(first === 0x2001 && next === 0xdb8 || first === 0x3fff && (next & 0xf000) === 0);
      return {address, version: 6, public: global};
    } catch {}
  }
  return null;
}

const portNames = new Map([
  [20,'FTP data'],[21,'FTP control'],[22,'SSH'],[23,'Telnet'],[25,'SMTP'],[53,'DNS'],[67,'DHCP server'],
  [69,'TFTP'],[80,'HTTP'],[88,'Kerberos'],[110,'POP3'],[111,'ONC RPC'],[123,'NTP'],[135,'Microsoft RPC'],
  [137,'NetBIOS name service'],[139,'NetBIOS session'],[143,'IMAP'],[161,'SNMP'],[179,'BGP'],[389,'LDAP'],
  [443,'HTTPS'],[445,'SMB'],[465,'SMTP over TLS'],[500,'ISAKMP / IKE'],[514,'Syslog'],[587,'Mail submission'],
  [636,'LDAP over TLS'],[853,'DNS over TLS'],[993,'IMAP over TLS'],[995,'POP3 over TLS'],[1194,'OpenVPN'],
  [1433,'Microsoft SQL Server'],[1883,'MQTT'],[2049,'NFS'],[2375,'Docker API'],[2376,'Docker API over TLS'],
  [3000,'Common alternate web service'],[3306,'MySQL'],[3389,'RDP'],[4500,'IPsec NAT traversal'],
  [5060,'SIP'],[5432,'PostgreSQL'],[5672,'AMQP'],[5900,'VNC'],[6379,'Redis'],[6443,'Common Kubernetes API port'],
  [8000,'Common alternate HTTP'],[8080,'HTTP alternate'],[8443,'Common alternate HTTPS'],[8888,'Common alternate web service'],
  [9000,'Common alternate application service'],[9100,'Printer data'],[9200,'Common Elasticsearch API port'],
  [11211,'Memcached'],[27017,'MongoDB'],
]);

export function portLabel(port) {
  return portNames.get(port) ?? 'No label in this tool';
}

function strings(value, limit = 500) {
  return [...new Set(Array.isArray(value) ? value.filter(item => typeof item === 'string' && item.trim())
    .map(item => item.trim().slice(0, 512)).slice(0, limit) : [])];
}

export function recordFrom(value, requested) {
  const actual = typeof value?.ip === 'string' ? parseIP(value.ip) : null;
  if (actual?.address !== requested.address) throw new Error('InternetDB returned a record for a different address.');
  const ports = [...new Set(Array.isArray(value.ports) ? value.ports.filter(port => Number.isInteger(port)
    && port >= 1 && port <= 65535).slice(0, 4096) : [])].sort((a, b) => a - b);
  return {address: actual.address, version: actual.version, ports, hostnames: strings(value.hostnames), fingerprints: strings(value.cpes),
    tags: strings(value.tags), vulnerabilities: strings(value.vulns).filter(cve => /^CVE-\d{4}-\d{4,}$/i.test(cve))};
}
