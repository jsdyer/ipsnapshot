import assert from 'node:assert/strict';
import {test} from 'node:test';
import {parseIP, portLabel, recordFrom} from '../web/model.mjs';

test('validates IPv4 and IPv6 syntax, canonicalizes, and rejects special-use targets', () => {
  assert.deepEqual(parseIP('8.8.8.8'), {address: '8.8.8.8', version: 4, public: true});
  assert.deepEqual(parseIP('[2001:4860:4860:0:0:0:0:8888]'),
    {address: '2001:4860:4860::8888', version: 6, public: true});
  for (const input of ['127.0.0.1', '100.64.1.2', '192.0.2.1', '198.18.0.0', '::1', 'fd01::1', '2001:db8::2']) {
    assert.equal(parseIP(input)?.public, false, input);
  }
  for (const input of ['1.2.3.256', '008.8.8.8', 'https://8.8.8.8', 'example.com', 'fe80::1%eth0']) assert.equal(parseIP(input), null);
});

test('deduplicates and validates source lookups', () => {
  const ip = parseIP('8.8.8.8');
  assert.deepEqual(recordFrom({ip: ip.address, ports: [443, 53, 53, -1], vulns: ['CVE-2026-0001','bad']}, ip).ports, [53,443]);
  assert.deepEqual(recordFrom({ip: ip.address, vulns: ['CVE-2026-0001','bad']}, ip).vulnerabilities, ['CVE-2026-0001']);
  assert.throws(() => recordFrom({ip: '1.1.1.1'}, ip), /different/);
  assert.equal(portLabel(22),'SSH');
});
