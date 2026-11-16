import {download, element, external, fetchJSON, get, initTheme, setStatus} from './common.mjs';
import {parseIP, portLabel, recordFrom, SOURCE} from './model.mjs';

initTheme();
let latest;
let controller;

function fillList(container, values, fallback, render = value => element('code', value)) {
  container.replaceChildren(...(values.length ? values.map(value => {
    const li = element('li');
    li.append(render(value));
    return li;
  }) : [element('li', fallback, 'muted')]));
}

function showPorts() {
  const filter = get('port-filter').value.trim().toLowerCase();
  const matches = latest.record.ports.filter(port => `${port} ${portLabel(port).toLowerCase()}`.includes(filter));
  const rows = matches.map(port => {
    const row = element('tr');
    row.append(element('td', String(port)), element('td', portLabel(port)));
    return row;
  });
  if (!rows.length) {
    const row = element('tr');
    const cell = element('td', filter ? 'No matching ports.' : 'No ports were reported.', 'muted');
    cell.colSpan = 2;
    row.append(cell);
    rows.push(row);
  }
  get('ports').replaceChildren(...rows);
}

function show(snapshot) {
  const {record, endpoint, retrieved} = snapshot;
  get('result-title').textContent = record.address;
  get('provenance').textContent = `IPv${record.version} · Retrieved ${new Date(retrieved).toLocaleString()} · Shodan InternetDB`;
  get('raw').href = endpoint;
  get('host-page').href = `https://www.shodan.io/host/${encodeURIComponent(record.address)}`;
  get('port-count').textContent = record.ports.length;
  get('host-count').textContent = record.hostnames.length;
  get('cpe-count').textContent = record.fingerprints.length;
  get('cve-count').textContent = record.vulnerabilities.length;
  fillList(get('hosts'), record.hostnames, 'No hostnames were reported.');
  get('tags').replaceChildren(...record.tags.map(tag => element('li', tag)));
  get('tags').hidden = !record.tags.length;
  fillList(get('fingerprints'), record.fingerprints, 'No product fingerprints were reported.');
  fillList(get('vulns'), record.vulnerabilities, 'No CVEs were listed for this record.',
    cve => external(cve, `https://www.cve.org/CVERecord?id=${encodeURIComponent(cve)}`));
  get('port-filter').value = '';
  showPorts();
  get('report').hidden = false;
}

async function lookup(address) {
  controller?.abort();
  get('report').hidden = true;
  latest = null;
  const target = parseIP(address);
  if (!target?.public) {
    get('submit').disabled = false;
    setStatus(target ? 'Use a public address. Private, local and documentation ranges are excluded.' :
      'Enter a single IPv4 or IPv6 address, such as 8.8.8.8.', true);
    return;
  }
  const current = controller = new AbortController();
  get('address').value = target.address;
  const endpoint = SOURCE + target.address;
  get('submit').disabled = true;
  setStatus(`Looking up ${target.address} in Shodan InternetDB…`);
  try {
    const payload = await fetchJSON(endpoint, {signal: current.signal, maxBytes: 512_000});
    if (current.signal.aborted) return;
    latest = {source: 'Shodan InternetDB', endpoint, retrieved: new Date().toISOString(), record: recordFrom(payload, target)};
    show(latest);
    setStatus('Snapshot loaded.');
  } catch (error) {
    if (current.signal.aborted) return;
    if (error.status === 404) setStatus('InternetDB has no record for this address. Coverage varies by address and observation.');
    else if (error.status === 429) setStatus('InternetDB is limiting requests. Wait before trying again.', true);
    else if (error.name === 'TimeoutError' || error instanceof TypeError) setStatus('InternetDB could not be reached. Try again later.', true);
    else setStatus(error.message, true);
  } finally {
    if (!current.signal.aborted) get('submit').disabled = false;
  }
}

get('lookup').addEventListener('submit', event => {
  event.preventDefault();
  lookup(get('address').value);
});
for (const button of document.querySelectorAll('[data-address]')) {
  button.addEventListener('click', () => lookup(button.dataset.address));
}
get('port-filter').addEventListener('input', showPorts);
get('export').addEventListener('click', () => {
  if (latest) download(`ip-snapshot-${latest.record.address.replaceAll(':', '-')}.json`, JSON.stringify(latest, null, 2));
});
