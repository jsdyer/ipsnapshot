# IP Snapshot

<!-- coolcode:guide -->
Enter a public IP address and export its InternetDB observations as JSON for comparison later. The lookup never probes the target; its retrieval time is not the date Shodan scanned a reported port or vulnerability.
<!-- /coolcode:guide -->

A browser-only CoolCode tool for reading Shodan InternetDB’s published observations associated with one public IP address. Includes conventional port labels, reported hostnames, fingerprints, CVE references and a local JSON export.

## Build and test

```sh
python3 scripts/build.py
node --test tests/*.test.mjs
python3 -m http.server --directory dist 8000
```

The form sends the submitted address directly to InternetDB. It never connects to the target IP. Lookup time is the time the app fetched the record. InternetDB does not provide per-observation scan timestamps. Ports, fingerprints and CVEs describe source observations and associations, with coverage and freshness varying by address. Port labels are conventional, not service detection.

[InternetDB](https://internetdb.shodan.io/) is published by Shodan. The [free service](https://blog.shodan.io/introducing-the-internetdb-api/) is for noncommercial use. The app contains no mirror or preloaded exposure data. Conventional port references are informed by the [IANA service registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml).
