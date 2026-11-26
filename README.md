# PCAP Traffic Investigation & Anomaly Hunting (Wireshark)

**Overview:** SOC L1 traffic analysis lab performed in Kali Linux using Wireshark (`4.6.6`) on a controlled 159-packet capture (`lab_traffic.pcap`). The objective was to inspect protocol distribution and detect three common security anomalies: cleartext credential transmission, suspicious DNS queries, and port scanning activity.

## 1. Protocol Hierarchy Overview
Using **Statistics → Protocol Hierarchy** (`159` total packets / `37,735` bytes):
<img src=./protocol_hierarchy.png alt="Protocol Hierarchy Overview">

## 2. Investigation Scenarios & Findings
### Scenario A: Cleartext HTTP `POST` Credentials
```bash
curl -X POST http://httpbin.org/post -d "user=admin&pass=TestPass123"
```
* **Display Filter:** `http.request.method == "POST"`

* **Findings:** Isolated Packet #83 (`10.0.2.15` → `54.172.45.38`, destination port `80`). Using Follow → HTTP Stream (`tcp.stream eq 3`) confirmed unencrypted form submission (`application/x-www-form-urlencoded`) exposing `user=admin&pass=TestPass123` in plaintext, followed by an `HTTP/1.1 200 OK` JSON response.

<img src=./http_post_filter.png alt="Using HTTP POST filter">
<img src=./http_stream.png alt="Cleartext HTTP POST Credentials">

### Scenario B: Suspiciously Long DNS Queries (Potential Tunneling)
```bash
nslookup averyverylongsuspicioussubdomainstringforlabtest.example.com 
```
* **Display Filter:** `dns && dns.qry.name.len > 40`

* **Findings:** Captured `4` packets (`#122–125`, `2.5%` of total traffic) between `10.0.2.15` and DNS resolver `10.0.0.10:53` requesting `A` and `AAAA` records for an unusually long subdomain (`averyverylongsuspicioussubdomainstringforlabtest.example.com`). In a corporate environment, abnormally long or high-frequency subdomain queries are a primary indicator of DNS tunneling or data exfiltration.

<img src=./dns_anomaly.png alt="Suspiciously Long DNS Queries">

### Scenario C: Port Scanning Detection (`SYN` Scan)
```bash
sudo nmap -sS -p 22,80,443,445,3389 scanme.nmap.org
```
* **Display Filter:** `tcp.flags.syn == 1 && tcp.flags.ack == 0`

* **Findings:** Isolated `12` initial `SYN` packets (`7.5%` of traffic). Unlike normal connections (e.g., Packets `#5`, `#40`, `#80` with `Win=64240` and TCP options), Packets `#131`, `#137–141`, `#146–148` show host `10.0.2.15` rapidly probing `45.33.32.156` across ports `443`, `80`, `22`, `3389`, `445` within milliseconds using a `58`-byte packet length and `Win=1024` — a clear signature of an automated Nmap SYN scan (`-sS`).

<img src=./syn_scan.png alt="Port Scanning Detection (SYN Scan)">

## 3. SOC Analyst Conclusion & Recommendations
* **Summary:** The capture contains confirmed cleartext credential exposure over HTTP, anomalous DNS query length, and active TCP SYN reconnaissance from internal host `10.0.2.15`.

* **Remediations:**

1. Enforce **HTTPS/TLS** for all authentication and form endpoints; block or redirect cleartext port `80` traffic.

2. Configure DNS monitoring/SIEM alerts for high-entropy or oversized domain queries (`len > 40`).

3. Investigate host `10.0.2.15` for unauthorized scanning tools and enforce firewall/IDS rules to alert on rapid multi-port `SYN` bursts.
