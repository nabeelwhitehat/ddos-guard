# ddos-guard

A DDoS detection and mitigation tool written in Python. It sniffs live traffic, learns what "normal" looks like, scores every 10-second window against that baseline, and responds with escalating rate limits and temporary firewall blocks. Alerts, a web dashboard, and manual admin controls are included.

This is a learning and lab project. It demonstrates the techniques used by network operations teams, but it is **not** a replacement for upstream DDoS protection (see [Limitations](#limitations) and [Comparison with commercial services](#comparison-with-commercial-services)).

> **Use only on networks and hosts you own or are authorized to monitor.** Test with isolated VMs, never against third-party systems.

---

## Contents

1. [How it works](#how-it-works)
2. [Concepts](#concepts)
3. [Architecture](#architecture)
4. [Project layout](#project-layout)
5. [Requirements and installation](#requirements-and-installation)
6. [Lab setup](#lab-setup)
7. [Configuration reference](#configuration-reference)
8. [Deployment: dry run to enforcement](#deployment-dry-run-to-enforcement)
9. [Detection and mitigation logic](#detection-and-mitigation-logic)
10. [Alerting and escalation](#alerting-and-escalation)
11. [Dashboard and admin API](#dashboard-and-admin-api)
12. [Tuning guide](#tuning-guide)
13. [Test results](#test-results)
14. [Limitations](#limitations)
15. [Comparison with commercial services](#comparison-with-commercial-services)
16. [Incident response runbook](#incident-response-runbook)
17. [Stakeholder communication templates](#stakeholder-communication-templates)
18. [Running as a service](#running-as-a-service)
19. [Troubleshooting](#troubleshooting)
20. [License](#license)

---

## How it works

1. **Collect.** Scapy sniffs one network interface and aggregates inbound packets into fixed windows (default 10 s). No raw packets are stored.
2. **Baseline.** A training run records nine features per window and stores mean, standard deviation, p95 and p99, bucketed by hour of week plus a global fallback.
3. **Detect.** Each live window is compared to the baseline. Per-feature z-scores are combined into one score between 0 and 1.
4. **Mitigate.** After two consecutive anomalous windows, the tool inserts iptables rules scoped to the monitored interface: a per-source rate limit and, at the highest level, temporary blocks on sources with an individually excessive packet rate.
5. **Alert.** One notification per escalation level, duplicates suppressed, and a "resolved" message when traffic returns to normal.
6. **Operate.** A password-protected dashboard shows live statistics and lets an admin unblock, whitelist, blacklist, and adjust thresholds.

---

## Concepts

### Attack types and what reveals them

| Attack | How it works | Metric that reveals it |
|---|---|---|
| Volumetric (UDP flood, ICMP flood) | Saturate bandwidth or packet-processing capacity with huge traffic volume | `pps`, `bps`, `udp_ratio`, `icmp_ratio` |
| Protocol (SYN flood) | Exhaust connection tables by sending SYNs that are never completed | `syn_ratio` (inbound SYN per outbound SYN-ACK), `pps` |
| Application layer (HTTP flood) | Many individually valid requests aimed at one service | `pps`, `top_port_share`, per-source rate |
| Distributed attacks | The above from many sources | `unique_src`, volume metrics |

### Baselines

Normal traffic has stable patterns that attacks violate. Statistics are kept per **hour of the week** (168 buckets) so a quiet Sunday night is not compared with a busy Monday morning. Hours with fewer than 30 samples fall back to the `global` statistics.

### Features (computed per window)

| Feature | Meaning |
|---|---|
| `pps`, `bps` | Inbound packets and bits per second |
| `tcp_ratio`, `udp_ratio`, `icmp_ratio` | Protocol mix |
| `unique_src` | Number of distinct source IPs |
| `top_src_share` | Share of packets from the busiest source |
| `top_port_share` | Share of packets to the busiest destination port |
| `syn_ratio` | Inbound SYNs divided by outbound SYN-ACKs |

Only **inbound** packets are counted as traffic. The host's own replies would otherwise distort source and volume statistics. Outbound SYN-ACKs are used only for `syn_ratio`.

### Rate limiting

Enforcement is delegated to the kernel (`iptables -m hashlimit`, keyed per source IP) instead of Python. It is faster, survives sensor lag, and drops packets before they reach the application.

---

## Architecture

![ddos-guard architecture](docs/architecture.png)

*Figure 1. Component architecture: traffic flows from the collector to the detector, which feeds the mitigator, the alert system, and the dashboard.*

`main.py` wires these together. The dashboard runs in a background thread of the same process, so it shows live state and can change it.

---

## Project layout

```
ddos-guard/
├── config.example.yaml    template: copy to config.yaml (git-ignored, holds secrets)
├── requirements.txt       runtime dependencies
├── requirements-dev.txt   adds pytest
├── baseline.json          learned statistics (generated by train.py)
├── collector.py           packet capture, WindowStats, features()
├── baseline.py            Baseline class (hour-of-week statistics)
├── train.py               collects clean traffic and writes baseline.json
├── detector.py            scoring and attack classification
├── live_detect.py         detection only, no mitigation (for testing)
├── mitigator.py           iptables rate limits, blocks, whitelist, expiry
├── alerts.py              alert escalation, dedup, log/Slack/email
├── state.py               shared rolling history for the dashboard
├── main.py                detection + mitigation + alerting + dashboard
├── dashboard/
│   ├── app.py             Flask API with auth and CSRF protection
│   └── index.html         live charts and controls
├── tests/
│   ├── test_detector.py   scoring and classification
│   ├── test_baseline.py   hour-of-week statistics
│   ├── test_mitigator.py  rules, whitelist, expiry (dry run)
│   └── test_alerts.py     deduplication, escalation, resolution
├── deploy/
│   └── ddos-guard.service systemd unit
├── .github/workflows/ci.yml   runs the tests on every push
├── alerts.log             written at runtime (git-ignored)
└── docs/
    ├── attack_notes.md    attack-type notes
    ├── architecture.png   component diagram
    └── dashboard.png      dashboard screenshot
```

---

## Requirements and installation

- Linux (iptables with the `hashlimit` and `comment` modules)
- Python 3.10 or newer
- Root privileges (packet capture and firewall changes)

```bash
git clone https://github.com/YOUR-USERNAME/ddos-guard.git
cd ddos-guard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp config.example.yaml config.yaml    # then edit interface, own_ip, whitelist and dashboard.password
```

`config.yaml` and `baseline.json` are git-ignored because they hold secrets and machine-specific data. A baseline does not ship with the repository: train one first (see [Deployment](#deployment-dry-run-to-enforcement)).

Run everything as root with the virtualenv's interpreter:

```bash
sudo venv/bin/python main.py
```

A plain `sudo python` would not see the packages installed in the virtualenv.

### Run the tests

The test suite uses a synthetic baseline and runs the mitigator in dry-run mode, so it needs no root access, no network interface and no live traffic:

```bash
pip install -r requirements-dev.txt
pytest
```

---

## Lab setup

The project was developed and tested with two machines:

| Machine | Role | Address |
|---|---|---|
| Ubuntu VM | Victim: ddos-guard, nginx, iperf3 | `192.168.56.10` (static, on `enp0s8`) |
| Host (Kali Linux) | Traffic generator and dashboard browser | `192.168.56.1` |

Network: VirtualBox, adapter 1 = NAT (package installs), adapter 2 = **Host-only** (`vboxnet0`, DHCP disabled). The VM's address is fixed with NetworkManager:

```bash
sudo nmcli connection modify "Wired connection 1" \
  ipv4.method manual ipv4.addresses 192.168.56.10/24 ipv4.never-default yes
sudo nmcli connection up "Wired connection 1"
```

`ipv4.never-default yes` keeps this interface from becoming the default route, so internet access over the NAT adapter is unaffected.

**Safety habits for the lab**

- Snapshot the VM before any real-enforcement test.
- Keep the VM console open as a backup access path, because a block on the host's address also cuts SSH and the dashboard.
- All rules carry the comment `ddos-guard` and are scoped to the monitored interface (`-i enp0s8`).

Emergency cleanup of every rule the tool created:

```bash
sudo iptables -S INPUT | grep ddos-guard | sed 's/^-A/-D/' | while read r; do sudo iptables $r; done
```

---

## Configuration reference

`config.yaml`:

```yaml
interface: enp0s8            # interface to sniff and to scope rules to
own_ip: 192.168.56.10        # this host's address (used to separate inbound/outbound)
window_seconds: 10
whitelist: ["192.168.56.1"]  # never blocked; ACCEPT rules are inserted at the top
slack_url: ""                # incoming-webhook URL (treat as a secret)

detector:
  sigma_threshold: 5         # z-score at which a feature counts as anomalous
  alert_score: 0.6           # score needed to count a window as anomalous
  mitigate_score: 0.8        # strict rate limit at or above this score
  block_score: 0.9           # source blocking enabled at or above this score
  per_source_block_pps: 100  # a source must send this many packets/s to be blocked

mitigation:
  dry_run: true              # print iptables commands instead of running them
  block_ttl_seconds: 120     # every rule expires automatically
  max_blocks: 10             # cap on simultaneous automatic blocks

alerts:
  cooldown_seconds: 120
  critical_after_seconds: 300
  log_file: alerts.log
  email:
    enabled: false
    smtp_host: smtp.gmail.com
    smtp_port: 587
    user: ""
    password: ""
    from: ""
    to: ""

dashboard:
  user: admin
  password: "CHANGE-ME"      # the dashboard refuses to start without one
  bind: 192.168.56.10        # management interface only
  port: 5000
```

---

## Deployment: dry run to enforcement

Follow this order. Do not skip stages.

1. **Capture test.** Confirm packets are visible on the interface.
2. **Train a baseline** (hours to days of clean traffic only):
   ```bash
   sudo venv/bin/python train.py     # Ctrl+C saves baseline.json
   ```
   Do not run attack tests during training: the tool would learn floods as normal. `train.py` autosaves every 30 windows.
3. **Detection only:**
   ```bash
   sudo venv/bin/python live_detect.py
   ```
4. **Dry run** (`dry_run: true`): review the `[DRY] iptables ...` lines for at least a week in production before enabling enforcement.
5. **Enforcement:** set `dry_run: false`. Whitelist the gateway, DNS servers, monitoring systems and your own admin addresses first.

Always stop the tool with **Ctrl+C** or SIGTERM (not Ctrl+Z, not `kill -9`) so the shutdown handler removes its rules. As a safety net, rules left behind by a crash are purged at the next start.

---

## Detection and mitigation logic

### Scoring

For each feature, `z = (value - mean) / max(std, floor)`. A per-feature minimum spread prevents a near-constant baseline from producing absurd z-scores. Severity per feature is `min(max(z, 0) / (2 * sigma), 1)`, so it reaches 0.5 at the threshold and 1.0 at twice the threshold. The weighted sum is normalized to 0..1.

| Feature | Weight |
|---|---|
| `pps` | 0.25 |
| `bps` | 0.20 |
| `syn_ratio` | 0.15 |
| `udp_ratio` | 0.10 |
| `icmp_ratio` | 0.10 |
| `top_src_share` | 0.08 |
| `top_port_share` | 0.07 |
| `unique_src` | 0.05 |

A volume-only flood (`pps` and `bps` far above baseline) scores **0.90**. Additional signals such as `unique_src` or `syn_ratio` push it toward 1.0.

The attack type is reported from the features that fired: SYN flood, UDP flood, ICMP flood, few-source flood, or "volumetric / request flood".

### False-positive guard

Nothing happens on the first anomalous window. Mitigation starts only after **two consecutive** windows at or above `alert_score`.

### Escalation levels

| Level | Score | Action |
|---|---|---|
| 0 | below 0.6 | Monitor only |
| 1 | 0.6 to 0.8 | Lenient per-source rate limit: 200 new connections/s, burst 400 |
| 2 | 0.8 to 0.9 | Strict per-source rate limit: 50/s, burst 100 |
| 3 | 0.9 and above | Strict limit **plus** temporary block of up to 5 top sources, but only those sending at least `per_source_block_pps` packets/s |

The rate limit targets the busiest protocol and destination port of the window, so it follows the attack (for example, it moved from port 80 to port 5201 when an iperf3 flood began). Rules are replaced as the level changes, which de-escalates automatically when the score falls.

### Safeguards

- `dry_run` is on by default.
- Whitelisted addresses and networks get `ACCEPT` rules at the top of the chain and can never be blocked, including by the dashboard.
- Every rule expires after `block_ttl_seconds`.
- `max_blocks` caps simultaneous automatic blocks.
- All rules are scoped to the monitored interface.
- Cleanup runs on shutdown and stale rules are purged on startup.
- For spoofed-source floods (such as SYN floods), blocking source addresses is ineffective or harmful. Prefer rate limits, SYN cookies (`sysctl net.ipv4.tcp_syncookies=1`) and upstream filtering.

---

## Alerting and escalation

| Severity | Trigger | Channels |
|---|---|---|
| warning | Level 1 incident, and "incident resolved" messages | log, Slack |
| high | Level 2 or 3 mitigation active | log, Slack, email |
| critical | Level 3 persisting longer than `critical_after_seconds` | all channels, with a recommendation to contact the ISP or scrubbing provider |

To prevent notification fatigue, an alert is sent only when severity **increases** or the cooldown has passed. An incident is declared resolved after three consecutive calm windows. Every alert is also appended to `alerts.log`, so the system works with no external channels configured.

Alert contents: attack type, score, firing indicators with z-scores, top sources, active mitigations, and incident age.

> Slack and email delivery are implemented but were not tested against a live webhook or SMTP server. Verify them before relying on them.

---

## Dashboard and admin API

Open `http://<bind>:<port>` (default `http://192.168.56.10:5000`). It shows the anomaly score, packets per second, protocol mix, top sources, active mitigations (with expiry timers), the incident log, and controls to whitelist, blacklist, unblock, and adjust thresholds.

![ddos-guard dashboard](docs/dashboard.png)

*Figure 2. The dashboard at idle after several test runs. The packets-per-second history shows the earlier load tests, the incident log lists the resulting alerts, and no mitigations are active.*

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/stats` | GET | Recent windows, top sources, current thresholds |
| `/api/mitigations` | GET | Active rules and the whitelist |
| `/api/incidents` | GET | Last 20 alert-log lines |
| `/api/whitelist` | POST `{"ip": "..."}` | Add an address or network |
| `/api/blacklist` | POST `{"ip": "...", "ttl": 3600}` | Manual block |
| `/api/unblock/<ip>` | POST | Remove a block |
| `/api/limits` | POST | Update thresholds (validated: 0 < alert <= mitigate <= block <= 1, 1 <= sigma <= 20) |

**Dashboard security.** The panel uses HTTP Basic authentication with constant-time comparison, requires an `X-Requested-With: ddos-guard` header on every POST (CSRF protection), refuses to run without a configured password, and binds to the management interface only. It uses plain HTTP, which is acceptable only on an isolated lab network. For anything real, put it behind a TLS reverse proxy on a management VLAN.

Changes made in the dashboard (whitelist, blacklist, thresholds) are held in memory and are **lost on restart**. Make permanent changes in `config.yaml`.

---

## Tuning guide

| Symptom | Adjust |
|---|---|
| False alerts on normal bursts | Raise `sigma_threshold`, raise `alert_score`, retrain the baseline for longer, or increase the streak requirement in `main.py` |
| Attacks detected too late | Reduce `window_seconds` (more CPU per window), or move to a faster sensor |
| Legitimate users being blocked | Raise `per_source_block_pps`, add them to the whitelist, or lower `block_score` impact by raising it |
| Rules linger too long or expire too soon | `block_ttl_seconds` |
| Too many alerts | Increase `alerts.cooldown_seconds` |
| Idle windows skew ratio statistics | Already handled: empty windows record volume metrics only |

Rules of thumb: a baseline needs at least 30 samples per hour-bucket; train on clean periods only; retrain periodically so the baseline follows legitimate growth.

---

## Test results

Measured in the lab described above (Ubuntu VM victim, Kali attacker, 10 s windows). Treat absolute numbers as indicative for this setup.

### Baseline

- 1,679 windows (about 4.7 hours) of synthetic "normal" traffic from one client.
- `pps`: mean 4.79, std 2.28, p99 9.12. The 5-sigma alert threshold is roughly 16 packets/s.

### Detection and mitigation

| Test | Result |
|---|---|
| Idle windows with dashboard polling | Score 0.03 to 0.04, no alerts |
| Single-source HTTP flood (`ab`, 25 s, 30 concurrent) | Score 0.90, one `high` alert, one rate-limit rule, resolved about 50 s after the start |
| De-escalation | The strict 50/s rule was replaced by the lenient 200/s rule as the score fell, then removed |
| Real-mode rule insertion | Rules inserted into iptables with no errors |
| Automatic expiry | Rules removed by the TTL without operator action |
| Manual block of the test client (30 s) | `curl` timed out and `ping` showed 100% loss during the block. Access returned automatically after the TTL |
| Whitelist | Every block attempt on a whitelisted address was skipped, including from the dashboard |
| Shutdown cleanup | All rules removed on Ctrl+C |
| Dashboard authentication | No credentials: 401. Wrong password: 401. Correct password without CSRF header: 403 |

### Flash crowd vs single-source attack

30 simulated users (30 source addresses, 14 packets/s each, 40 s):

| Version | Outcome |
|---|---|
| Before the per-source rule | Score 1.00. The five busiest users were blocked, then five more (10 legitimate users in total) |
| After the per-source rule | Score 1.00 and one `high` alert, but **no user was blocked**. Only the rate-limit rule was applied |

### Sensor performance

| Measure | Result |
|---|---|
| CPU, idle | 0 to 0.8% of one core |
| CPU, under flood | about 82% of one core |
| Packets received by the NIC during a 40 s flood test | 3,439,468 (about 86,000 packets/s averaged) |
| Packets counted by the sensor | about 33,500 |
| **Capture ratio** | **about 1%** (order of magnitude; windows were not perfectly aligned) |

Detection still works because the baseline is tiny: even the undercounted peak (about 1,700 pps) is hundreds of standard deviations above normal. The reported numbers, however, are far below real traffic.

---

## Limitations

1. **Sensor throughput.** Python and Scapy capture about 1% of packets at roughly 170,000 packets/s and use about 82% of a core. Reported rates understate real attacks by about two orders of magnitude. Production systems use AF_PACKET rings, eBPF/XDP, or flow telemetry (NetFlow/sFlow/IPFIX) from a router.
2. **Detection latency.** Two 10-second windows are needed before action, plus processing lag under load. Short attacks end before any mitigation starts. The tool suits sustained attacks.
3. **Attacks that saturate the uplink.** A large volumetric attack fills your link before packets reach the host. Host-level tools cannot fix that. Upstream ISP or scrubbing-provider mitigation is required.
4. **Spoofed sources.** Blocking source IPs is useless or harmful against spoofed floods.
5. **Flash crowds look like attacks.** Legitimate surges raise the same volume signals and trigger alerts. The per-source block rule prevents punishing the users, but the tool cannot tell a legitimate surge from a low-rate distributed attack where each bot behaves like a normal user. That needs a CDN, challenges (CAPTCHA/JS), or IP-reputation data.
6. **Rate limit covers new connections only.** The rule matches TCP SYNs. A flood over established, reused connections slips past it.
7. **Weak baseline realism.** The test baseline came from one synthetic client over a few hours. Source-distribution signals (`unique_src`, `top_src_share`) are untested against real traffic, and daily or weekly cycles are not captured. A production baseline needs days to weeks of real traffic and a poisoned baseline degrades detection.
8. **In-memory dashboard changes** are lost on restart.
9. **Self-observation.** The sensor sees the dashboard's own polling traffic (about 4 packets/s) and sees blocked traffic that iptables later drops, which can briefly raise `syn_ratio` after a block.
10. **No geographic map.** Source-country visualization needs GeoLite2 data and public addresses, which the private lab lacks.
11. **IPv4 only.** IPv6 traffic is ignored.
12. **Untested integrations.** Slack and email delivery were not exercised against live services.
13. **Single host.** There is no clustering, persistence of incident history beyond `alerts.log`, or high availability.

Your tool mitigates attacks, it does not prevent them. Very large attacks may still cause impact.

---

## Comparison with commercial services

| | ddos-guard | Cloudflare / AWS Shield / Akamai / Google Cloud Armor |
|---|---|---|
| Where it runs | On the protected host | Anycast edge networks in front of your origin |
| Capacity | Limited by your uplink and one CPU core | Terabits per second across many points of presence |
| Detection | Statistical baseline, 10 s windows | Global traffic intelligence, always-on, in seconds |
| Mitigation | iptables rate limits and blocks | Traffic scrubbing, challenges, WAF, bot management, caching |
| Spoofed floods | Cannot help | Absorbed at the edge |
| Application-layer (L7) | Basic rate limiting | Behavioral analysis, fingerprinting, CAPTCHA |
| Cost | Free, your time | Subscription or usage-based |
| Best use | Learning, small deployments, last-line host defense | Primary protection for production services |

**Where this tool fits.** In a layered defense it sits behind upstream protection and in front of the application: upstream scrubbing or CDN first, then network firewall and SYN cookies, then ddos-guard for local anomaly detection and automatic rate limiting, then the application's own WAF and rate limits.

---

## Incident response runbook

1. **Detect.** An alert arrives (Slack, email, or the dashboard shows a red score).
2. **Verify.** Real attack or flash crowd? Check the top sources and indicators. Many diverse sources at a modest per-source rate suggests legitimate load (a marketing campaign, a news mention). Check application logs and ask whether anything was launched.
3. **Contain.** Confirm that the automatic rate limit is active. Block extra abusive sources from the dashboard if needed. Never block your own admin addresses or critical infrastructure. Enable SYN cookies if a SYN flood is indicated.
4. **Escalate.** If the attack persists beyond about 5 minutes (a `critical` alert), or your uplink is saturated, contact your ISP or enable your upstream scrubbing provider or CDN. Note start time, attack type, and sources.
5. **Communicate.** Notify stakeholders using the templates below. Update on a fixed cadence.
6. **Recover.** Wait for the "incident resolved" alert. Confirm rules expired (`sudo iptables -S INPUT | grep ddos-guard`), service health is normal, and no legitimate user remains blocked.
7. **Review.** Within a few days, write a post-incident report: timeline, impact, what worked, what failed, tuning changes. Preserve `alerts.log`.

---

## Stakeholder communication templates

**Initial notice**

> Subject: [Investigating] Degraded performance on {service}
>
> At {time} we detected abnormal traffic affecting {service}. Some users may see slow responses or errors. Automated mitigation is active and our team is investigating. Next update by {time}.

**Update**

> Subject: [Update] {service} traffic incident
>
> Status as of {time}: the abnormal traffic is {continuing / decreasing}. Mitigation in place: rate limiting {and upstream filtering}. Impact: {description}. Next update by {time}.

**Resolution**

> Subject: [Resolved] {service} traffic incident
>
> As of {time}, traffic is back to normal and {service} is operating normally. Duration: {minutes} minutes. We continue to monitor and will share a summary within {days} days.

**Post-mortem summary**

> Incident: {title} | Date: {date} | Duration: {minutes} min
> Summary: {what happened}. Detection: {how and when}. Impact: {users/services affected}. Response: {actions}. Root cause: {attack type and source characteristics}. Follow-ups: {tuning changes, upstream protection, owners and dates}.

---

## Running as a service

`/etc/systemd/system/ddos-guard.service`:

```ini
[Unit]
Description=ddos-guard DDoS detection and mitigation
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/USER/ddos-guard
ExecStart=/home/USER/ddos-guard/venv/bin/python main.py
Restart=on-failure
RestartSec=5
KillSignal=SIGTERM
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ddos-guard
journalctl -u ddos-guard -f
```

Replace `USER` with the account that owns the project. SIGTERM triggers the same cleanup as Ctrl+C. Keep `config.yaml` readable only by root (`chmod 600`), because it contains the dashboard password and the Slack webhook.

---

## Troubleshooting

| Problem | Likely cause and fix |
|---|---|
| `ModuleNotFoundError: scapy` | Run with `sudo venv/bin/python`, not plain `python` |
| No packets seen | Wrong `interface`, or the sniffer started after the traffic. Check `ip a` |
| `iptables error:` lines | Missing `xt_hashlimit` or `comment` module, or iptables not installed |
| Locked out of the VM or dashboard | The tool blocked your own address. Use the VM console and run the emergency cleanup command above |
| Dashboard charts empty | The browser cannot reach the Chart.js CDN, or the password is wrong |
| Dashboard returns 503 | `dashboard.password` is empty in `config.yaml` |
| Commands "suspended" in the terminal | You pressed Ctrl+Z. Use Ctrl+C to stop programs and `jobs` plus `kill %1` to clear suspended ones |
| iperf3 "Address already in use" | A background iperf3 service is already listening. Use it, or stop it with `sudo systemctl stop iperf3` |
| Stale rules after a crash | They are purged on the next start, or run the emergency cleanup command |

---

## License

MIT. See the `LICENSE` file. This software is provided for education and authorized testing only; you are responsible for using it lawfully.
