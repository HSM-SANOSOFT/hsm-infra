---
title: Inbound email never arrives — Stalwart + Traefik behind a Hillstone firewall
date: 2026-06-05
category: docs/solutions/integration-issues/
module: email
problem_type: integration_issue
component: email_processing
severity: critical
symptoms:
  - "External email from Gmail/Hotmail never arrived; remote bounce 554 5.4.316 Message expired, connection refused"
  - "Inbound SMTP stalled ~30-60s before the 220 greeting"
  - "Admin UI at https://mail.hospitalsm.net/admin returned HTTP 502"
  - "check-host.net: 443 open worldwide but 25/587/993 timed out worldwide; LAN reached :25 via hairpin only"
root_cause: config_error
resolution_type: config_change
related_components:
  - tooling
  - authentication
tags:
  - traefik
  - stalwart
  - proxy-protocol
  - smtp
  - fail2ban
  - hillstone-firewall
  - reverse-proxy
  - nat-dnat
---

# Inbound email never arrives — Stalwart + Traefik behind a Hillstone firewall

## Problem

External email could not be delivered to `admin@hospitalsm.net`. The stack — Stalwart mail v0.16 + Bulwark webmail + Traefik v3.7.3 (Docker network `email_network`, `172.20.0.0/16`) behind a Hillstone hardware firewall (public `181.39.233.78` → Hillstone NAT → host `10.1.1.18`) — had **three independent root causes stacked on top of each other**. Fixing any one in isolation still left mail broken, which made diagnosis hard: the outermost failure (firewall) hid behind two inner failures (Traefik PROXY-protocol and Stalwart IP self-ban), and a NAT hairpin masked the firewall block from the local LAN.

Config files involved: `docker/compose/email/traefik.yml` and `docker/compose/email/compose.yml`. Domain `hospitalsm.net`, DNS at DigitalOcean.

## Symptoms

- Remote MTAs (Hotmail) bounced after their full retry window: `554 5.4.316 Message expired, connection refused`.
- Inbound SMTP banner through Traefik took ~60s to arrive; direct-to-Stalwart was instant.
- `/admin` over the domain returned **HTTP 502**.
- Stalwart log: `Blocked IP address (security.ip-blocked) listenerId="http" remoteIp=172.20.0.4` (172.20.0.4 = Traefik's own container IP).
- Zero external SMTP connections appeared in Stalwart logs across many minutes and multiple fresh Hotmail/Gmail sends — yet sending from a laptop on the same LAN worked.
- `check-host.net` global TCP probe to `181.39.233.78`: port **443 OPEN** from all 5 countries; ports **25 / 587 / 993 TIMEOUT** from all nodes.

## What Didn't Work

- **Blaming DNS / iprev / PTR for the SMTP stall** — wrong. DNS was fast: PTR `NXDOMAIN` returned in ~1s, forward lookup in ~0s. The missing PTR affects outbound reputation only, not inbound connectivity.
- **`nc`-based banner timing** gave false ~85s readings. `nc -q` held the pipe open and the shell `$(...)` waited for `nc` to *exit*, not for the 220 banner to arrive. Useless for isolating where the delay lived.
- **Restarting the mail container** did not clear the IP ban — it is persisted in RocksDB, not in memory.
- **Setting `waitOnFail` to 0/blank** made the relay-rejection response *slower*, not instant — it fell back to a long internal default (~30s).
- **Testing from the local laptop** "worked" via NAT hairpin (intra-zone trust→trust was permitted), completely masking the firewall block from the public internet.

## Solution

### Root Cause 1 — 60s inbound SMTP banner stall (Traefik PROXY protocol on public entrypoints)

`traefik.yml` declared `proxyProtocol` on every mail **entrypoint**:

```yaml
smtp:
  address: :25
  proxyProtocol:
    trustedIPs: [172.20.0.0/16]
# ...identical for 587/465/143/993/995/110/4190
```

This makes Traefik (the public edge) **expect an inbound PROXY header from the connecting client**. Public SMTP clients never send one. SMTP is server-speaks-first, so the client waits for the `220` greeting while Traefik waits for a PROXY header → deadlock until go-proxyproto's ~60s read timeout.

**Fix:** delete the `proxyProtocol` blocks from all entrypoints. The PROXY header you actually want is **Traefik → Stalwart**, already set per service in `compose.yml`:

```yaml
traefik.tcp.services.smtp.loadbalancer.proxyProtocol.version=2
```

Result: banner through Traefik dropped from 60s → **0.00s**. Committed as `a397463`.

### Root Cause 2 — `/admin` HTTP 502 (Stalwart auto-banned the reverse proxy)

The Stalwart `http` listener had no proxy-trust configured, so it attributed every web request to Traefik's container IP (`172.20.0.4`). Bulwark webmail constantly polls JMAP through Traefik; one failed/probe request tripped Stalwart's fail2ban-style auto-ban against the proxy IP — after which **every** `/admin` request via Traefik returned 502. The ban survived container restarts (RocksDB-persisted).

**Fix:** add `172.20.0.0/16` to Stalwart's allowed-IP list (admin UI → `server.allowed-ip`) so the proxy can never be auto-banned, then clear the existing ban. `/admin` then returned `302` (login redirect) with no re-ban.

### Root Cause 3 — no external mail connects at all (Hillstone DNAT without a Security Policy) — the real blocker

`check-host.net` showed web port 443 open from the internet but mail ports filtered. The Hillstone firewall had DNAT (port-forward) rules mapping the public mail ports to `10.1.1.18`, but **no Security Policy permitting untrust→trust traffic** for those ports. On Hillstone, DNAT only rewrites the destination address; a separate Security Policy must explicitly *permit* the flow. Port 443 worked because it had a permit policy; the mail ports had DNAT only. The internal hairpin worked because intra-zone (trust→trust) was already allowed.

**Fix:** add an **untrust→trust Security Policy** permitting the mail-port service group (`25, 465, 587, 993, 995, 4190`) to `10.1.1.18`.

Result: MxToolbox immediately connected from the internet (`220`, TLS OK, not an open relay), and real Gmail + Hotmail delivered to the Inbox with **SPF pass, DKIM pass, DMARC pass**.

## Why This Works

- **PROXY protocol is directional and hop-specific.** It belongs only on the trusted internal hop (Traefik → Stalwart), never on the public-facing entrypoint where anonymous clients connect. Putting it on the entrypoint turns a "server speaks first" protocol into a mutual-wait deadlock that only resolves on timeout. Moving the PROXY expectation to the backend service preserves the real client IP for Stalwart while letting public clients connect normally.
- **Stalwart trusts the source IP it sees.** Without proxy-trust on the `http` listener, all traffic looks like it comes from Traefik, so any abuse heuristic bans the one IP that must never be banned. Allow-listing the proxy CIDR exempts it from the fail2ban logic. Because bans live in RocksDB, the stale ban also had to be cleared explicitly — restarts don't help.
- **Hillstone separates NAT from policy.** DNAT answers "where does this packet go," the Security Policy answers "is this packet allowed." Both are required for inbound. The LAN hairpin path never crossed the untrust→trust boundary, so it falsely appeared to work — which is why a *global, off-LAN* reachability test was the decisive diagnostic.

## Prevention

**Diagnostic techniques that worked (reuse these):**

- **`check-host.net` global multi-node TCP probe** against the public IP — the single test that exposed the firewall block (web port open, mail ports filtered, from the real internet). Never trust a same-LAN test; NAT hairpin masks edge/firewall problems.
- **Python socket banner-arrival timing** — time the exact `recv()` of the `220` to cleanly isolate "through-Traefik (60s)" vs "direct-to-Stalwart (0s)". Avoids `nc`/`$()` buffering artifacts:

  ```python
  import socket, time
  s = socket.create_connection(("mail", 25), timeout=90)
  s.sendall(b"PROXY TCP4 8.8.8.8 172.20.0.5 40000 25\r\n")  # only when testing the backend directly
  t = time.time(); d = s.recv(200)
  print("elapsed=%.2f" % (time.time() - t), d[:60])
  ```

- **Read Stalwart Trace logs for decision-vs-response timestamps** — relay decision instant but `550` sent 5–30s later = tarpit/`waitOnFail`, not a network problem.

**Config gotchas to remember:**

- **PROXY protocol belongs on the backend hop only** (`...loadbalancer.proxyProtocol.version=2` in `compose.yml`), never on public mail entrypoints in `traefik.yml`.
- **Hillstone (and similar): DNAT ≠ permission.** Every inbound port-forward needs a matching untrust→trust Security Policy. Audit that web *and* mail ports each have both rules.
- **`waitOnFail` (UI: Settings → MTA → Session → RCPT → "Error Wait")**: setting it to `0`/blank does *not* mean instant — it falls back to a ~30s internal default and causes MxToolbox transaction-time timeouts on the relay-rejection path. Set an explicit small value (`1s`). This delay only affects rejected/relay (abuse) traffic; mail to valid local recipients stays sub-second.
- **Domain-level "Allow Relaying: true"** is for split-delivery only. It is *not* needed for authenticated outbound and must never be used to permit anonymous relay (open relay). Verified not an open relay: `allowRelaying=0` for unauthenticated.
- **Stalwart runtime settings (`allowed-ip`, CORS, log level, `waitOnFail`) live in RocksDB via the admin UI — they are NOT version-controlled** and reset on `docker compose down -v` / volume rebuild. Document them out-of-band so they can be re-applied.

**DNS reference (verified good):** MX `10 mail.hospitalsm.net`; A `181.39.233.78`; SPF `v=spf1 mx -all`; DMARC `p=reject`. Missing PTR (reverse DNS `NXDOMAIN`) is set by the ISP and affects outbound reputation only — not inbound delivery.

## Related Issues

- `docker/compose/email/traefik.yml` — where the `proxyProtocol` entrypoint misconfiguration (Root Cause 1) lived; fixed in commit `a397463`.
- `docker/compose/email/compose.yml` — service topology; holds the correct `loadbalancer.proxyProtocol.version=2` per-service PROXY setting.
- `docker/compose/email/.example.env` — environment template (`SESSION_SECRET`, `ADMIN_PASSWORD`, DigitalOcean token) for the stack.
- No prior `docs/solutions/` entries or GitHub issues — this is the first documented solution in the repo.
