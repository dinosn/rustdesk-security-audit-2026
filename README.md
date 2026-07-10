# RustDesk Security Audit — 2026

Security assessment of **RustDesk** (open-source remote desktop) — **client and server** — covering the pre-auth network surface, the peer-to-peer secure channel, the client remote-control/file-transfer paths, IPC/privilege boundaries, and the Dart/Flutter + FFI layers.

> ⚠️ **Private / undisclosed.** These are previously-unreported (0-day) findings. This repository is private and for internal tracking only. **Do not publish or share externally** until coordinated disclosure with the RustDesk maintainers is complete.

---

## Targets

| Component | Repo | Commit | Size |
|-----------|------|--------|------|
| Client | `rustdesk/rustdesk` | `137298e` | ~142K LoC Rust + ~71K LoC Dart |
| Server | `rustdesk/rustdesk-server` | `91fb928` | ~3.4K LoC Rust |
| Shared | `rustdesk/hbb_common` (submodule) | client `7e1c392` / server `83419b6` | protocol + crypto + net |

---

## Headline findings

| ID | Finding | Severity | Status |
|----|---------|----------|--------|
| **F-C10** | Malicious **host** → file-transfer path traversal (`../` in a directory-listing filename) → **arbitrary file write → RCE on the controller** | **Critical** | Confirmed (4 independent readers) |
| **F-C01** | `RequestRelay.secure` cleartext flag → **encryption downgrade to plaintext** session | Critical / High | Confirmed |
| **F-C02** | Unauthenticated **UDP rendezvous** → `ConfigureUpdate` → **persistent client redirect** + address injection | Critical / High | Confirmed |
| **F-C03** | `RegisterPk` same-source-IP `&&` guard → **persistent ID hijack / MITM** (uuid = cleartext `machine_uid`) | High / Critical | ✅ **Live-proven** |
| **F-C04** | Port-forward / RDP tunnel **strips E2E encryption** (`set_raw()` drops the secretbox key) | High | Confirmed |
| **F-C05** | `WsFramedStream` **Text-frame secretbox authentication bypass** | High | Confirmed |
| **F-S04** | Unauthenticated **UDP reflector** (forged `AddrMangle` destination) | High (DoS-class) | ✅ **Live-proven** |

Plus ~20 more (Windows IPC cross-session **privilege escalation**, Cliprdr/keyboard/audio **permission bypasses**, **updater with no signature verification**, custom-server unsigned-config acceptance, proxy CRLF injection, **2FA trusted-device bypass**, privacy-mode bypass cluster, SSRF via server-supplied addresses). Full list in [`FINDINGS.md`](FINDINGS.md); disclosure-grade write-up in [`RUSTDESK-SECURITY-ASSESSMENT.md`](RUSTDESK-SECURITY-ASSESSMENT.md).

**The through-line:** the RustDesk **server and shared framing are well-hardened**; the real exposure is (1) the **rendezvous/relay secure channel** — the "encrypted" session can be downgraded, hijacked, or injected into by an on-path attacker or malicious server — and (2) a **malicious host → controller** arbitrary-file-write RCE via file transfer.

### Correctly excluded / down-rated (calibration)
- **Plugin subsystem** bugs (incl. a would-be-Critical macOS `do shell script` command-injection) and the **WebRTC `is_secured()` latent MITM** are **feature-gated out of shipped builds** — reported as *gated*, not live.
- A candidate "Critical" **codec OOB** was **refuted** (64-bit `usize` sizing — no overflow); ~10 DoS/hardening items down-rated.
- **Server is solid** on: parameterized SQL, 256 KB frame-prealloc cap, uuid-ownership on established IDs, loopback-gated admin/config, authenticated+encrypted TCP rendezvous.

---

## Methodology

Produced with the **RAPTOR loop-hunt** — a looping, multi-altitude, generate-then-adversarially-verify vulnerability hunt:

- **5 looped rounds**, N=15 isolated reasoners per round, full isolation (each reads raw source, blind to the others).
- **4-altitude traversal:** whole-project → file-by-file → functionality → function, plus a variant-hunt round and a convergence/dry-check round.
- **3-way cross-vendor reconciliation for every candidate:** an independent Claude generator → a Claude judge (re-reading from raw, prompted to refute) → an **OpenAI `gpt-5.4` cross-vendor judge** (from raw) → orchestrator **whole-flow** verification.
- **Two findings live-proven** against a real `hbbs` binary on a lab host (see [`poc/`](poc/)).
- **Convergence:** candidate counts declined monotonically **60 → 47 → 34 → 19 → 11**; the loop stopped when two consecutive rounds produced no genuinely-new shipped-build High/Critical.

Two methodology lessons captured in [`TRIED.md`](TRIED.md):
1. **Per-file judges false-negative on cross-layer taint.** F-C10 spans Dart → FFI → Rust; the OpenAI judge initially rejected it reading only the Rust sink file (it couldn't see the base path was attacker-tainted in Dart). Re-judging with the **whole flow** confirmed it Critical.
2. **Per-file judges miss build-level reachability gates.** The plugin "Critical" was killed by cross-checking `Cargo.toml` features + `build.py` (feature disabled, empty source list).

The exact per-round hunt scripts and the cross-vendor judge harness are in [`methodology/`](methodology/).

---

## Repository layout

```
├── RUSTDESK-SECURITY-ASSESSMENT.md   # Disclosure-grade report (start here)
├── FINDINGS.md                       # Full findings ledger (per-finding root cause, trace, attack, remediation)
├── TRIED.md                          # Attempt ledger — every round, altitude, slice, and method learning
├── INVENTORY.md                      # Component coverage matrix (the completeness gate)
├── poc/
│   ├── poc_rendezvous.py             # Live PoC: F-C03 (pk-substitution) + F-S04 (UDP reflector)
│   └── RESULTS.md                    # Live-proof output against a real hbbs
├── methodology/
│   ├── round1.mjs … round5.mjs       # The 5 loop-hunt workflow scripts (RAPTOR)
│   └── openai_judge.py               # Cross-vendor (OpenAI gpt-5.4) judge harness
└── data/
    ├── r{1..4}_reconciled.json       # 3-way verdict summaries per round
    ├── sca-{client,server}.json      # cargo-audit / RUSTSEC dependency scan
    └── raw/                          # Full survivor claims + Claude/OpenAI judge reasoning
```

---

## Reproducing the live PoC (F-C03 + F-S04)

Both are proven against a real `hbbs` in default config (no `-k` key). On a lab host with Docker:

```bash
# Build hbbs (native cargo may be too old for lockfile v4 — build in a modern container)
git clone --depth 1 https://github.com/rustdesk/rustdesk-server && cd rustdesk-server
git submodule update --init --depth 1 libs/hbb_common
docker run --rm -v "$PWD:/src" -w /src rust:bookworm bash -c \
  'apt-get update -qq && apt-get install -y -qq libssl-dev pkg-config && cargo build --release --bin hbbs'

# Run hbbs (host-networked so the PoC reaches UDP :21116)
docker run -d --name hbbs --network host -v "$PWD:/work" -w /work rust:bookworm ./target/release/hbbs

# Fire the PoC (raw protobuf over UDP; reads the sqlite DB to confirm the pk overwrite)
DB_PATH="$PWD/db_v2.sqlite3" HBBS_PORT=21116 python3 poc/poc_rendezvous.py
```

Expected: `F-C03 pk-substitution: VULNERABLE` (a same-source-IP registration with the sniffable `uuid` overwrites the server-pinned public key; a wrong-`uuid` control is rejected) and `F-S04 reflector: VULNERABLE` (a victim listener that never contacted `hbbs` receives a reflected `PunchHoleResponse`). See [`poc/RESULTS.md`](poc/RESULTS.md).

---

## Suggested remediation priorities

1. **F-C10** — canonicalize + confine the download destination to the chosen root; reject `..`/absolute in the **base** path, not only the filename.
2. **F-C01 / F-C02** — authenticate the rendezvous channel end-to-end (especially UDP); refuse silent plaintext downgrade; make the insecure indicator un-dismissable.
3. **F-C03** — require proof-of-possession (challenge signed by the registered key) before any `pk` change; stop treating the cleartext `machine_uid` as an ownership secret.
4. **F-R2-07** — sign/verify update artifacts (don't rely on TLS alone), especially for custom/self-hosted API servers.
5. **F-C04 / F-C05** — no transport (port-forward, RDP tunnel, WebSocket Text frames, WebRTC) may carry session data outside the secretbox.

---

*Generated with the RAPTOR autonomous research framework · findings independently cross-vendor verified · 2 live-proven.*
