# RustDesk Loop-Hunt — Attempt Ledger (TRIED.md)

Read this before every round. Never repeat a (component × altitude × bug-class × approach)
cell. Dedup new candidates against `FINDINGS.md` AND the rejected set below.

Mechanics locked: independent generator + judge-from-raw for every candidate; N=15 concurrency,
full isolation; pipeline; live-verify each survivor with a fresh reader; lab (root@192.168.1.119)
Docker for dynamic/ASAN. Stop after K=2 consecutive dry rounds.

Altitudes: [WP]=whole-project  [FILE]=file-by-file  [FUNC]=functionality  [FN]=function-by-function

---

## Round 0 — Deterministic front-load (DONE)
| Approach | Scope | Outcome |
|----------|-------|---------|
| cargo-audit RUSTSEC | client Cargo.lock (1057 deps) | 24 advisories → `sca-client.json`. Notable: RUSTSEC-2020-0071 time segfault, libgit2-sys RCE, openssl UAF, bytes int-overflow. LOGGED; deps EXCLUDED from LLM scope. |
| cargo-audit RUSTSEC | server Cargo.lock (385 deps) | 24 advisories → `sca-server.json`. Notable: protobuf 3.7.1 uncontrolled-recursion DoS (server parses unauth peer msgs → **reachable** — reachability lead), libsqlite3-sys CVE-2022-35737, rustls infinite-loop, axum no-body-limit. LOGGED; EXCLUDED. |
| semgrep --config=auto | client+server Rust src | 12 hits, all `detect-insecure-websocket` (ws://). Low-value; Rust poorly covered by semgrep registry. Noted as transport lead only. |
| Component inventory | full project | `INVENTORY.md` written — coverage denominator: ~60 components across A–M. |
| Provider-key detection | env | Only OPENAI keyed → generator=OpenAI(/agentic)+Claude-Sonnet subagents; judge=Claude harness (cross-vendor). |

### Round 0 reachability leads (carry into hunt, do NOT report as own findings)
- **protobuf recursion DoS (RUSTSEC-2024-0437)** — server `rendezvous_server.rs`/`relay_server.rs` decode unauth protobuf. Check nesting depth limits → possible pre-auth DoS. (dep bug, but reachability is RustDesk's)
- **bytes BytesMut::reserve int-overflow (RUSTSEC-2026-0007)** — used in `bytes_codec.rs` framing. Check if attacker controls reserve size.
- **ws:// insecure transport (semgrep)** — websocket.rs / relay. Check TLS enforcement / downgrade.

---

## Component coverage matrix (mirrors INVENTORY.md — the denominator)
All components UNCOVERED at start except omissions. Update as rounds complete.
UNCOVERED: A1-A12, B1-B6, C1-C12, D1-D4, E1-E6, F1-F3, G1-G5, H1-H3, I1, J1-J4, K1-K7, L1-L3, M1-M4
OMITTED: src/lang/* (i18n data), libxdo-sys-stub (trivial), transitive-dep-CVEs (Round 0 log-and-exclude)

---

## Rounds (append each round here BEFORE running the next)

### Round 1 — [WP]+[FUNC] Pre-auth network surface (server daemons + shared transports/framing/rendezvous)
Cells: B1,B2,B3,B4,B5 (server) + A1,A2,A8,A9 (hbb_common framing/compress/transports/proto) + E2,E3,E4 (client rendezvous/kcp/lan)
Lenses: pre-auth message parse, integer/length math, alloc-bomb, spoofing/authz on registration & relay, SQLi, MITM/TLS-downgrade, protobuf recursion.
Status: workflow wf_899d96a0 (15 gen + judges) running; orchestrator did INDEPENDENT reads of the crown jewels in parallel.

ORCHESTRATOR independent ground-truth (dual-confirmed w/ OpenAI gpt-5.4 judge):
- **CONFIRMED F-S02** register_pk TOFU id-squat (Medium / pot. High) → FINDINGS.md
- **CONFIRMED F-S01** X-Real-IP/X-Forwarded-For spoof from any WS client (Medium) → FINDINGS.md
- **CONFIRMED F-S03** online_request unbounded loop (Low, DoS — DEPRIORITIZED per scope)
- REJECTED (observed mitigation, → dedup index): server SQLi (sqlx bound params), bytes_codec alloc-bomb/int-overflow (256KB prealloc cap), register_pk hijack of EXISTING id (uuid-ownership), remote ConfigureUpdate (loopback-gated), server-side SSRF via HttpProxyRequest (no handler in hbbs).
Coverage now: B1 B2 B3 B4 B5 = COVERED(r1). A1(bytes_codec) A9(proto) = COVERED(r1). E2(rendezvous_mediator) partial.

TOP LEAD → R2: **client secure-channel MITM / encryption-downgrade.** `client.rs::secure_connection` (760-836) verifies peer box-pk via rendezvous server SIGN key (RS_PUB_KEY or configured `key`). Multiple **fall-back-to-plaintext** paths: empty `signed_id_pk` (773), sign_pk none (782-792), pk mismatch (816-820). `confirm_insecure_connection` (3825) UI gate. Need host-side (connection.rs) + UI confirm to determine if a MITM server/network can silently force plaintext or substitute pk. HIGH-VALUE RCE/MITM thread — spans multiple files (whole-flow pass required).

### Round 1 CLOSE-OUT (workflow wf_899d96a0 + OpenAI cross-vendor + orchestrator verify)
60 candidates → 52 Claude-survivors → 45 in-scope OpenAI-judged (17 conf / 18 needs-live / 6 corrected / 4 rejected).
**Reconciled report-worthy (both-vendor ≥High, in-scope):** F-C01 (RequestRelay.secure downgrade), F-C02 (UDP rendezvous ConfigureUpdate redirect), F-C03 (RegisterPk && pk-substitution / on-path hijack — my FN corrected UP), F-C04 (set_raw port-forward cleartext, needs-live), F-C05 (WsFramedStream Text-frame auth-bypass), F-S04 (AddrMangle reflector, DoS-class). +Tier-2 mediums F-S05..S09, F-C06..C09. All in FINDINGS.md. Artifacts: r1_reconciled.json, r1_survivors_full.json, r1_openai_verdicts.json.
**Theme:** rendezvous/relay secure-channel-bypass + message injection cluster. TCP rendezvous = SAFE (authenticated). UDP rendezvous = UNAUTH. Client trusts server msgs (ConfigureUpdate persist).
**Coverage now COVERED(r1):** B1-B5, A1(bytes_codec), A2(compress-partial), A8(tcp/udp/stream/ws/tls-partial), A9(proto), E2(rendezvous_mediator), E3(kcp-partial), E4(lan-partial), A4(fingerprint/verifier-partial), A5(password_security-partial), plus client secure_connection handshake (server.rs/common.rs/client.rs).
**Method learning R1:** (1) cross-vendor caught my FN on F-C03 (assumed-secret uuid was on-wire) — always check if the "secret barrier" is actually transmitted. (2) Claude over-rated 6 DoS/hardening to High; OpenAI correctly downgraded — keep OpenAI in the precision seat. (3) The workflow found real bugs I missed in files I'd read (AddrMangle reflector) — isolated fresh eyes > one careful read.

### LIVE-VALIDATION (lab root@192.168.1.119, Docker rust:bookworm, hbbs @ server 91fb928)
Built hbbs in Docker (native lab cargo too old for lockfile v4). Ran `poc/poc_rendezvous.py` vs live hbbs UDP:21116 default config:
- **F-C03 pk-substitution → LIVE-PROVEN VULNERABLE** (same-IP same-uuid overwrites pinned pk; wrong-uuid control rejected).
- **F-S04 reflector → LIVE-PROVEN VULNERABLE** (victim listener got reflected PunchHoleResponse).
hbbs container `hbbs_poc` left running on lab. PoC + RESULTS.md in out/projects/rustdesk/poc/.
Method note: UDP path = raw protobuf (tokio_util passthrough codec); TCP path = hbb_common length-prefixed codec. AddrMangle decode tm=0 form: number=(ip_u32<<49)|port.

### Round 2 — [FUNC]+[FN] CLIENT RCE surface (untrusted peer/host data → memory/fs/exec) + finish MITM cluster
Cells (draw from inventory, all UNCOVERED): 
 A6(hbb fs.rs path-traversal), D3(client/file_trait.rs), C3(clipboard_service), A/K3(clipboard lib + clipboard.rs + clipboard_file.rs) — FILE-TRANSFER/CLIPBOARD ARBITRARY-WRITE/PATH-TRAVERSAL
 C1(server/connection.rs msg dispatch), D1(client/io_loop.rs) — MESSAGE PARSING host↔controller (the big untrusted-input surface)
 K1(libs/scrap decode: codec/vpxcodec/aom/hwcodec) — CODEC MEMORY CORRUPTION on attacker frames
 F1/F2/F3(ipc.rs, ipc/auth.rs, ipc/fs.rs) + C10(portable_service) + J1(windows/acl) — IPC LOCAL PRIVESC (service runs elevated)
 H1/H2(plugin native loader) + I1(updater.rs) — RCE / supply-chain / unsigned-load
 C8(terminal_service) + C9(printer_service) — cmd-exec / file
 F-C04 caller check (port_forward.rs), F-C09 (login_failure_check rate-limit), F-S09 (admin via spoof)
Lenses: path-traversal/arbitrary-write, OOB/UAF/int-overflow on decode, command-injection, unsigned-code-load, local IPC authz-bypass/privesc, deserialization. DEPRIORITIZE pure-DoS.
Status: DONE. wf_96843333 (47 cand → 43 survive → 40 in-scope OpenAI-judged). Reconciled → FINDINGS.md R2 section (r2_reconciled.json).

### Round 2 CLOSE-OUT
**Shipped-build report-worthy (both-vendor ≥High):** F-C04 (E2E strip — CONFIRMED both vendors), F-R2-01 (GoogleImage int-overflow→OOB write — top RCE lead, needs fuzz), F-R2-02 (remove_jobs host→controller file overwrite), F-R2-03 (Cliprdr permission-bypass cluster), F-R2-04 (Windows IPC cross-session privesc), F-R2-05 (switch-sides tunnel-perm bypass), F-R2-06 (symlink path-confusion arb-write, conditional), F-R2-07 (updater no sig-verify → supply-chain RCE). +Tier-2 F-R2-08..12.
**GATED (verified NOT in shipped builds):** plugin cluster (macOS do-shell-script cmd-inj [was Crit], zip-slip, unsigned-dlopen, plugin-id, ShellExecuteW). Gate: get_plugin_source_list()=vec![] (manager.rs:66) + plugin_framework not in default features + never enabled in build.py. → per-file judges over-confirmed; my build-config cross-check killed them for shipped builds.
**Method learning R2:** per-file judges (Claude AND OpenAI) both miss BUILD-level reachability gates (feature flags, empty source lists) — orchestrator MUST cross-check Cargo.toml features + build.py for any finding in an optional module. This killed a "Critical."
**Coverage now COVERED(r2):** A6(fs.rs), K1(codec-partial: OOB+AV1 need deep/fuzz), K3(clipboard), C1(connection.rs msg-dispatch), D1(io_loop), F1/F2/F3(ipc), C10(portable_service), J1(win/acl), J2(gtk_sudo-partial), I1(updater), C8(terminal), C9(printer), E5(port_forward). H1/H2/H3 plugin = COVERED-but-GATED.

### Round 3 — DEPTH (codec fuzz on top RCE lead) + BREADTH (remaining inventory)
DEPTH: verify F-R2-01 (GoogleImage OOB) + fuzz VP8/VP9/AV1 decode + YUV→RGB convert on lab (AFL++/libFuzzer). The RCE crown-jewel thread.
BREADTH cells (UNCOVERED): L1-L3 (Dart/Flutter FFI + connection/permission logic), E6(custom_server config/deser), A7(proxy SSRF), C4(input_service unauth-input), C5/C6/C7(video/audio/display services), C12(wayland/dbus), J3(macos), J4(privacy_mode), K2(capture), K4(enigo), K5(virtual_display driver ioctl), K6(remote_printer), K7(portable), M3(whiteboard), A3(config), A10(mem), A11(keyboard).
Status: DONE. wf_2c36429e (34 cand → 28 survive). Reconciled → FINDINGS.md R3 section (r3_reconciled.json).
Depth note: F-R2-01 codec OOB REJECTED by orchestrator static verify (usize=64-bit, no overflow) — NO fuzz harness built (would chase an architecturally-refuted bug).

### Round 3 CLOSE-OUT
Report-worthy: F-R3-01 (custom-server unsigned-config sig bypass, High), F-R3-02 (proxy CRLF injection, High), F-R3-03 (2FA trusted-device bypass via self-reported hwid, Med→High), F-R3-04 (privacy-mode bypass cluster), F-R3-05 (keyboard→clipboard perm bypass), F-R3-06/07/08 (FFI/privesc/approve-mode, Med/Low). F-R3-CRIT (file path) CORRECTED down (Rust fs.rs validates ../+absolute; single-file metadata gap = needs-live).
Method learning R3: Dart-only generators can't see the RUST enforcement layer — a Dart "Critical" path-traversal was mitigated by Rust validate_file_name_no_traversal. Cross-LAYER (not just cross-file) verification is mandatory for the FFI/Dart↔Rust boundary.
COVERAGE: inventory now ~COMPLETE. Covered r3: L1-L3(Dart), E6(custom_server), A7(proxy), C4(input), C5-C7(av), C12(wayland/dbus), J3(macos), J4(privacy_mode), K4(enigo), K5(vdisplay), K6(printer), M3(whiteboard), A3(config), A10(mem-partial). Thin/remaining: webrtc.rs transport specifics, kcp deeper, K2(capture, low-value), K7(portable), M2(UI widgets, low-value), M4.
Yield trend: R1(4 Crit+6 High) → R2(F-C04 conf + 6 High) → R3(2-3 High + Med cluster). DECLINING. Not dry yet.

### Round 4 — VARIANT-HUNT on confirmed clusters + verification (convergence-oriented; NEW approach)
Novelty = hunt SIBLINGS of proven bugs (higher precision than broad slicing):
 (1) permission-gate systematic audit of connection.rs — enumerate EVERY peer-message type × its permission gate (variants of F-R2-03/05, F-R3-05 missing-gate class).
 (2) self-reported-identity-trust hunt — every hwid/uuid/machine_uid/device_id/peer-id used for authz (variants of F-C03, F-R3-03).
 (3) secure-channel-skip hunt — webrtc.rs/kcp_stream.rs/stream.rs + every parse path for set_key(None)/enc-skip/unauth-frame (variants of F-C01/04/05).
 (4) client-trusts-server-message hunt — every client handler of a server msg that mutates persistent state/triggers action (variants of F-C02).
 (5) fs.rs write-path gap verify — single-file metadata exemption + symlink derived-path (F-R3-CRIT, F-R2-06).
 (6) full 2FA/password/OTP/trusted-device/login_failure flow (verify F-R3-03, F-C09).
 + thin cells: webrtc transport, kcp, mem.rs unsafe, portable lib.
Status: DONE. wf_bcb374ee (19 cand → 16 survive). Reconciled → FINDINGS.md R4 section (r4_reconciled.json).

### Round 4 CLOSE-OUT + CONVERGENCE
**★ F-C10 (MARQUEE) — CONFIRMED Critical:** malicious host → dir-listing filename `../` → arbitrary write → RCE on controller. 4-way confirmed (Claude gen+judge + orchestrator cross-layer + OpenAI WHOLE-FLOW judge). Was a pre-flagged R3 gap; R4 variant-hunt nailed it.
**Variants confirmed (siblings, validate coverage):** F-R4-01 (Android input-inject no-perm ×2), F-R4-02 (server-addr-trust, F-C02 sibling), F-R4-03 (SSRF/internal-connect), F-R4-04 (root CLI provisioning), F-R4-05 (audio no-perm), F-R4-06 (switch-sides skips 2FA re-verify), F-R4-07 (toggle-vdisplay/privacy no-perm, per-IP lockout).
**CRITICAL METHOD LEARNING:** OpenAI per-file judge FALSE-NEGATIVE'd F-C10 (rejected reading only fs.rs — couldn't see base-taint from Dart/io_loop). WHOLE-FLOW re-judge (all 3 files) → confirmed/Critical. RULE: cross-layer/FFI findings MUST be judged with the whole flow, never per-file. (Also fixed: relative `file` paths in candidates broke openai_judge read → spurious rejects; always absolutize.)
**CONVERGENCE:** candidate count 60→47→34→19 (monotonic decline). R4 = mostly SIBLINGS of known clusters + one pre-flagged gap confirmed. **Rate of genuinely-NEW bug classes ≈ 0.** This is effectively dry-round #1 for new classes (F-C10 was a known lead, not a new class). Inventory ~fully covered.
**DECISION:** converged. Produce consolidated disclosure report (the deliverable). One more variant/thin round (R5) available if user wants a formal 2nd dry round, but marginal yield expected.

Final tally: ~31 in-scope findings. Crown jewels: F-C10 (Crit RCE), F-C01/02/03/04/05 (secure-channel-bypass cluster, 2 live-proven), F-R2/R3/R4 permission-bypass/privesc/updater/SSRF. Plugin cluster GATED. Server hardened.

### Round 5 CLOSE-OUT + LOOP COMPLETE (dry twice)
wf_6a96b39b (11 cand → 8 survive). NO new shipped-build High/Critical. Survivors = siblings of known clusters + F-R5-WEBRTC (GATED latent MITM design flaw: is_secured() hardcoded true + set_key no-op + DTLS fingerprint not pinned to peer pk → skips insecure-consent prompt; feature off + unwired today; fix before shipping WebRTC) + Low items (PeerConfig regex, CLI-flag log path, Windows-IPC PID-reuse needs-live).
CONVERGENCE: candidate counts 60→47→34→19→11 (monotonic). R4 = siblings + 1 pre-flagged Crit (F-C10). R5 = siblings + gated + Low. **Two consecutive rounds with no genuinely-new shipped High/Critical bug-class → STOP CONDITION (dry×2) SATISFIED. LOOP COMPLETE.**
Deliverable: out/RUSTDESK-SECURITY-ASSESSMENT.md (+ copy in out/). Memory: reference_rustdesk_audit + feedback_cross_layer_whole_flow_judging.
Deeper-pass options left (optional, not blockers): WebRTC fingerprint-auth live trace (if feature enabled), dedicated codec fuzz campaign, scrap capture backends.

### Rejected-reason dedup keys (server)
- server:database.rs:*:sqli → sqlx bound params
- server:bytes_codec:decode:alloc-bomb → 256KB prealloc cap (hardened)
- server:rendezvous_server:register_pk:hijack-existing → uuid-ownership enforced
- server:rendezvous_server:ConfigureUpdate:remote → loopback-gated
- server:rendezvous_server:HttpProxyRequest:ssrf → no server handler
