export const meta = {
  name: 'rustdesk-r1-preauth',
  description: 'RustDesk loop-hunt Round 1: N=15 isolated generators over pre-auth network surface (server daemons + shared framing/transports/proto + client rendezvous), each candidate judged from raw',
  phases: [
    { title: 'Generate', detail: '15 isolated generators, from raw source, finding-contract candidates' },
    { title: 'Judge', detail: 'per-candidate refutation from raw; disposition' },
  ],
}

const T = '/Users/krasn/tools/raptor/targets'
const HBB = `${T}/rustdesk/libs/hbb_common/src`      // shared lib (client pin 7e1c392)
const SRV = `${T}/rustdesk-server/src`               // server daemons
const SRVHBB = `${T}/rustdesk-server/libs/hbb_common/src` // server pin 83419b6
const CSRC = `${T}/rustdesk/src`                     // client src

const PRIMER = `RustDesk is a peer-to-peer remote-desktop tool.
- Server side: 'hbbs' (rendezvous/ID server, ${SRV}/rendezvous_server.rs) handles peer registration, heartbeat, and NAT hole-punching over UDP+TCP; 'hbbr' (relay, ${SRV}/relay_server.rs) blindly relays encrypted streams between peers when hole-punch fails. Both are PRE-AUTH network daemons reachable by any internet host.
- Peers identify by a numeric ID; a controlled peer may require a password. A secure channel is set up with NaCl (box/secretbox, sign) over the peer connection.
- Client parses messages FROM the rendezvous server and FROM the remote peer — a malicious/MITM server or peer is an ATTACKER against the client.
- Protobuf messages are defined in libs/hbb_common/protos/{message,rendezvous}.proto. Framing is length-prefixed (bytes_codec.rs).
TRUST BOUNDARIES: (1) any internet host -> hbbs/hbbr (pre-auth). (2) rendezvous server -> client (client trusts server messages). (3) remote peer -> the machine being controlled (after handshake). (4) remote host -> controller (controller parses host's frames/clipboard/files).`

const CONTRACT = `For EACH candidate vulnerability output:
- title, component, file (absolute path), line (best guess int), function
- bug_class (e.g. integer-overflow, oob-read, oob-write, uaf, alloc-bomb, auth-bypass, spoofing, sqli, path-traversal, ssrf, mitm-tls, dos, logic)
- root_cause templated: "<function> in <file> does not <missing check>, allowing <consequence>"
- entry_point: the attacker-controlled source (which message/field/packet, from which trust boundary)
- sink: the dangerous operation reached
- trace: ordered hops from entry_point to sink (function/file each hop)
- attack: WHO the attacker is, the EXACT input/packet/sequence, and the OBSERVED result
- preconditions: config/auth/version/build gating (state "default config: yes/no")
- severity: Critical|High|Medium|Low (likelihood x impact; unauth-RCE/full-takeover=Critical)
- potential_severity: worst case IF an unobserved layer is insecure (never collapse to Low because a confirming layer is out of view)
- confidence: 0..1 with a one-line reason
- disposition_hint: "confirmed-from-artifacts" if provable from code in hand, else "needs-live-validation"
RULES: high recall — enumerate aggressively — but every candidate MUST name a real attacker-controlled entry point AND a real dangerous sink with a trace between them (else it's a lead, drop it). Do NOT pad with hardening notes. Read the RAW source with the Read tool before asserting anything. If you cannot cite the exact code, do not report it.`

const GEN_SCHEMA = {
  type: 'object',
  properties: {
    reviewed_files: { type: 'array', items: { type: 'string' } },
    candidates: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          title: { type: 'string' }, component: { type: 'string' },
          file: { type: 'string' }, line: { type: 'integer' }, function: { type: 'string' },
          bug_class: { type: 'string' }, root_cause: { type: 'string' },
          entry_point: { type: 'string' }, sink: { type: 'string' }, trace: { type: 'string' },
          attack: { type: 'string' }, preconditions: { type: 'string' },
          severity: { type: 'string' }, potential_severity: { type: 'string' },
          confidence: { type: 'number' }, confidence_reason: { type: 'string' },
          disposition_hint: { type: 'string' },
        },
        required: ['title','file','function','bug_class','root_cause','entry_point','sink','attack','severity','confidence'],
      },
    },
  },
  required: ['candidates'],
}

const JUDGE_SCHEMA = {
  type: 'object',
  properties: {
    verdict: { type: 'string', enum: ['confirmed','needs-live-validation','corrected','rejected'] },
    reason: { type: 'string' },
    observed_mitigation: { type: 'string' },
    corrected_severity: { type: 'string' },
    corrected_root_cause: { type: 'string' },
    live_test: { type: 'string' },
    final_severity: { type: 'string' },
    confidence: { type: 'number' },
  },
  required: ['verdict','reason'],
}

// 15 isolated generator cells over the pre-auth surface
const CELLS = [
  { key: 'srv-rendezvous', files: [`${SRV}/rendezvous_server.rs`],
    lens: 'PRE-AUTH parse of RendezvousMessage variants over UDP+TCP: register_peer/register_pk/punch_hole/request_relay/configure_update/software_update etc. Hunt: peer-ID spoofing (register/hijack another peer\'s ID or public key), unauthenticated state mutation, integer/length math on incoming fields, unbounded allocation, panics on malformed input (DoS), missing rate-limit, key/uuid checks that can be bypassed.' },
  { key: 'srv-relay', files: [`${SRV}/relay_server.rs`, `${SRV}/hbbr.rs`],
    lens: 'PRE-AUTH relay: can an unauthenticated peer open a relay session to an ARBITRARY target (SSRF-via-relay / internal pivot), relay unlimited data (amplification/resource exhaustion), or bypass licence/allow-list checks? Check how the relay pairs the two sides, any address/target taken from the request, and framing/size limits.' },
  { key: 'srv-peer-db', files: [`${SRV}/peer.rs`, `${SRV}/database.rs`],
    lens: 'Peer registry + sqlite. Hunt: SQL injection (any query built from peer-controlled id/uuid/info without binding), peer record hijack/spoofing, unbounded growth, i32/time math (note recent overflow fix), guid/pk trust.' },
  { key: 'srv-common-utils', files: [`${SRV}/common.rs`, `${SRV}/utils.rs`, `${SRV}/main.rs`, `${SRV}/lib.rs`],
    lens: 'Server key/secret/licence handling, get_expired_time and time math, any parse of peer input, env/config trust, default secrets, comparison of keys (timing/constant-time), test_if_valid_server style checks.' },
  { key: 'hbb-bytescodec', files: [`${HBB}/bytes_codec.rs`],
    lens: 'Length-prefixed frame decoder. Hunt: attacker-controlled length field -> unbounded/huge allocation (alloc-bomb DoS), integer overflow in size math, BytesMut::reserve overflow (RUSTSEC-2026-0007 reachability), missing max-frame-size cap.' },
  { key: 'hbb-compress', files: [`${HBB}/compress.rs`],
    lens: 'Decompression of attacker data. Hunt: decompression bomb (no output-size bound), integer overflow on decompressed length, OOB, unwrap/panic on malformed compressed input (DoS).' },
  { key: 'hbb-tcp-stream', files: [`${HBB}/tcp.rs`, `${HBB}/stream.rs`],
    lens: 'TCP framing + secure-stream wrapper. Hunt: read-loop size limits, secretbox/nonce handling, unencrypted-fallback, integer math on frame length, panics, how the encryption key is established and whether an unencrypted frame is accepted where an encrypted one is expected.' },
  { key: 'hbb-udp-socket', files: [`${HBB}/udp.rs`, `${HBB}/socket_client.rs`],
    lens: 'UDP framing + socket client (proxy/connect). Hunt: packet parse bounds, spoofed-source acceptance, SSRF via connect target, proxy handling, integer math.' },
  { key: 'hbb-ws-webrtc', files: [`${HBB}/websocket.rs`, `${HBB}/webrtc.rs`],
    lens: 'WebSocket + WebRTC transport. Hunt: message-size limits (unbounded frame -> memory DoS, cf. tungstenite RUSTSEC), ws:// vs wss:// enforcement / TLS downgrade, origin/host validation, parse panics.' },
  { key: 'hbb-tls-verify', files: [`${HBB}/tls.rs`, `${HBB}/fingerprint.rs`, `${HBB}/verifier.rs`],
    lens: 'TLS + identity verification — MITM surface. Hunt: does the TLS client actually VERIFY the server certificate (or accept any cert)? custom verifier that returns Ok unconditionally? public-key/fingerprint pinning correctness, non-constant-time compare of keys/fingerprints, downgrade.' },
  { key: 'hbb-config-pwd', files: [`${HBB}/config.rs`, `${HBB}/password_security.rs`],
    lens: 'Config/key store + password security. Hunt: weak password hashing/derivation, non-constant-time password compare, key material at rest, predictable salt/nonce, permission-password model, encrypted-config key derivation.' },
  { key: 'cli-rendezvous-mediator', files: [`${CSRC}/rendezvous_mediator.rs`],
    lens: 'CLIENT parses messages FROM the rendezvous server (server = attacker under MITM or malicious server). Hunt: does the client blindly trust a server-pushed relay redirect / config update / connect request / software_update URL? request_relay to an attacker address, forced downgrade, panic-on-malformed (DoS), any field used to build a path/URL/command.' },
  { key: 'cli-kcp', files: [`${CSRC}/kcp_stream.rs`],
    lens: 'KCP reliable-UDP stream. Hunt: framing/segment length math, buffer handling, integer overflow, state machine on attacker segments, memory growth, panics.' },
  { key: 'cli-lan', files: [`${CSRC}/lan.rs`],
    lens: 'LAN discovery over UDP broadcast — any host on the LAN is the attacker. Hunt: parse of peer-announce packets, spoofed peer entries injected into the local peer list, fields used unsafely, panics, amplification.' },
  { key: 'wp-auth-securechannel', files: [`${CSRC}/rendezvous_mediator.rs`, `${SRV}/rendezvous_server.rs`, `${HBB}/tcp.rs`, `${HBB}/config.rs`],
    lens: 'WHOLE-PROJECT trust-boundary pass on connection establishment + secure channel. Trace end-to-end: how does a peer prove identity / get authorized, where is the NaCl box/sign key exchange, and can a MITM (server or network) downgrade to no-encryption, substitute a public key, replay, or bypass the password/permission gate? Focus on DESIGN-level auth-bypass and MITM spanning these files.' },
]

phase('Generate')
log(`Round 1: ${CELLS.length} isolated generators over pre-auth surface`)

const results = await pipeline(
  CELLS,
  (cell) => agent(
    `${PRIMER}\n\nYou are an isolated security generator. Slice: ${cell.key}.\nRead these RAW source files with the Read tool (read them fully):\n${cell.files.map(f=>'  '+f).join('\n')}\n\nHUNT LENS: ${cell.lens}\n\n${CONTRACT}\n\nReturn ONLY the structured object. If a file is large, read it in full anyway — coverage matters. Enumerate every real candidate; do not self-censor on recall, the judge will refute.`,
    { label: `gen:${cell.key}`, phase: 'Generate', schema: GEN_SCHEMA, model: 'sonnet' }
  ).then(r => ({ cell: cell.key, ...(r || { candidates: [] }) })),
  (gen, cell) => {
    const cands = (gen && gen.candidates) ? gen.candidates : []
    if (!cands.length) return { cell: cell.key, judged: [] }
    return parallel(cands.map(c => () =>
      agent(
        `${PRIMER}\n\nYou are an independent JUDGE. Do NOT trust the claim below — re-derive from raw.\nRE-READ the cited source with the Read tool: file=${c.file} function=${c.function} (read the whole file and surrounding context).\n\nCANDIDATE CLAIM:\n${JSON.stringify(c, null, 2)}\n\nYour job: try to REFUTE it. You may REJECT only with an OBSERVED reason you can point to in the code: the cited code doesn't do what the claim says; the entry point is NOT attacker-reachable; a mitigating check is PRESENT in code you can read (cite file:line); or it is designed behavior under the stated trust model. \nINVALID refutations (do NOT use): "a real server probably handles it", "the framework likely validates", "presumably authz upstream", "needs non-default config" (unless you verify the default), "not built/loaded" (unless you verify). Assuming an UNSEEN layer is secure is NOT refutation.\nIf the ONLY barrier is a layer you cannot observe (runtime you can't run, peer/server code not in these files) -> verdict = needs-live-validation, keep the worst-case (potential) severity, and emit an EXACT safe live_test (command/packet + expected vulnerable-vs-safe result).\nIf real but mis-rated/mis-scoped -> corrected, give final_severity + corrected_root_cause.\nIf real and provable from artifacts -> confirmed, set final_severity.\nReturn ONLY the structured verdict.`,
        { label: `judge:${cell.key}:${(c.title||'').slice(0,24)}`, phase: 'Judge', schema: JUDGE_SCHEMA, model: 'sonnet' }
      ).then(v => ({ candidate: c, verdict: v || { verdict: 'rejected', reason: 'judge-null' } }))
    )).then(judged => ({ cell: cell.key, judged }))
  }
)

// Flatten survivors, keep everything (incl rejected) for the ledger
const out = []
for (const r of results.filter(Boolean)) {
  for (const j of (r.judged || [])) {
    out.push({ cell: r.cell, ...j })
  }
}
const kept = out.filter(o => o.verdict && o.verdict.verdict && o.verdict.verdict !== 'rejected')
const rejected = out.filter(o => !o.verdict || !o.verdict.verdict || o.verdict.verdict === 'rejected')
log(`Round 1 done: ${out.length} candidates, ${kept.length} survive (confirmed/needs-live/corrected), ${rejected.length} rejected`)
return { round: 1, total: out.length, survivors: kept, rejected }
