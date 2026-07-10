export const meta = {
  name: 'rustdesk-r2-client-rce',
  description: 'RustDesk loop-hunt Round 2: N=15 isolated generators over the client RCE surface (file-transfer/clipboard arbitrary-write, host<->controller message parsing, codec decode memory-corruption, IPC local privesc, plugin/updater RCE), each judged from raw',
  phases: [
    { title: 'Generate', detail: '15 isolated generators over the client RCE surface' },
    { title: 'Judge', detail: 'per-candidate refutation from raw' },
  ],
}

const T = '/Users/krasn/tools/raptor/targets/rustdesk'
const HBB = `${T}/libs/hbb_common/src`
const S = `${T}/src`
const SC = `${T}/libs/scrap/src/common`
const CB = `${T}/libs/clipboard/src`

const PRIMER = `RustDesk P2P remote desktop. Attack model for THIS round (post-handshake / local):
- HOST side (machine being controlled): src/server/connection.rs parses EVERY message from the controlling peer after login — mouse/keyboard, file-transfer, clipboard, options, port-forward, terminal. A malicious CONTROLLER is the attacker. Permission gating (keyboard/file/clipboard/terminal/restart/...) is enforced here.
- CONTROLLER side: src/client/io_loop.rs parses messages from the remote HOST (a malicious/compromised host is the attacker against the controller).
- FILE TRANSFER: libs/hbb_common/src/fs.rs implements the file read/write protocol; remote-supplied paths -> local filesystem. Arbitrary-write / path-traversal / symlink here ~= RCE.
- CLIPBOARD: src/clipboard*.rs + libs/clipboard (incl. a FUSE server) move files via clipboard; remote-controlled file names/paths.
- CODEC: libs/scrap decodes attacker-supplied VP8/VP9/AV1/H26x frames via libvpx/aom/hwcodec (C libs) — Rust wrapper bounds/stride/size math is the memory-corruption surface.
- IPC: src/ipc.rs + ipc/auth.rs + ipc/fs.rs — the UI talks to a SERVICE running as SYSTEM/root over a local pipe/socket; local privesc surface (who may connect, what ops are authorized).
- PLUGIN: src/plugin/* loads native code. UPDATER: src/updater.rs downloads+applies updates.
OUT OF SCOPE (already found in R1 — do NOT re-report): rendezvous/relay secure-channel bypasses, UDP ConfigureUpdate redirect, RequestRelay.secure downgrade, RegisterPk pk-substitution, WsFramedStream Text-frame, AddrMangle reflector, X-Real-IP spoof.`

const CONTRACT = `For EACH candidate output: title, component, file (absolute), line (int), function, bug_class (path-traversal|arbitrary-write|oob-read|oob-write|uaf|int-overflow|command-injection|deserialization|privesc|authz-bypass|unsigned-load|type-confusion|ssrf|logic), root_cause ("<fn> in <file> does not <check>, allowing <consequence>"), entry_point (which message/field/file-op/frame, from which attacker), sink (dangerous op), trace (hops), attack (attacker, exact input, observed result), preconditions (permission needed? default config? gating), severity (Critical|High|Medium|Low), potential_severity, confidence (0..1)+confidence_reason, disposition_hint.
FOCUS: RCE, arbitrary file write/read, path traversal, memory corruption on decode, local privesc, command injection, unsigned-code load. DEPRIORITIZE pure-DoS (only report if trivial+unauth). Every candidate needs a real attacker-controlled entry point AND a real dangerous sink with a trace. Read RAW source with Read; for large files use Grep to find the message dispatch / sinks then Read those regions. Enumerate aggressively; the judge will refute. Cite exact code.`

const GEN_SCHEMA = { type:'object', properties:{ reviewed_files:{type:'array',items:{type:'string'}},
  candidates:{type:'array',items:{type:'object',properties:{
    title:{type:'string'},component:{type:'string'},file:{type:'string'},line:{type:'integer'},function:{type:'string'},
    bug_class:{type:'string'},root_cause:{type:'string'},entry_point:{type:'string'},sink:{type:'string'},trace:{type:'string'},
    attack:{type:'string'},preconditions:{type:'string'},severity:{type:'string'},potential_severity:{type:'string'},
    confidence:{type:'number'},confidence_reason:{type:'string'},disposition_hint:{type:'string'}},
    required:['title','file','function','bug_class','root_cause','entry_point','sink','attack','severity','confidence']}}},
  required:['candidates']}

const JUDGE_SCHEMA = { type:'object', properties:{
  verdict:{type:'string',enum:['confirmed','needs-live-validation','corrected','rejected']},
  reason:{type:'string'},observed_mitigation:{type:'string'},corrected_severity:{type:'string'},
  corrected_root_cause:{type:'string'},live_test:{type:'string'},final_severity:{type:'string'},confidence:{type:'number'}},
  required:['verdict','reason']}

const CELLS = [
  { key:'fs-transfer', files:[`${HBB}/fs.rs`],
    lens:'File-transfer protocol from remote peer. Hunt: path traversal (absolute paths, ../, symlink, UNC/drive on Windows) in read_dir/get_recursive/write file ops; arbitrary file WRITE to attacker path (=RCE via autostart/config); arbitrary READ/exfil; no confinement to an agreed root; TOCTOU. Trace each remote-supplied path field to the fs syscall.' },
  { key:'clipboard-file', files:[`${S}/clipboard_file.rs`, `${S}/clipboard.rs`],
    lens:'Clipboard file transfer (cliprdr). Hunt: remote-controlled file names/paths written locally (path traversal/arbitrary write), format/size parsing OOB, the CliprdrClientMsg handling, permission gating (clipboard/file perms).' },
  { key:'clipboard-fuse', files:[`${CB}/lib.rs`, `${CB}/platform/unix/fuse/mod.rs`, `${CB}/platform/unix/serv_files.rs`, `${CB}/platform/unix/local_file.rs`],
    lens:'Clipboard FUSE + file server. Hunt: attacker-controlled file metadata/paths, path traversal in the FUSE-exposed names, size/offset math OOB, symlink, arbitrary read of local files.' },
  { key:'ipc-fs', files:[`${S}/ipc/fs.rs`],
    lens:'IPC file operations performed by the (elevated) service. Hunt: does the elevated side do fs ops on paths supplied by a less-privileged/remote requester without authz/confinement -> local privesc / arbitrary write as SYSTEM/root; path traversal; symlink.' },
  { key:'conn-dispatch-a', files:[`${S}/server/connection.rs`],
    lens:'HOST message dispatch (part A: login/auth/permission + file/clipboard messages). Use Grep for the message match (Union), permission checks (ControlPermissions/keyboard/file/clipboard/terminal), and password/2FA verify. Hunt: permission-gate bypass (act without the granted permission), missing authz on a message type, path/command reached from a message field, unauth message accepted pre-login.' },
  { key:'conn-dispatch-b', files:[`${S}/server/connection.rs`],
    lens:'HOST message dispatch (part B: input/options/terminal/port-forward/misc messages). Grep the dispatch. Hunt: keyboard/mouse/text injection without permission, option/setting messages that change security state, terminal/exec reachable, memory/parse issues, restart/elevation triggers from a message.' },
  { key:'io-loop', files:[`${S}/client/io_loop.rs`],
    lens:'CONTROLLER parsing messages from a malicious HOST. Hunt: memory/logic on host-supplied messages, host-driven file writes on the controller (reverse file transfer), clipboard/paths from host, any host message that makes the controller execute/download/write, panics.' },
  { key:'codec-vpx', files:[`${SC}/codec.rs`, `${SC}/vpxcodec.rs`, `${SC}/vpx.rs`],
    lens:'VP8/VP9 decode of attacker frames. Hunt: decoded width/height/stride trusted without bounds -> OOB when copying/converting; frame length/size int-overflow; buffer allocation vs actual data mismatch; UAF across decode calls; unchecked libvpx return + use of output.' },
  { key:'codec-aom-hw', files:[`${SC}/aom.rs`, `${SC}/hwcodec.rs`, `${SC}/convert.rs`],
    lens:'AV1 (aom) + hardware codec + YUV/RGB convert. Hunt: stride/dimension/size math OOB in convert (i420/nv12->rgba), attacker-controlled dimensions from frame header, buffer sizing overflow, unchecked hw decoder output length.' },
  { key:'ipc-core-auth', files:[`${S}/ipc.rs`, `${S}/ipc/auth.rs`],
    lens:'UI<->elevated-service IPC. Hunt: who can connect to the IPC named pipe/unix socket (ACL/peer-cred check?) — if any local user can connect and issue privileged ops -> local privesc; command/path injection via IPC messages; authz on each IPC op; secrets over IPC.' },
  { key:'privesc-platform', files:[`${S}/server/portable_service.rs`, `${S}/platform/windows/acl.rs`, `${S}/platform/gtk_sudo.rs`, `${S}/platform/linux.rs`],
    lens:'Privilege boundaries. Hunt: shared-memory/portable-service trust, Windows ACL/service creation weaknesses, gtk_sudo/pkexec env-injection or arg-injection in elevation, world-writable resources, PATH/env trust during privileged spawn.' },
  { key:'plugin-load', files:[`${S}/plugin/native.rs`, `${S}/plugin/plugins.rs`, `${S}/plugin/manager.rs`, `${S}/plugin/native_handlers/mod.rs`],
    lens:'Plugin native-code loading. Hunt: does the plugin manager download+load a native library WITHOUT signature/hash verification, or from an attacker-influenceable URL/path/config -> RCE; unsafe FFI callback boundaries; path traversal in plugin install.' },
  { key:'updater', files:[`${S}/updater.rs`],
    lens:'Auto-update. Hunt: update URL trust (server/config-controlled), signature/hash verification of the downloaded artifact (absence -> RCE via malicious update), downgrade attack, arbitrary write of the downloaded file, TLS on the download.' },
  { key:'exec-services', files:[`${S}/server/terminal_service.rs`, `${S}/server/terminal_helper.rs`, `${S}/server/printer_service.rs`],
    lens:'Terminal + printer services. Hunt: remote command execution gating (is the terminal permission enforced before spawning a shell? can args/env be injected?), printer spool file path/format handling, arbitrary write via printer.' },
  { key:'loose-ends', files:[`${S}/port_forward.rs`, `${S}/server/login_failure_check.rs`, `${S}/server/connection.rs`],
    lens:'R1 loose ends. (1) port_forward.rs: confirm whether set_raw() drops E2E encryption on the network-facing peer link (real cleartext downgrade) vs an inner pipe. (2) login_failure_check.rs + connection.rs password path: is the connection password brute-force rate-limited/locked out (a weak/short one-time password + no lockout = remote access)? (3) any admin/privileged action reachable by an unauth or spoofed-source peer.' },
]

phase('Generate')
log(`Round 2: ${CELLS.length} isolated generators over the client RCE surface`)

const results = await pipeline(
  CELLS,
  (cell) => agent(
    `${PRIMER}\n\nIsolated security generator. Slice: ${cell.key}.\nRead these RAW files (Read tool; use Grep first on huge files to find dispatch/sinks):\n${cell.files.map(f=>'  '+f).join('\n')}\n\nHUNT LENS: ${cell.lens}\n\n${CONTRACT}\n\nReturn ONLY the structured object.`,
    { label:`gen:${cell.key}`, phase:'Generate', schema:GEN_SCHEMA, model:'sonnet' }
  ).then(r => ({ cell: cell.key, ...(r || { candidates: [] }) })),
  (gen, cell) => {
    const cands = (gen && gen.candidates) ? gen.candidates : []
    if (!cands.length) return { cell: cell.key, judged: [] }
    return parallel(cands.map(c => () =>
      agent(
        `${PRIMER}\n\nIndependent JUDGE. Do NOT trust the claim; re-derive from raw.\nRE-READ the cited source (Read tool): file=${c.file} function=${c.function} (read the whole relevant region + callers).\n\nCANDIDATE:\n${JSON.stringify(c,null,2)}\n\nTry to REFUTE. REJECT only with an OBSERVED reason: cited code doesn't do what claimed; entry point not attacker-reachable; a mitigating check PRESENT (cite file:line: e.g. a permission gate, a path-canonicalize+prefix-check, a signature verify, an IPC peer-cred check); or designed behavior. INVALID: "a real client probably checks", "framework validates", "needs non-default config"(unless verified), "the elevated service surely authorizes"(unless you SEE it). Assuming an unseen layer is secure is NOT refutation. If the only barrier is unobservable -> needs-live-validation + worst-case severity + exact safe live_test. If real but mis-rated -> corrected + final_severity. If provable -> confirmed + final_severity. Weigh: a permission-gated action a granted peer misuses is lower than an UNGATED one; arbitrary-write to an attacker path is High/Critical (RCE). Return ONLY the structured verdict.`,
        { label:`judge:${cell.key}:${(c.title||'').slice(0,22)}`, phase:'Judge', schema:JUDGE_SCHEMA, model:'sonnet' }
      ).then(v => ({ candidate: c, verdict: v || { verdict:'rejected', reason:'judge-null' } }))
    )).then(judged => ({ cell: cell.key, judged }))
  }
)

const out=[]
for (const r of results.filter(Boolean)) for (const j of (r.judged||[])) out.push({ cell:r.cell, ...j })
const kept=out.filter(o=>o.verdict&&o.verdict.verdict&&o.verdict.verdict!=='rejected')
const rejected=out.filter(o=>!o.verdict||!o.verdict.verdict||o.verdict.verdict==='rejected')
log(`Round 2 done: ${out.length} candidates, ${kept.length} survive, ${rejected.length} rejected`)
return { round:2, total:out.length, survivors:kept, rejected }
