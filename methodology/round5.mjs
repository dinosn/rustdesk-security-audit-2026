export const meta = {
  name: 'rustdesk-r5-convergence',
  description: 'RustDesk loop-hunt Round 5 (convergence/dry-check): deepest-remaining surface — WebRTC DTLS-fingerprint auth, more F-C10 file-transfer siblings, capture backends, mobile paths, config/id paths, ipc deeper, + completeness critic. Each judged from raw.',
  phases: [ { title:'Generate' }, { title:'Judge' } ],
}
const T='/Users/krasn/tools/raptor/targets/rustdesk'
const S=`${T}/src`, HBB=`${T}/libs/hbb_common/src`

const PRIMER=`RustDesk P2P remote desktop — Round 5 CONVERGENCE/dry-check. Rounds 1-4 already found (DO NOT re-report): rendezvous/relay secure-channel-bypass cluster (RequestRelay.secure downgrade, UDP ConfigureUpdate redirect, RegisterPk pk-substitution, WsFramedStream Text-frame, set_raw E2E strip), the F-C10 file-transfer path-traversal (malicious host dir-listing filename -> arbitrary write on controller), Windows IPC cross-session privesc, Cliprdr/keyboard/audio permission-bypasses, updater no-sig, custom_server unsigned-config, proxy CRLF, 2FA trusted-device bypass, privacy-mode bypass cluster, SSRF via server-supplied addresses. Plugin cluster is GATED (not shipped). Report only GENUINELY-NEW issues or NEW variants with a distinct root cause/location. Check permission enforcement at the RUST layer.`

const CONTRACT=`For EACH candidate: title, component, file(ABSOLUTE path), line(int), function, bug_class, root_cause("<fn> in <file> does not <check>, allowing <consequence>"), entry_point, sink, trace, attack(attacker,exact input,observed result), preconditions(permission?default?feature-gate-check Cargo.toml), severity, potential_severity, confidence(0..1)+confidence_reason, disposition_hint. Real attacker entry + dangerous sink + trace each. Use ABSOLUTE file paths. Read RAW (Grep huge files). DEPRIORITIZE pure-DoS. If you find NOTHING new, return an empty candidates array — that is a valid, expected result this round.`

const GEN_SCHEMA={type:'object',properties:{reviewed_files:{type:'array',items:{type:'string'}},candidates:{type:'array',items:{type:'object',properties:{title:{type:'string'},component:{type:'string'},file:{type:'string'},line:{type:'integer'},function:{type:'string'},bug_class:{type:'string'},root_cause:{type:'string'},entry_point:{type:'string'},sink:{type:'string'},trace:{type:'string'},attack:{type:'string'},preconditions:{type:'string'},severity:{type:'string'},potential_severity:{type:'string'},confidence:{type:'number'},confidence_reason:{type:'string'},disposition_hint:{type:'string'}},required:['title','file','function','bug_class','root_cause','entry_point','sink','attack','severity','confidence']}}},required:['candidates']}
const JUDGE_SCHEMA={type:'object',properties:{verdict:{type:'string',enum:['confirmed','needs-live-validation','corrected','rejected']},reason:{type:'string'},observed_mitigation:{type:'string'},corrected_severity:{type:'string'},corrected_root_cause:{type:'string'},live_test:{type:'string'},final_severity:{type:'string'},confidence:{type:'number'}},required:['verdict','reason']}

const CELLS=[
 {key:'webrtc-auth', files:[`${HBB}/webrtc.rs`,`${S}/rendezvous_mediator.rs`,`${HBB}/socket_client.rs`],
  lens:'WebRTC transport applies NO RustDesk secretbox (set_key no-op, relies on DTLS). Determine: is the DTLS certificate FINGERPRINT authenticated? Trace how the WebRTC offer/answer/SDP + fingerprint are exchanged (via the rendezvous server signaling). If a malicious/MITM rendezvous server can substitute the DTLS fingerprint / relay the SDP unauthenticated, WebRTC sessions are MITM-able (no secretbox identity binding). Report if fingerprint is unverified.'},
 {key:'fs-siblings', files:[`${HBB}/fs.rs`,`${S}/server/connection.rs`,`${S}/clipboard_file.rs`],
  lens:'More F-C10-class siblings: any OTHER place a remote/peer-controlled path or filename (rename, mkdir, remove, digest sibling, resume-offset base, clipboard-file drop, printer spool) reaches a filesystem op where the BASE path (not just name) is attacker-influenced and unvalidated. Also the HOST-side receive (controller uploads to host) path-traversal. Distinct root cause/location from F-C10.'},
 {key:'capture-backends', files:[`${T}/libs/scrap/src/common/x11.rs`,`${T}/libs/scrap/src/common/wayland.rs`,`${T}/libs/scrap/src/common/dxgi.rs`,`${T}/libs/scrap/src/common/mediacodec.rs`],
  lens:'Screen-capture backends (thin cell). Hunt memory/unsafe issues in the capture path, shared-memory handling, and any place capture dimensions/buffers are attacker- or environment-influenced. Mostly non-attacker-facing; report real memory bugs only.'},
 {key:'mobile-android', files:[`${S}/server/connection.rs`,`${S}/flutter_ffi.rs`],
  lens:'Android/mobile-specific paths. Grep cfg(target_os="android"/"ios"). Hunt: mobile permission model gaps (input/accessibility injection without gate), the mobile CM accept flow, any FFI reachable from a compromised app context. Distinct from the desktop findings.'},
 {key:'config-id-paths', files:[`${HBB}/config.rs`,`${S}/naming.rs`,`${S}/core_main.rs`],
  lens:'Config + id-based file paths + CLI arg handling in core_main. Hunt: attacker/peer-influenced values used to build config/log/id file paths (path traversal on config write), CLI arg parsing that a local attacker abuses (uri handler / --flag), predictable or injectable config option values, env trust at startup.'},
 {key:'ipc-deeper', files:[`${S}/ipc.rs`,`${S}/platform/windows.rs`,`${S}/platform/linux.rs`],
  lens:'Deeper IPC/platform privesc (beyond the confirmed Windows cross-session). Named-pipe/unix-socket ACLs at CREATION, the service<->UI trust for EACH privileged op (password read, config write, elevation, install/uninstall), Linux socket path perms, symlink on the ipc socket path. Report unauthenticated privileged local ops.'},
 {key:'terminal-exec', files:[`${S}/server/terminal_service.rs`,`${S}/server/terminal_helper.rs`,`${S}/platform/linux_desktop_manager.rs`],
  lens:'Terminal/exec deeper: is the terminal permission enforced before EVERY shell spawn (open/resize/write/close/reset)? env/arg/PATH injection into the spawned shell, working-dir trust, the desktop-manager session spawn. Report command-exec reachable without the terminal permission or with injectable args/env.'},
 {key:'completeness-critic', files:[`${T}/src`,`${T}/libs`],
  lens:'COMPLETENESS CRITIC: given rounds 1-4 covered the pre-auth network, client RCE surface, Dart logic, and confirmed-cluster variants, identify what was NOT examined — any module/message-type/entry-point/transport NOT yet traced, or any claim rounds 1-4 asserted without proof. Grep broadly (rg for Message union arms, unsafe blocks, Command::new, fs::write/File::create, dlopen/LoadLibrary, unwrap on peer input). Report the highest-value UNEXAMINED surface as candidates (a lead is fine if it names a concrete file:function + why it matters).'},
]

phase('Generate'); log(`Round 5 convergence/dry-check: ${CELLS.length} generators`)
const results=await pipeline(CELLS,
 (cell)=>agent(`${PRIMER}\n\nIsolated generator. Slice: ${cell.key}.\nRead RAW (Grep first):\n${cell.files.map(f=>'  '+f).join('\n')}\n\nHUNT LENS: ${cell.lens}\n\n${CONTRACT}\n\nReturn ONLY the structured object.`,
   {label:`gen:${cell.key}`,phase:'Generate',schema:GEN_SCHEMA,model:'sonnet'}).then(r=>({cell:cell.key,...(r||{candidates:[]})})),
 (gen,cell)=>{const cands=(gen&&gen.candidates)?gen.candidates:[]; if(!cands.length)return {cell:cell.key,judged:[]};
   return parallel(cands.map(c=>()=>agent(`${PRIMER}\n\nIndependent JUDGE, re-derive from raw (whole flow if cross-file). RE-READ file=${c.file} fn=${c.function}.\n\nCANDIDATE:\n${JSON.stringify(c,null,2)}\n\nREJECT only with an OBSERVED reason (mitigating check PRESENT cite line / not reachable / designed / feature-gated / already-found-in-R1-4 not new). Unobservable barrier -> needs-live-validation+live_test. Mis-rated -> corrected. Provable -> confirmed. Return ONLY verdict.`,
     {label:`judge:${cell.key}:${(c.title||'').slice(0,20)}`,phase:'Judge',schema:JUDGE_SCHEMA,model:'sonnet'}).then(v=>({candidate:c,verdict:v||{verdict:'rejected',reason:'judge-null'}}))
   )).then(judged=>({cell:cell.key,judged}))})
const out=[]; for(const r of results.filter(Boolean))for(const j of (r.judged||[]))out.push({cell:r.cell,...j})
const kept=out.filter(o=>o.verdict&&o.verdict.verdict&&o.verdict.verdict!=='rejected')
log(`Round 5 done: ${out.length} candidates, ${kept.length} survive`)
return {round:5,total:out.length,survivors:kept,rejected:out.filter(o=>!kept.includes(o))}
