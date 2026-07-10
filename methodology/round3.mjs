export const meta = {
  name: 'rustdesk-r3-breadth',
  description: 'RustDesk loop-hunt Round 3 (breadth): N=15 isolated generators over the remaining inventory — Dart/Flutter authz+permission logic, FFI boundary, custom_server/proxy, input/video/audio services, privacy-mode bypass, platform privesc, virtual-display/printer drivers, config — each judged from raw',
  phases: [ { title:'Generate' }, { title:'Judge' } ],
}
const T='/Users/krasn/tools/raptor/targets/rustdesk'
const S=`${T}/src`, HBB=`${T}/libs/hbb_common/src`, F=`${T}/flutter/lib`

const PRIMER=`RustDesk P2P remote desktop — BREADTH round over UI/services/config/drivers. Attack models:
- Malicious CONTROLLER vs HOST (post-login, permission-gated) — permissions: keyboard/file/clipboard/audio/camera/terminal/tunnel/restart/recording/block_input/remote_modify/privacy_mode.
- Malicious/MITM SERVER or peer vs client.
- LOCAL attacker (privesc via IPC/driver/service).
Key Dart logic lives in flutter/lib/models/*.dart (HOST accept-connection + permission grant + unattended-access password are decided here; the Rust side enforces too). FFI boundary = src/flutter_ffi.rs. Already-found (DO NOT re-report): rendezvous/relay MITM cluster, E2E-strip port-forward, codec OOB, Cliprdr perm-bypass, Windows IPC privesc, updater no-sig, plugin cluster (gated).`

const CONTRACT=`For EACH candidate: title, component, file(abs), line(int), function, bug_class(authz-bypass|privilege-escalation|logic|command-injection|path-traversal|arbitrary-write|ssrf|deserialization|memory|type-confusion|privacy-bypass|input-injection), root_cause("<fn> in <file> does not <check>, allowing <consequence>"), entry_point(attacker+which input), sink, trace(hops), attack(attacker,exact input,observed result), preconditions(permission? default config? feature-gate — CHECK Cargo.toml features/build.py if in an optional module), severity, potential_severity, confidence(0..1)+confidence_reason, disposition_hint. FOCUS: authz/permission bypass, privesc, privacy-mode bypass, input-injection without permission, config/deser injection, SSRF, memory. DEPRIORITIZE pure-DoS. Real entry+sink+trace each. Read RAW (Grep huge files for the dispatch/permission checks). Cite exact code.`

const GEN_SCHEMA={type:'object',properties:{reviewed_files:{type:'array',items:{type:'string'}},candidates:{type:'array',items:{type:'object',properties:{title:{type:'string'},component:{type:'string'},file:{type:'string'},line:{type:'integer'},function:{type:'string'},bug_class:{type:'string'},root_cause:{type:'string'},entry_point:{type:'string'},sink:{type:'string'},trace:{type:'string'},attack:{type:'string'},preconditions:{type:'string'},severity:{type:'string'},potential_severity:{type:'string'},confidence:{type:'number'},confidence_reason:{type:'string'},disposition_hint:{type:'string'}},required:['title','file','function','bug_class','root_cause','entry_point','sink','attack','severity','confidence']}}},required:['candidates']}
const JUDGE_SCHEMA={type:'object',properties:{verdict:{type:'string',enum:['confirmed','needs-live-validation','corrected','rejected']},reason:{type:'string'},observed_mitigation:{type:'string'},corrected_severity:{type:'string'},corrected_root_cause:{type:'string'},live_test:{type:'string'},final_severity:{type:'string'},confidence:{type:'number'}},required:['verdict','reason']}

const CELLS=[
 {key:'dart-server-accept', files:[`${F}/models/server_model.dart`,`${F}/desktop/pages/server_page.dart`],
  lens:'HOST accept-connection + permission-grant + unattended-access password logic in Dart. Hunt: auto-accept without prompt, permission defaults too broad, password/PIN gating bypass, a connection accepted without the security-password check, permission state not enforced.'},
 {key:'dart-model-core', files:[`${F}/models/model.dart`],
  lens:'Core Dart message/session model. Grep for permission, password, authorized, handle_*; hunt authz/logic bugs where a peer message changes security state or a permission is not checked before an action.'},
 {key:'dart-input-file', files:[`${F}/models/input_model.dart`,`${F}/models/file_model.dart`],
  lens:'Input + file-transfer Dart models. Hunt: input/file actions performed without the corresponding permission, path handling from peer, file overwrite prompts bypassed.'},
 {key:'ffi-boundary', files:[`${S}/flutter_ffi.rs`],
  lens:'Rust<->Dart FFI. Grep the exported fn surface; hunt: privileged operations (config write, install, elevation, IPC, file) exposed via FFI callable without auth, type-confusion on args, session/id not validated, any FFI that a compromised UI or a session message can reach to escalate.'},
 {key:'custom-server', files:[`${S}/custom_server.rs`],
  lens:'Custom server config (base64/JSON config string -> deser). Hunt: config injection, deser of attacker-influenced config, the config string parsing, whether a malicious config URL/string sets api/rendezvous/relay to attacker hosts or injects options.'},
 {key:'proxy-ssrf', files:[`${HBB}/proxy.rs`],
  lens:'Proxy handling. Hunt: SSRF via proxy target, credential leakage, host/scheme validation, proxy string parse.'},
 {key:'input-service', files:[`${S}/server/input_service.rs`,`${S}/server/rdp_input.rs`],
  lens:'HOST input injection from the controlling peer. Hunt: is keyboard/mouse/text injection gated by the keyboard permission and the block_input state? can input be injected without permission, or during privacy/block-input? key mapping OOB.'},
 {key:'av-services', files:[`${S}/server/video_service.rs`,`${S}/server/audio_service.rs`,`${S}/server/display_service.rs`],
  lens:'Video/audio/display services. Hunt: capture started/streamed without the corresponding permission (recording/camera/audio), display switch logic, resource/size math, memory on frame construction.'},
 {key:'privacy-mode', files:[`${S}/privacy_mode.rs`,`${S}/server/wayland.rs`,`${S}/server/dbus.rs`],
  lens:'Privacy mode + wayland/dbus. Hunt: can a peer view the screen when privacy mode should block it (privacy-bypass)? race between enabling privacy mode and capture; dbus/wayland auth.'},
 {key:'macos-platform', files:[`${S}/platform/macos.rs`,`${S}/platform/delegate.rs`],
  lens:'macOS platform. Hunt: privilege escalation, TCC/permission handling, unsafe process spawn, path/env trust in privileged operations, helper-tool auth.'},
 {key:'linux-platform', files:[`${S}/platform/linux.rs`,`${S}/platform/linux_desktop_manager.rs`],
  lens:'Linux platform (already partly seen). Hunt: privileged spawn env/arg injection, PATH trust, xauth/display handling, session/user enumeration -> command building (get_home et al), world-writable resources.'},
 {key:'vdisplay-printer', files:[`${T}/libs/virtual_display/src/lib.rs`,`${T}/libs/remote_printer/src/lib.rs`,`${T}/libs/remote_printer/src/setup/driver.rs`,`${T}/libs/remote_printer/src/setup/setup.rs`],
  lens:'Virtual-display + remote-printer drivers. Hunt: driver/ioctl input validation, printer driver install as privileged (privesc), path/file handling in printer setup, attacker-controlled spool/driver name.'},
 {key:'enigo-input', files:[`${T}/libs/enigo/src/lib.rs`,`${T}/libs/enigo/src/dsl.rs`],
  lens:'Enigo input-simulation lib. Hunt: parse of input DSL/keysequence from peer, OOB/panic on crafted key data, unicode handling.'},
 {key:'whiteboard', files:[`${S}/whiteboard/mod.rs`,`${S}/whiteboard/server.rs`,`${S}/whiteboard/client.rs`],
  lens:'Whiteboard feature. Hunt: network input parsing, whether whiteboard messages are permission-gated, memory/logic on peer-supplied whiteboard data.'},
 {key:'config-misc', files:[`${HBB}/config.rs`,`${S}/naming.rs`,`${HBB}/keyboard.rs`,`${HBB}/mem.rs`],
  lens:'Config store + naming + keyboard map + mem utils. Hunt: config file parse/injection, path handling in config/id paths, unsafe in mem.rs, key-map OOB, predictable/secret config values, option injection.'},
]

phase('Generate'); log(`Round 3 breadth: ${CELLS.length} generators over remaining inventory`)
const results=await pipeline(CELLS,
 (cell)=>agent(`${PRIMER}\n\nIsolated generator. Slice: ${cell.key}.\nRead RAW (Grep huge files first):\n${cell.files.map(f=>'  '+f).join('\n')}\n\nHUNT LENS: ${cell.lens}\n\n${CONTRACT}\n\nReturn ONLY the structured object.`,
   {label:`gen:${cell.key}`,phase:'Generate',schema:GEN_SCHEMA,model:'sonnet'}).then(r=>({cell:cell.key,...(r||{candidates:[]})})),
 (gen,cell)=>{const cands=(gen&&gen.candidates)?gen.candidates:[]; if(!cands.length)return {cell:cell.key,judged:[]};
   return parallel(cands.map(c=>()=>agent(`${PRIMER}\n\nIndependent JUDGE, re-derive from raw. RE-READ file=${c.file} fn=${c.function}.\n\nCANDIDATE:\n${JSON.stringify(c,null,2)}\n\nTry to REFUTE with an OBSERVED reason (cited code doesn't do what claimed / not attacker-reachable / mitigating check PRESENT cite line / designed / FEATURE-GATED-check Cargo.toml). INVALID: assuming an unseen layer is secure. If barrier unobservable -> needs-live-validation + worst-case + live_test. If mis-rated -> corrected+final_severity. If provable -> confirmed+final_severity. A permission-gated action a granted peer misuses is LOWER than an ungated one. Return ONLY the verdict.`,
     {label:`judge:${cell.key}:${(c.title||'').slice(0,20)}`,phase:'Judge',schema:JUDGE_SCHEMA,model:'sonnet'}).then(v=>({candidate:c,verdict:v||{verdict:'rejected',reason:'judge-null'}}))
   )).then(judged=>({cell:cell.key,judged}))})
const out=[]; for(const r of results.filter(Boolean))for(const j of (r.judged||[]))out.push({cell:r.cell,...j})
const kept=out.filter(o=>o.verdict&&o.verdict.verdict&&o.verdict.verdict!=='rejected')
log(`Round 3 done: ${out.length} candidates, ${kept.length} survive`)
return {round:3,total:out.length,survivors:kept,rejected:out.filter(o=>!kept.includes(o))}
