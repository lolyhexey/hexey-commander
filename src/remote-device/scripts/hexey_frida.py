"""Frida helper for the remote device.

One long-running process per device. Reads one JSON request per line on stdin
and writes one JSON response per line on stdout:

    {"id": 1, "op": "attach", "target": "notepad.exe"}
    {"id": 1, "ok": true, "result": {...}}  or  {"id": 1, "ok": false, "error": "..."}

Sessions stay open between requests until detached or the helper exits.
"""
import json
import os
import sys
import threading
import time
import traceback

import frida
import re

# Frida 17 no longer puts the Java and ObjC bridges in the runtime; this bundle
# (see scripts/frida-bridges/) defines them for scripts that use them.
BRIDGES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frida-bridges.js")
USES_BRIDGE = re.compile(r"\b(Java|ObjC)\b")
_bridges = [None]


def bridges_source():
    if _bridges[0] is None:
        try:
            with open(BRIDGES_FILE, encoding="utf-8") as f:
                _bridges[0] = f.read()
        except OSError as e:
            raise ValueError("Java/ObjC bridge bundle missing (%s); reinstall the package" % e)
    return _bridges[0]


def create_script(s, source):
    if USES_BRIDGE.search(source):
        source = bridges_source() + "\n;\n" + source
    return s["session"].create_script(source)

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------

device = frida.get_local_device()
devices = {}          # alias -> frida.Device
sessions = {}         # session id -> session record
next_session = [1]
next_script = [1]
next_hook = [1]
out_lock = threading.Lock()

# Per-session event/error buffers
event_buffers = {}    # session id -> [events]
error_buffers = {}    # session id -> [errors]
# Per-session memory patches for restore on cleanup
memory_patches = {}   # session id -> [(address, original_hex)]
# Per-session named scripts
named_scripts = {}    # session id -> {script_id -> {script, name, source}}
# Per-session hooks
active_hooks = {}     # session id -> {hook_id -> {script, target, type}}


def reply(obj):
    with out_lock:
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()


def need(req, key):
    if key not in req or req[key] in (None, ""):
        raise ValueError('"%s" is required' % key)
    return req[key]


def get_device(req):
    """Resolve the device from a request, defaulting to local."""
    dev = req.get("device")
    if not dev:
        return device
    if dev in devices:
        return devices[dev]
    for d in frida.enumerate_devices():
        if d.id == dev or d.name == dev:
            return d
    raise ValueError("device not found: %s" % dev)


def get_session(req):
    sid = str(need(req, "session"))
    s = sessions.get(sid)
    if s is None:
        raise ValueError("no session %s (open sessions: %s)" % (sid, ", ".join(sessions) or "none"))
    if s["session"].is_detached:
        sessions.pop(sid, None)
        raise ValueError("session %s ended (the process exited or was detached)" % sid)
    return s


def add_session(session_obj, pid, name, spawned):
    sid = str(next_session[0])
    next_session[0] += 1
    sessions[sid] = {
        "session": session_obj, "pid": pid, "name": name,
        "spawned": spawned, "scripts": [],
    }
    event_buffers[sid] = []
    error_buffers[sid] = []
    memory_patches[sid] = []
    named_scripts[sid] = {}
    active_hooks[sid] = {}
    return sid


def add_event(sid, event):
    buf = event_buffers.get(sid)
    if buf is not None and len(buf) < 50000:
        event["_ts"] = time.time()
        buf.append(event)


def add_error(sid, error):
    buf = error_buffers.get(sid)
    if buf is not None and len(buf) < 5000:
        buf.append({"error": str(error), "at": time.time()})


def run_js(s, source, wait=5.0, max_messages=5000, keep=False):
    """Load a script, collect what it send()s for `wait` seconds (or until it
    sends {"done": true}), and return the messages."""
    messages = []
    finished = threading.Event()

    def on_message(msg, data):
        if msg.get("type") == "send":
            payload = msg.get("payload")
            if isinstance(payload, dict) and payload.get("done"):
                finished.set()
                return
            if len(messages) < max_messages:
                item = {"payload": payload}
                if data is not None:
                    item["data_hex"] = data.hex()
                messages.append(item)
            else:
                finished.set()
        elif msg.get("type") == "error":
            messages.append({"error": msg.get("description"), "stack": msg.get("stack")})
            finished.set()

    script = create_script(s, source)
    script.on("message", on_message)
    script.load()
    finished.wait(wait)
    if keep:
        s["scripts"].append(script)
    else:
        try:
            script.unload()
        except Exception:
            pass
    return messages


def first_payload(msgs):
    for m in msgs:
        if "error" in m:
            raise ValueError(m["error"])
        if "payload" in m:
            return m["payload"]
    raise ValueError("no answer from the script")


# ---------------------------------------------------------------------------
# Device & Process Management
# ---------------------------------------------------------------------------

def op_devices(req):
    out = []
    for d in frida.enumerate_devices():
        out.append({"id": d.id, "name": d.name, "type": str(d.type)})
    return out


def op_device_info(req):
    d = get_device(req)
    params = d.query_system_parameters()
    return {
        "id": d.id,
        "name": d.name,
        "type": str(d.type),
        "os": params.get("os", {}).get("id", "unknown"),
        "os_version": params.get("os", {}).get("version", "unknown"),
        "arch": params.get("arch", "unknown"),
        "platform": params.get("platform", "unknown"),
        "access": params.get("access", "unknown"),
    }


def op_connect_device(req):
    address = need(req, "address")
    alias = req.get("alias") or address
    mgr = frida.get_device_manager()
    d = mgr.add_remote_device(address)
    devices[alias] = d
    devices[d.id] = d
    return {"id": d.id, "name": d.name, "type": str(d.type), "alias": alias}


def op_server_status(req):
    d = get_device(req)
    try:
        params = d.query_system_parameters()
        return {
            "connected": True,
            "device_id": d.id,
            "device_name": d.name,
            "frida_version": frida.__version__,
            "os": params.get("os", {}).get("id", "unknown"),
            "arch": params.get("arch", "unknown"),
        }
    except Exception as e:
        return {"connected": False, "device_id": d.id, "error": str(e)}


def op_processes(req):
    d = get_device(req)
    flt = (req.get("filter") or "").lower()
    out = []
    for p in d.enumerate_processes():
        if flt and flt not in p.name.lower() and flt != str(p.pid):
            continue
        out.append({"pid": p.pid, "name": p.name})
    out.sort(key=lambda p: p["pid"])
    return out


def op_applications(req):
    d = get_device(req)
    flt = (req.get("filter") or "").lower()
    out = []
    for a in d.enumerate_applications():
        if flt and flt not in a.name.lower() and flt not in a.identifier.lower():
            continue
        out.append({
            "identifier": a.identifier,
            "name": a.name,
            "pid": a.pid if a.pid else None,
        })
    out.sort(key=lambda a: a["name"].lower())
    return out


# ---------------------------------------------------------------------------
# Session & Process Control
# ---------------------------------------------------------------------------

def op_attach(req):
    d = get_device(req)
    target = need(req, "target")
    pid = int(target) if str(target).isdigit() else None
    if pid is None:
        matches = [p for p in d.enumerate_processes() if p.name.lower() == str(target).lower()]
        if not matches:
            raise ValueError("no running process named %s" % target)
        if len(matches) > 1:
            raise ValueError("%d processes are named %s; attach by pid: %s" % (
                len(matches), target, ", ".join(str(p.pid) for p in matches)))
        pid, name = matches[0].pid, matches[0].name
    else:
        name = next((p.name for p in d.enumerate_processes() if p.pid == pid), str(pid))
    session_obj = d.attach(pid)
    sid = add_session(session_obj, pid, name, False)
    return {"session": sid, "pid": pid, "name": name}


def op_spawn(req):
    d = get_device(req)
    program = need(req, "program")
    argv = [program] + [str(a) for a in (req.get("args") or [])]
    pid = d.spawn(argv)
    session_obj = d.attach(pid)
    sid = add_session(session_obj, pid, program, True)
    if not req.get("suspended"):
        d.resume(pid)
    return {"session": sid, "pid": pid, "suspended": bool(req.get("suspended"))}


def op_resume(req):
    s = get_session(req)
    d = get_device(req)
    d.resume(s["pid"])
    return {"resumed": s["pid"]}


def op_kill(req):
    d = get_device(req)
    sid = req.get("session")
    pid = req.get("pid")
    if sid:
        s = sessions.get(str(sid))
        if s:
            pid = s["pid"]
            _cleanup_session(str(sid))
    if pid is None:
        raise ValueError("provide session or pid")
    pid = int(pid)
    d.kill(pid)
    return {"killed": pid}


def op_sessions(req):
    out = []
    for sid, s in list(sessions.items()):
        out.append({
            "session": sid, "pid": s["pid"], "name": s["name"],
            "spawned": s["spawned"], "detached": s["session"].is_detached,
            "scripts": len(s["scripts"]) + len(named_scripts.get(sid, {})),
            "hooks": len(active_hooks.get(sid, {})),
        })
    return out


def op_session_status(req):
    s = get_session(req)
    sid = str(req["session"])
    ns = named_scripts.get(sid, {})
    ah = active_hooks.get(sid, {})
    return {
        "session": sid,
        "pid": s["pid"],
        "name": s["name"],
        "spawned": s["spawned"],
        "detached": s["session"].is_detached,
        "anonymous_scripts": len(s["scripts"]),
        "named_scripts": [{"script_id": k, "name": v.get("name", "")} for k, v in ns.items()],
        "hooks": [{"hook_id": k, "target": v.get("target", ""), "type": v.get("type", "")} for k, v in ah.items()],
        "events_buffered": len(event_buffers.get(sid, [])),
        "errors_buffered": len(error_buffers.get(sid, [])),
        "memory_patches": len(memory_patches.get(sid, [])),
    }


def op_detach(req):
    sid = str(need(req, "session"))
    s = sessions.pop(sid, None)
    if s is None:
        raise ValueError("no session %s" % sid)
    _cleanup_session_state(sid, s)
    if not s["session"].is_detached:
        s["session"].detach()
    if req.get("kill") and s["spawned"]:
        try:
            device.kill(s["pid"])
        except Exception:
            pass
    return {"detached": sid, "pid": s["pid"]}


def _cleanup_session_state(sid, s):
    """Remove all hooks, scripts, patches, buffers for a session."""
    for hid, h in list(active_hooks.get(sid, {}).items()):
        try:
            h["script"].unload()
        except Exception:
            pass
    active_hooks.pop(sid, None)
    for scid, sc in list(named_scripts.get(sid, {}).items()):
        try:
            sc["script"].unload()
        except Exception:
            pass
    named_scripts.pop(sid, None)
    for sc in s.get("scripts", []):
        try:
            sc.unload()
        except Exception:
            pass
    event_buffers.pop(sid, None)
    error_buffers.pop(sid, None)
    memory_patches.pop(sid, None)


def _cleanup_session(sid):
    s = sessions.pop(sid, None)
    if s is None:
        return
    _cleanup_session_state(sid, s)
    if not s["session"].is_detached:
        try:
            s["session"].detach()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Script Management
# ---------------------------------------------------------------------------

def op_load_script(req):
    s = get_session(req)
    sid = str(req["session"])
    source = need(req, "source")
    name = req.get("name") or ""
    script_id = str(next_script[0])
    next_script[0] += 1

    def on_message(msg, data):
        if msg.get("type") == "send":
            add_event(sid, {"source": "script", "script_id": script_id, "payload": msg.get("payload")})
        elif msg.get("type") == "error":
            add_error(sid, msg.get("description", "script error"))

    script = create_script(s, source)
    script.on("message", on_message)
    script.load()

    named_scripts.setdefault(sid, {})[script_id] = {
        "script": script, "name": name, "source": source,
    }
    return {"script_id": script_id, "name": name}


def op_unload_script(req):
    s = get_session(req)
    sid = str(req["session"])
    script_id = str(need(req, "script_id"))
    ns = named_scripts.get(sid, {})
    sc = ns.pop(script_id, None)
    if sc is None:
        raise ValueError("no script %s in session %s" % (script_id, sid))
    try:
        sc["script"].unload()
    except Exception:
        pass
    return {"unloaded": script_id}


def op_reload_script(req):
    s = get_session(req)
    sid = str(req["session"])
    script_id = str(need(req, "script_id"))
    ns = named_scripts.get(sid, {})
    old = ns.get(script_id)
    if old is None:
        raise ValueError("no script %s in session %s" % (script_id, sid))
    try:
        old["script"].unload()
    except Exception:
        pass
    source = req.get("source") or old["source"]
    name = old.get("name", "")

    def on_message(msg, data):
        if msg.get("type") == "send":
            add_event(sid, {"source": "script", "script_id": script_id, "payload": msg.get("payload")})
        elif msg.get("type") == "error":
            add_error(sid, msg.get("description", "script error"))

    script = create_script(s, source)
    script.on("message", on_message)
    script.load()
    ns[script_id] = {"script": script, "name": name, "source": source}
    return {"reloaded": script_id, "name": name}


def op_script(req):
    s = get_session(req)
    wait = float(req.get("timeout_ms") or 5000) / 1000.0
    msgs = run_js(s, need(req, "source"), wait=wait, keep=bool(req.get("keep")))
    return msgs


# ---------------------------------------------------------------------------
# Hook & Instrumentation
# ---------------------------------------------------------------------------

RESOLVE_JS = """
function resolve(t) {
  if (/^(0x)?[0-9a-f]+$/i.test(t)) return ptr(t.startsWith('0x') ? t : '0x' + t);
  const bang = t.indexOf('!');
  if (bang > 0) return Process.getModuleByName(t.slice(0, bang)).getExportByName(t.slice(bang + 1));
  return Module.getGlobalExportByName(t);
}
"""

HOOK_JS = RESOLVE_JS + """
const target = resolve(%s);
const nargs = %d;
const hookId = %s;
send({ hooked: true, address: target.toString(), hook_id: hookId });
Interceptor.attach(target, {
  onEnter(args) {
    const a = [];
    for (let i = 0; i < nargs; i++) a.push(args[i].toString());
    let caller = null;
    try { caller = DebugSymbol.fromAddress(this.returnAddress).toString(); } catch (e) {}
    send({ hook_id: hookId, event: 'call', thread: this.threadId, args: a, caller, at: Date.now() });
  },
  onLeave(ret) {
    send({ hook_id: hookId, event: 'ret', thread: this.threadId, value: ret.toString(), at: Date.now() });
  }
});
"""

TRACE_JS = RESOLVE_JS + """
const target = resolve(%s);
const nargs = %d;
const max = %d;
let count = 0;
send({ resolved: target.toString() });
Interceptor.attach(target, {
  onEnter(args) {
    this.n = ++count;
    if (count > max) return;
    const a = [];
    for (let i = 0; i < nargs; i++) a.push(args[i].toString());
    let caller = null;
    try { caller = DebugSymbol.fromAddress(this.returnAddress).toString(); } catch (e) {}
    send({ call: this.n, thread: this.threadId, args: a, caller, at: Date.now() });
    if (count === max) send({ note: 'reached max_events' });
  },
  onLeave(ret) {
    if (this.n <= max) send({ ret: this.n, value: ret.toString() });
  }
});
"""


def op_hook(req):
    s = get_session(req)
    sid = str(req["session"])
    target = need(req, "target")
    nargs = int(req.get("args") or 4)
    hook_id = str(next_hook[0])
    next_hook[0] += 1

    def on_message(msg, data):
        if msg.get("type") == "send":
            payload = msg.get("payload")
            if isinstance(payload, dict):
                add_event(sid, payload)
        elif msg.get("type") == "error":
            add_error(sid, msg.get("description", "hook error"))

    script = create_script(s, 
        HOOK_JS % (json.dumps(target), nargs, json.dumps(hook_id))
    )
    script.on("message", on_message)
    script.load()

    active_hooks.setdefault(sid, {})[hook_id] = {
        "script": script, "target": target, "type": "native",
    }
    return {"hook_id": hook_id, "target": target}


def op_unhook(req):
    s = get_session(req)
    sid = str(req["session"])
    hook_id = str(need(req, "hook_id"))
    ah = active_hooks.get(sid, {})
    h = ah.pop(hook_id, None)
    if h is None:
        raise ValueError("no hook %s in session %s" % (hook_id, sid))
    try:
        h["script"].unload()
    except Exception:
        pass
    return {"unhooked": hook_id, "target": h.get("target", "")}


REPLACE_JS = RESOLVE_JS + """
const target = resolve(%s);
const retType = %s;
const paramTypes = %s;
const origPtr = target;
send({ replacing: target.toString() });
Interceptor.replace(target, new NativeCallback(function(%s) {
  %s
}, retType, paramTypes));
"""


def op_replace(req):
    s = get_session(req)
    sid = str(req["session"])
    target = need(req, "target")
    return_type = req.get("return_type") or "int"
    param_types = req.get("param_types") or []
    return_value = req.get("return_value")
    source = req.get("source")
    hook_id = str(next_hook[0])
    next_hook[0] += 1

    param_names = ", ".join("a%d" % i for i in range(len(param_types))) if param_types else ""
    if source:
        body = source
    elif return_value is not None:
        rv = str(return_value)
        if return_type == "pointer":
            body = "return ptr(%s);" % json.dumps(rv)
        elif return_type == "void":
            body = "// replaced with no-op"
        else:
            body = "return %s;" % (int(rv) if rv.lstrip("-").isdigit() else json.dumps(rv))
    else:
        if return_type == "void":
            body = "// replaced with no-op"
        else:
            body = "return 0;"

    js = REPLACE_JS % (
        json.dumps(target),
        json.dumps(return_type),
        json.dumps(param_types),
        param_names,
        body,
    )

    def on_message(msg, data):
        if msg.get("type") == "send":
            add_event(sid, msg.get("payload", {}))
        elif msg.get("type") == "error":
            add_error(sid, msg.get("description", "replace error"))

    script = create_script(s, js)
    script.on("message", on_message)
    script.load()
    active_hooks.setdefault(sid, {})[hook_id] = {
        "script": script, "target": target, "type": "replace",
    }
    return {"hook_id": hook_id, "target": target, "return_type": return_type}


def op_rpc(req):
    s = get_session(req)
    sid = str(req["session"])
    script_id = str(need(req, "script_id"))
    method = need(req, "method")
    args = req.get("args") or []
    ns = named_scripts.get(sid, {})
    sc = ns.get(script_id)
    if sc is None:
        raise ValueError("no script %s in session %s" % (script_id, sid))
    fn = sc["script"].exports_sync
    if not hasattr(fn, method):
        raise ValueError("script %s has no RPC export '%s'" % (script_id, method))
    result = getattr(fn, method)(*args)
    return {"method": method, "result": result}


def op_trace(req):
    s = get_session(req)
    duration = float(req.get("duration_ms") or 5000) / 1000.0
    nargs = int(req.get("args") or 4)
    max_events = int(req.get("max_events") or 200)
    msgs = run_js(s, TRACE_JS % (json.dumps(str(need(req, "target"))), nargs, max_events),
                  wait=duration, max_messages=max_events * 2 + 10)
    return [m.get("payload", m) for m in msgs]


# ---------------------------------------------------------------------------
# Memory Analysis
# ---------------------------------------------------------------------------

MODULES_JS = """
const f = %s;
const out = Process.enumerateModules()
  .filter(m => !f || m.name.toLowerCase().includes(f) || m.path.toLowerCase().includes(f))
  .map(m => ({ name: m.name, base: m.base.toString(), size: m.size, path: m.path }));
send(out); send({ done: true });
"""

EXPORTS_JS = """
const m = Process.getModuleByName(%s);
const f = %s;
const out = m.enumerateExports()
  .filter(e => !f || e.name.toLowerCase().includes(f))
  .map(e => ({ type: e.type, name: e.name, address: e.address.toString() }));
send(out); send({ done: true });
"""

IMPORTS_JS = """
const m = Process.getModuleByName(%s);
const f = %s;
const out = m.enumerateImports()
  .filter(e => !f || e.name.toLowerCase().includes(f))
  .map(e => ({ type: e.type || 'function', name: e.name, module: e.module || '', address: (e.address || ptr(0)).toString() }));
send(out); send({ done: true });
"""

READ_JS = """
const p = ptr(%s);
const n = %d;
send({ address: p.toString() }, p.readByteArray(n)); send({ done: true });
"""

SCAN_JS = """
const pattern = %s;
const protection = %s;
const maxResults = %d;
const results = [];
for (const range of Process.enumerateRanges(protection)) {
  if (results.length >= maxResults) break;
  let matches;
  // A range can be unmapped or guarded between enumeration and scanning
  try { matches = Memory.scanSync(range.base, range.size, pattern); } catch (e) { continue; }
  for (const m of matches) {
    if (results.length >= maxResults) break;
    let sym = null;
    try { sym = DebugSymbol.fromAddress(m.address).toString(); } catch (e) {}
    results.push({ address: m.address.toString(), size: m.size, symbol: sym });
  }
}
send(results); send({ done: true });
"""

WRITE_MEM_JS = """
const addr = ptr(%s);
const bytes = [%s];
const original = [];
for (let i = 0; i < bytes.length; i++) {
  original.push(addr.add(i).readU8());
}
const buf = Memory.alloc(bytes.length);
for (let i = 0; i < bytes.length; i++) {
  buf.add(i).writeU8(bytes[i]);
}
Memory.copy(addr, buf, bytes.length);
send({ address: addr.toString(), written: bytes.length, original_hex: original.map(b => ('0' + b.toString(16)).slice(-2)).join('') });
send({ done: true });
"""

PROTECT_JS = """
const addr = ptr(%s);
const size = %d;
const prot = %s;
Memory.protect(addr, size, prot);
send({ address: addr.toString(), size: size, protection: prot });
send({ done: true });
"""


def op_modules(req):
    s = get_session(req)
    flt = json.dumps((req.get("filter") or "").lower())
    msgs = run_js(s, MODULES_JS % flt)
    return first_payload(msgs)


def op_exports(req):
    s = get_session(req)
    msgs = run_js(s, EXPORTS_JS % (
        json.dumps(need(req, "module")),
        json.dumps((req.get("filter") or "").lower()),
    ))
    return first_payload(msgs)


def op_imports(req):
    s = get_session(req)
    msgs = run_js(s, IMPORTS_JS % (
        json.dumps(need(req, "module")),
        json.dumps((req.get("filter") or "").lower()),
    ))
    return first_payload(msgs)


def op_read(req):
    s = get_session(req)
    length = int(req.get("length") or 256)
    if length < 1:
        raise ValueError('"length" must be at least 1')
    msgs = run_js(s, READ_JS % (json.dumps(str(need(req, "address"))), length))
    for m in msgs:
        if "error" in m:
            raise ValueError(m["error"])
        if "data_hex" in m:
            return {"address": m["payload"]["address"], "length": length, "hex": m["data_hex"]}
    raise ValueError("no data came back")


def op_scan(req):
    s = get_session(req)
    pattern = need(req, "pattern")
    protection = req.get("protection") or "r--"
    max_results = int(req.get("max") or 100)
    msgs = run_js(s, SCAN_JS % (
        json.dumps(pattern), json.dumps(protection), max_results,
    ), wait=30.0)
    return first_payload(msgs)


def op_write_mem(req):
    s = get_session(req)
    sid = str(req["session"])
    address = str(need(req, "address"))
    hex_str = need(req, "hex").strip().replace(" ", "")
    byte_values = ",".join("0x" + hex_str[i:i+2] for i in range(0, len(hex_str), 2))
    msgs = run_js(s, WRITE_MEM_JS % (json.dumps(address), byte_values))
    result = first_payload(msgs)
    if "original_hex" in result:
        memory_patches.setdefault(sid, []).append((address, result["original_hex"]))
    return result


def op_protect(req):
    s = get_session(req)
    address = str(need(req, "address"))
    size = int(need(req, "size"))
    protection = need(req, "protection")
    msgs = run_js(s, PROTECT_JS % (json.dumps(address), size, json.dumps(protection)))
    return first_payload(msgs)


# ---------------------------------------------------------------------------
# Advanced Dynamic Analysis
# ---------------------------------------------------------------------------

THREADS_JS = """
const threads = Process.enumerateThreads();
const out = threads.map(t => ({
  id: t.id,
  state: t.state,
  pc: t.context.pc.toString(),
  sp: t.context.sp.toString(),
}));
send(out); send({ done: true });
"""

REGISTERS_JS = """
const threadId = %d;
const t = Process.enumerateThreads().find(t => t.id === threadId);
if (!t) throw new Error('thread ' + threadId + ' not found (it may have exited; use frida_list_threads for live ids)');
const ctx = t.context;
// CpuContext registers are prototype getters, so Object.keys() sees none of them
const byArch = {
  x64: ['rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp','r8','r9','r10','r11','r12','r13','r14','r15','rip'],
  ia32: ['eax','ebx','ecx','edx','esi','edi','ebp','esp','eip'],
  arm64: Array.from({ length: 29 }, (_, i) => 'x' + i).concat(['fp','lr','sp','pc','nzcv']),
  arm: Array.from({ length: 13 }, (_, i) => 'r' + i).concat(['sp','lr','pc','cpsr']),
};
const names = new Set(byArch[Process.arch] || []);
for (const k in ctx) names.add(k);
names.add('pc'); names.add('sp');
const regs = {};
for (const k of names) {
  let v;
  try { v = ctx[k]; } catch (e) { continue; }
  if (v === undefined || v === null || typeof v === 'function') continue;
  regs[k] = v.toString();
}
if (Object.keys(regs).length === 0) throw new Error('no registers readable for thread ' + threadId + ' on ' + Process.arch);
send({ thread_id: threadId, state: t.state, arch: Process.arch, registers: regs }); send({ done: true });
"""

BACKTRACE_JS = """
const threads = Process.enumerateThreads();
const t = threads.find(t => t.id === %d);
if (!t) throw new Error('thread not found (it may have exited; use frida_list_threads for live ids)');
else {
  const bt = Thread.backtrace(t.context, Backtracer.ACCURATE);
  const frames = bt.map(addr => {
    let sym = null;
    try { sym = DebugSymbol.fromAddress(addr).toString(); } catch(e) {}
    return { address: addr.toString(), symbol: sym };
  });
  send(frames); send({ done: true });
}
"""

STALKER_START_JS = """
const threadId = %d;
const eventTypes = %s;
const maxEvents = %d;
const events = [];
Stalker.follow(threadId, {
  events: {
    call: eventTypes.includes('call'),
    ret: eventTypes.includes('ret'),
    exec: eventTypes.includes('exec'),
    block: eventTypes.includes('block'),
    compile: eventTypes.includes('compile'),
  },
  onReceive: function(rawEvents) {
    const parsed = Stalker.parse(rawEvents, { annotate: true, stringify: true });
    for (const e of parsed) {
      if (events.length >= maxEvents) break;
      events.push(e);
    }
    if (events.length >= maxEvents) {
      Stalker.unfollow(threadId);
      send(events); send({ done: true });
    }
  },
});
setTimeout(function() {
  Stalker.unfollow(threadId);
  send(events); send({ done: true });
}, %d);
"""

STALKER_STOP_JS = """
Stalker.unfollow(%d);
Stalker.garbageCollect();
send({ stopped: true, thread_id: %d });
send({ done: true });
"""


def op_threads(req):
    s = get_session(req)
    msgs = run_js(s, THREADS_JS)
    return first_payload(msgs)


def op_registers(req):
    s = get_session(req)
    thread_id = int(need(req, "thread_id"))
    msgs = run_js(s, REGISTERS_JS % thread_id)
    return first_payload(msgs)


def op_backtrace(req):
    s = get_session(req)
    thread_id = int(need(req, "thread_id"))
    msgs = run_js(s, BACKTRACE_JS % thread_id)
    return first_payload(msgs)


def op_stalker_start(req):
    s = get_session(req)
    thread_id = int(need(req, "thread_id"))
    event_types = req.get("events") or ["call", "ret"]
    max_events = int(req.get("max_events") or 500)
    duration = int(req.get("duration_ms") or 5000)
    msgs = run_js(s, STALKER_START_JS % (
        thread_id, json.dumps(event_types), max_events, duration,
    ), wait=duration / 1000.0 + 2.0, max_messages=max_events + 10)
    return first_payload(msgs)


def op_stalker_stop(req):
    s = get_session(req)
    thread_id = int(need(req, "thread_id"))
    msgs = run_js(s, STALKER_STOP_JS % (thread_id, thread_id))
    return first_payload(msgs)


# ---------------------------------------------------------------------------
# Android Java / JNI
# ---------------------------------------------------------------------------

JAVA_CLASSES_JS = """
Java.perform(function() {
  const f = %s;
  const classes = Java.enumerateLoadedClassesSync();
  const out = classes
    .filter(c => !f || c.toLowerCase().includes(f))
    .slice(0, 2000)
    .map(c => ({ name: c }));
  send(out); send({ done: true });
});
"""

JAVA_METHODS_JS = """
Java.perform(function() {
  const cls = Java.use(%s);
  const methods = cls.class.getDeclaredMethods();
  const out = methods.map(m => ({
    name: m.getName(),
    return_type: m.getReturnType().getName(),
    param_types: m.getParameterTypes().map(p => p.getName()),
    modifiers: m.getModifiers(),
  }));
  send(out); send({ done: true });
});
"""

JAVA_HOOK_JS = """
if (typeof Java === 'undefined') throw new Error('the Java bridge is not loaded in this Frida runtime');
if (!Java.available) throw new Error('no Java runtime in this process (not an Android app)');
Java.perform(function() {
  const cls = Java.use(%s);
  const methodName = %s;
  const hookId = %s;
  if (!cls[methodName] || !cls[methodName].overloads) throw new Error('method not found: ' + methodName);
  const overloads = cls[methodName].overloads;
  overloads.forEach(function(overload) {
    overload.implementation = function() {
      const args = [];
      for (let i = 0; i < arguments.length; i++) {
        try { args.push(String(arguments[i])); } catch(e) { args.push('<error>'); }
      }
      send({ hook_id: hookId, event: 'call', method: methodName, args: args, at: Date.now() });
      const ret = overload.apply(this, arguments);
      let retStr = null;
      try { retStr = String(ret); } catch(e) { retStr = '<error>'; }
      send({ hook_id: hookId, event: 'ret', method: methodName, value: retStr, at: Date.now() });
      return ret;
    };
  });
  send({ hooked: true, hook_id: hookId, class: %s, method: methodName, overloads: overloads.length });
});
"""

JAVA_INSTANCES_JS = """
Java.perform(function() {
  const className = %s;
  const instances = [];
  Java.choose(className, {
    onMatch: function(instance) {
      let desc = '<instance>';
      try { desc = instance.toString(); } catch(e) {}
      instances.push({ class: className, description: desc });
      if (instances.length >= 100) return 'stop';
    },
    onComplete: function() {
      send(instances); send({ done: true });
    }
  });
});
"""

JNI_TRACE_JS = """
const f = %s;
const maxEvents = %d;
let count = 0;
// JNI functions are not exported by libart; they are reached through the JNIEnv
// function table, whose slots are fixed by the JNI specification.
const slots = {
  FindClass: 6, ExceptionDescribe: 16, ExceptionClear: 17, NewGlobalRef: 21, DeleteGlobalRef: 22,
  DeleteLocalRef: 23, NewLocalRef: 25, GetMethodID: 33, CallObjectMethod: 34, CallBooleanMethod: 37,
  CallIntMethod: 49, CallVoidMethod: 61, GetFieldID: 94, GetStaticMethodID: 113, GetStaticFieldID: 144,
  NewStringUTF: 167, GetStringUTFChars: 169, RegisterNatives: 215, ExceptionCheck: 228,
};
const str = p => { try { return p.isNull() ? null : p.readCString(); } catch (e) { return null; } };
const describe = {
  FindClass: a => ({ name: str(a[1]) }),
  GetMethodID: a => ({ name: str(a[2]), sig: str(a[3]) }),
  GetStaticMethodID: a => ({ name: str(a[2]), sig: str(a[3]) }),
  GetFieldID: a => ({ name: str(a[2]), sig: str(a[3]) }),
  GetStaticFieldID: a => ({ name: str(a[2]), sig: str(a[3]) }),
  NewStringUTF: a => ({ value: str(a[1]) }),
  RegisterNatives: a => {
    const n = a[3].toInt32();
    const methods = [];
    for (let i = 0; i < Math.min(n, 50); i++) {
      const m = a[2].add(i * 3 * Process.pointerSize);
      methods.push({ name: str(m.readPointer()), sig: str(m.add(Process.pointerSize).readPointer()),
        fn: m.add(2 * Process.pointerSize).readPointer().toString() });
    }
    return { count: n, methods: methods };
  },
};
const emit = (name, thread, extra) => {
  if (++count > maxEvents) return;
  send(Object.assign({ event: 'jni', function: name, thread: thread, at: Date.now() }, extra));
};
if (typeof Java === 'undefined' || !Java.available) throw new Error('no Java runtime in this process (not an Android app)');
const env = Java.vm.getEnv();
const table = env.handle.readPointer();
const hooked = [];
for (const name of Object.keys(slots)) {
  if (f && !name.toLowerCase().includes(f.toLowerCase())) continue;
  const target = table.add(slots[name] * Process.pointerSize).readPointer();
  const d = describe[name];
  const callbacks = {
    onEnter: function (args) {
      if (name === 'GetStringUTFChars') return;
      let extra = {};
      if (d) { try { extra = d(args); } catch (e) {} }
      emit(name, this.threadId, extra);
    },
  };
  if (name === 'GetStringUTFChars') {
    callbacks.onLeave = function (ret) { emit(name, this.threadId, { value: str(ret) }); };
  }
  Interceptor.attach(target, callbacks);
  hooked.push(name);
}
if (hooked.length === 0) throw new Error('no JNI function matches filter: ' + f);
send({ tracing: true, filter: f || 'all', functions: hooked });
"""


def op_java_classes(req):
    s = get_session(req)
    flt = json.dumps((req.get("filter") or "").lower())
    msgs = run_js(s, JAVA_CLASSES_JS % flt, wait=10.0)
    return first_payload(msgs)


def op_java_methods(req):
    s = get_session(req)
    class_name = need(req, "class_name")
    msgs = run_js(s, JAVA_METHODS_JS % json.dumps(class_name), wait=10.0)
    return first_payload(msgs)


def load_confirmed_hook(s, sid, source, kind, target, wait=10.0):
    """Load a persistent hook script and return only once it reports {"hooked": true};
    a script error before that unloads it and raises instead of handing out a hook id."""
    confirmed = threading.Event()
    outcome = {}

    def on_message(msg, data):
        if msg.get("type") == "send":
            payload = msg.get("payload")
            if not isinstance(payload, dict):
                return
            if payload.get("hooked") and not confirmed.is_set():
                outcome["info"] = payload
                confirmed.set()
                return
            add_event(sid, payload)
        elif msg.get("type") == "error":
            description = msg.get("description", "%s hook error" % kind)
            if not confirmed.is_set():
                outcome["error"] = description
                confirmed.set()
            else:
                add_error(sid, description)

    script = create_script(s, source)
    script.on("message", on_message)
    script.load()
    confirmed.wait(wait)
    if "info" not in outcome:
        try:
            script.unload()
        except Exception:
            pass
        raise ValueError(outcome.get("error") or "%s hook was not confirmed within %ds" % (kind, wait))
    hook_id = str(next_hook[0])
    next_hook[0] += 1
    active_hooks.setdefault(sid, {})[hook_id] = {"script": script, "target": target, "type": kind}
    return hook_id, outcome["info"]


def op_java_hook(req):
    s = get_session(req)
    sid = str(req["session"])
    class_name = need(req, "class_name")
    method = need(req, "method")
    hook_id = str(next_hook[0])
    source = JAVA_HOOK_JS % (json.dumps(class_name), json.dumps(method), json.dumps(hook_id), json.dumps(class_name))
    hook_id, info = load_confirmed_hook(s, sid, source, "java", "%s.%s" % (class_name, method))
    return {"hook_id": hook_id, "class": class_name, "method": method, "overloads": info.get("overloads")}


def op_java_instances(req):
    s = get_session(req)
    class_name = need(req, "class_name")
    msgs = run_js(s, JAVA_INSTANCES_JS % json.dumps(class_name), wait=15.0)
    return first_payload(msgs)


def op_jni_trace(req):
    s = get_session(req)
    flt = req.get("filter") or ""
    max_events = int(req.get("max_events") or 200)
    duration = float(req.get("duration_ms") or 5000) / 1000.0
    msgs = run_js(s, JNI_TRACE_JS % (json.dumps(flt), max_events),
                  wait=duration, max_messages=max_events + 10)
    if msgs and "error" in msgs[0]:
        raise ValueError(msgs[0]["error"])
    return [m.get("payload", m) for m in msgs]


# ---------------------------------------------------------------------------
# iOS / macOS (Objective-C & Swift)
# ---------------------------------------------------------------------------

OBJC_CLASSES_JS = """
const f = %s;
const classes = ObjC.enumerateLoadedClassesSync();
const flat = Object.values(classes).flat();
const out = flat
  .filter(c => !f || c.toLowerCase().includes(f))
  .slice(0, 2000)
  .map(c => ({ name: c }));
send(out); send({ done: true });
"""

OBJC_HOOK_JS = """
const className = %s;
const selector = %s;
const hookId = %s;
if (typeof ObjC === 'undefined') throw new Error('the Objective-C bridge is not loaded in this Frida runtime');
if (!ObjC.available) throw new Error('no Objective-C runtime in this process (not an iOS/macOS app)');
const cls = ObjC.classes[className];
if (!cls) throw new Error('class not found: ' + className);
{
  const method = cls[selector];
  if (!method) throw new Error('method not found: ' + selector);
  {
    Interceptor.attach(method.implementation, {
      onEnter: function(args) {
        const nargs = method.argumentTypes ? method.argumentTypes.length : 2;
        const a = [];
        for (let i = 2; i < nargs; i++) {
          try { a.push(new ObjC.Object(args[i]).toString()); } catch(e) { a.push(args[i].toString()); }
        }
        send({ hook_id: hookId, event: 'call', class: className, method: selector, args: a, at: Date.now() });
      },
      onLeave: function(ret) {
        let v = null;
        try { v = new ObjC.Object(ret).toString(); } catch(e) { v = ret.toString(); }
        send({ hook_id: hookId, event: 'ret', class: className, method: selector, value: v, at: Date.now() });
      }
    });
    send({ hooked: true, hook_id: hookId, class: className, method: selector });
  }
}
"""

SWIFT_SYMBOLS_JS = """
const modName = %s;
const f = %s;
let symbols = [];
if (modName) {
  const mod = Process.getModuleByName(modName);
  symbols = mod.enumerateExports().concat(mod.enumerateSymbols ? mod.enumerateSymbols() : []);
} else {
  Process.enumerateModules().forEach(m => {
    symbols = symbols.concat(m.enumerateExports());
  });
}
const out = symbols
  .filter(s => s.name && s.name.includes('$s'))
  .filter(s => !f || s.name.toLowerCase().includes(f))
  .slice(0, 2000)
  .map(s => {
    let demangled = s.name;
    try { demangled = DebugSymbol.fromAddress(s.address).name || s.name; } catch(e) {}
    return { name: s.name, demangled: demangled, address: s.address.toString(), type: s.type || 'unknown' };
  });
send(out); send({ done: true });
"""


def op_objc_classes(req):
    s = get_session(req)
    flt = json.dumps((req.get("filter") or "").lower())
    msgs = run_js(s, OBJC_CLASSES_JS % flt, wait=10.0)
    return first_payload(msgs)


def op_objc_hook(req):
    s = get_session(req)
    sid = str(req["session"])
    class_name = need(req, "class_name")
    method = need(req, "method")
    hook_id = str(next_hook[0])
    source = OBJC_HOOK_JS % (json.dumps(class_name), json.dumps(method), json.dumps(hook_id))
    hook_id, _ = load_confirmed_hook(s, sid, source, "objc", "%s %s" % (class_name, method))
    return {"hook_id": hook_id, "class": class_name, "method": method}


def op_swift_symbols(req):
    s = get_session(req)
    module = req.get("module") or ""
    flt = (req.get("filter") or "").lower()
    msgs = run_js(s, SWIFT_SYMBOLS_JS % (
        json.dumps(module) if module else "null",
        json.dumps(flt),
    ), wait=15.0)
    return first_payload(msgs)


# ---------------------------------------------------------------------------
# Monitoring & Logging
# ---------------------------------------------------------------------------

def op_get_events(req):
    s = get_session(req)
    sid = str(req["session"])
    buf = event_buffers.get(sid, [])
    since = req.get("since")
    limit = int(req.get("limit") or 200)
    if since:
        try:
            ts = float(since)
            buf = [e for e in buf if e.get("_ts", 0) > ts]
        except (ValueError, TypeError):
            pass
    result = buf[:limit]
    if req.get("clear"):
        event_buffers[sid] = buf[limit:]
    return {"events": result, "total_buffered": len(event_buffers.get(sid, []))}


def op_subscribe_events(req):
    s = get_session(req)
    sid = str(req["session"])
    timeout = float(req.get("timeout_ms") or 5000) / 1000.0
    event_limit = int(req.get("event_limit") or 100)
    clear = req.get("clear", True)
    deadline = time.time() + timeout
    while time.time() < deadline:
        buf = event_buffers.get(sid, [])
        if buf:
            result = buf[:event_limit]
            if clear:
                event_buffers[sid] = buf[event_limit:]
            return {"events": result, "total_buffered": len(event_buffers.get(sid, []))}
        time.sleep(0.1)
    return {"events": [], "total_buffered": 0, "timed_out": True}


def op_export_trace(req):
    s = get_session(req)
    sid = str(req["session"])
    buf = event_buffers.get(sid, [])
    output_path = req.get("output_path")
    lines = [json.dumps(e) for e in buf]
    if output_path:
        with open(output_path, "w") as f:
            f.write("\n".join(lines) + "\n")
        return {"exported": len(buf), "path": output_path}
    return {"exported": len(buf), "data": lines}


def op_get_errors(req):
    s = get_session(req)
    sid = str(req["session"])
    buf = error_buffers.get(sid, [])
    result = list(buf)
    if req.get("clear"):
        error_buffers[sid] = []
    return {"errors": result, "count": len(result)}


def op_cleanup(req):
    """Close all sessions, restore memory, remove hooks/scripts."""
    cleaned = {"sessions": 0, "hooks": 0, "scripts": 0, "patches_restored": 0}
    for sid in list(sessions.keys()):
        s = sessions.get(sid)
        if s:
            patches = memory_patches.get(sid, [])
            for addr, orig_hex in reversed(patches):
                try:
                    byte_values = ",".join("0x" + orig_hex[i:i+2] for i in range(0, len(orig_hex), 2))
                    run_js(s, WRITE_MEM_JS % (json.dumps(addr), byte_values), wait=2.0)
                    cleaned["patches_restored"] += 1
                except Exception:
                    pass
            cleaned["hooks"] += len(active_hooks.get(sid, {}))
            cleaned["scripts"] += len(named_scripts.get(sid, {})) + len(s.get("scripts", []))
            _cleanup_session(sid)
            cleaned["sessions"] += 1
    return cleaned


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

OPS = {
    # Device & Process
    "devices": op_devices,
    "device_info": op_device_info,
    "connect_device": op_connect_device,
    "server_status": op_server_status,
    "processes": op_processes,
    "applications": op_applications,
    # Session & Process Control
    "attach": op_attach,
    "spawn": op_spawn,
    "resume": op_resume,
    "kill": op_kill,
    "sessions": op_sessions,
    "session_status": op_session_status,
    "detach": op_detach,
    # Script Management
    "script": op_script,
    "load_script": op_load_script,
    "unload_script": op_unload_script,
    "reload_script": op_reload_script,
    # Hook & Instrumentation
    "hook": op_hook,
    "unhook": op_unhook,
    "replace": op_replace,
    "rpc": op_rpc,
    "trace": op_trace,
    # Memory
    "modules": op_modules,
    "exports": op_exports,
    "imports": op_imports,
    "read": op_read,
    "scan": op_scan,
    "write_mem": op_write_mem,
    "protect": op_protect,
    # Advanced
    "threads": op_threads,
    "registers": op_registers,
    "backtrace": op_backtrace,
    "stalker_start": op_stalker_start,
    "stalker_stop": op_stalker_stop,
    # Java / JNI
    "java_classes": op_java_classes,
    "java_methods": op_java_methods,
    "java_hook": op_java_hook,
    "java_instances": op_java_instances,
    "jni_trace": op_jni_trace,
    # iOS / macOS
    "objc_classes": op_objc_classes,
    "objc_hook": op_objc_hook,
    "swift_symbols": op_swift_symbols,
    # Monitoring
    "get_events": op_get_events,
    "subscribe_events": op_subscribe_events,
    "export_trace": op_export_trace,
    "get_errors": op_get_errors,
    "cleanup": op_cleanup,
    # Internal
    "ping": lambda req: {"frida": frida.__version__},
}


def handle(line):
    try:
        req = json.loads(line)
    except Exception:
        return
    rid = req.get("id")
    try:
        fn = OPS.get(req.get("op"))
        if fn is None:
            raise ValueError("unknown op %s" % req.get("op"))
        reply({"id": rid, "ok": True, "result": fn(req)})
    except Exception as e:
        reply({"id": rid, "ok": False, "error": "%s: %s" % (type(e).__name__, e)})


def main():
    for line in sys.stdin:
        line = line.strip()
        if line:
            threading.Thread(target=handle, args=(line,), daemon=True).start()
    # Cleanup on exit
    for sid in list(sessions.keys()):
        _cleanup_session(sid)


if __name__ == "__main__":
    main()
