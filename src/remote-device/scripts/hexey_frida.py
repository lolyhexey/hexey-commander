"""Frida helper for the remote device.

One long-running process per device. Reads one JSON request per line on stdin
and writes one JSON response per line on stdout:

    {"id": 1, "op": "attach", "target": "notepad.exe"}
    {"id": 1, "ok": true, "result": {...}}  or  {"id": 1, "ok": false, "error": "..."}

Sessions stay open between requests until detached or the helper exits.
"""
import json
import sys
import threading
import time
import traceback

import frida

device = frida.get_local_device()
sessions = {}  # session id -> {"session", "pid", "name", "spawned", "scripts": [...]}
next_session = [1]
out_lock = threading.Lock()


def reply(obj):
    with out_lock:
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()


def need(req, key):
    if key not in req or req[key] in (None, ""):
        raise ValueError('"%s" is required' % key)
    return req[key]


def get_session(req):
    sid = str(need(req, "session"))
    s = sessions.get(sid)
    if s is None:
        raise ValueError("no session %s (open sessions: %s)" % (sid, ", ".join(sessions) or "none"))
    if s["session"].is_detached:
        sessions.pop(sid, None)
        raise ValueError("session %s ended (the process exited or was detached)" % sid)
    return s


def add_session(session, pid, name, spawned):
    sid = str(next_session[0])
    next_session[0] += 1
    sessions[sid] = {"session": session, "pid": pid, "name": name, "spawned": spawned, "scripts": []}
    return sid


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

    script = s["session"].create_script(source)
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


def op_processes(req):
    flt = (req.get("filter") or "").lower()
    out = []
    for p in device.enumerate_processes():
        if flt and flt not in p.name.lower() and flt != str(p.pid):
            continue
        out.append({"pid": p.pid, "name": p.name})
    out.sort(key=lambda p: p["pid"])
    return out


def op_attach(req):
    target = need(req, "target")
    pid = int(target) if str(target).isdigit() else None
    if pid is None:
        matches = [p for p in device.enumerate_processes() if p.name.lower() == str(target).lower()]
        if not matches:
            raise ValueError("no running process named %s" % target)
        if len(matches) > 1:
            raise ValueError("%d processes are named %s; attach by pid: %s" % (len(matches), target, ", ".join(str(p.pid) for p in matches)))
        pid, name = matches[0].pid, matches[0].name
    else:
        name = next((p.name for p in device.enumerate_processes() if p.pid == pid), str(pid))
    session = device.attach(pid)
    sid = add_session(session, pid, name, False)
    return {"session": sid, "pid": pid, "name": name}


def op_spawn(req):
    program = need(req, "program")
    argv = [program] + [str(a) for a in (req.get("args") or [])]
    pid = device.spawn(argv)
    session = device.attach(pid)
    sid = add_session(session, pid, program, True)
    if not req.get("suspended"):
        device.resume(pid)
    return {"session": sid, "pid": pid, "suspended": bool(req.get("suspended"))}


def op_resume(req):
    s = get_session(req)
    device.resume(s["pid"])
    return {"resumed": s["pid"]}


def op_sessions(req):
    out = []
    for sid, s in list(sessions.items()):
        out.append({"session": sid, "pid": s["pid"], "name": s["name"], "spawned": s["spawned"],
                    "detached": s["session"].is_detached, "scripts": len(s["scripts"])})
    return out


def op_detach(req):
    sid = str(need(req, "session"))
    s = sessions.pop(sid, None)
    if s is None:
        raise ValueError("no session %s" % sid)
    for sc in s["scripts"]:
        try:
            sc.unload()
        except Exception:
            pass
    if not s["session"].is_detached:
        s["session"].detach()
    if req.get("kill") and s["spawned"]:
        try:
            device.kill(s["pid"])
        except Exception:
            pass
    return {"detached": sid, "pid": s["pid"]}


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

READ_JS = """
const p = ptr(%s);
const n = %d;
send({ address: p.toString() }, p.readByteArray(n)); send({ done: true });
"""

RESOLVE_JS = """
function resolve(t) {
  if (/^(0x)?[0-9a-f]+$/i.test(t)) return ptr(t.startsWith('0x') ? t : '0x' + t);
  const bang = t.indexOf('!');
  if (bang > 0) return Process.getModuleByName(t.slice(0, bang)).getExportByName(t.slice(bang + 1));
  return Module.getGlobalExportByName(t);
}
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


def op_modules(req):
    s = get_session(req)
    flt = json.dumps((req.get("filter") or "").lower())
    msgs = run_js(s, MODULES_JS % flt)
    return first_payload(msgs)


def op_exports(req):
    s = get_session(req)
    msgs = run_js(s, EXPORTS_JS % (json.dumps(need(req, "module")), json.dumps((req.get("filter") or "").lower())))
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


def op_trace(req):
    s = get_session(req)
    duration = float(req.get("duration_ms") or 5000) / 1000.0
    nargs = int(req.get("args") or 4)
    max_events = int(req.get("max_events") or 200)
    msgs = run_js(s, TRACE_JS % (json.dumps(str(need(req, "target"))), nargs, max_events), wait=duration, max_messages=max_events * 2 + 10)
    return [m.get("payload", m) for m in msgs]


def op_script(req):
    s = get_session(req)
    wait = float(req.get("timeout_ms") or 5000) / 1000.0
    msgs = run_js(s, need(req, "source"), wait=wait, keep=bool(req.get("keep")))
    return msgs


def first_payload(msgs):
    for m in msgs:
        if "error" in m:
            raise ValueError(m["error"])
        if "payload" in m:
            return m["payload"]
    raise ValueError("no answer from the script")


OPS = {
    "processes": op_processes, "attach": op_attach, "spawn": op_spawn, "resume": op_resume,
    "sessions": op_sessions, "detach": op_detach, "modules": op_modules, "exports": op_exports,
    "read": op_read, "trace": op_trace, "script": op_script,
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
    # Requests may take seconds (traces); run each on its own thread so
    # detach or a quick read is not stuck behind a long trace.
    for line in sys.stdin:
        line = line.strip()
        if line:
            threading.Thread(target=handle, args=(line,), daemon=True).start()
    for s in list(sessions.values()):
        try:
            s["session"].detach()
        except Exception:
            pass


if __name__ == "__main__":
    main()
