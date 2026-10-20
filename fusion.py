#!/usr/bin/env python3
"""Command-line client for the Autodesk Fusion MCP server (standard library only).

Talks JSON-RPC to Fusion's local MCP server (default: http://127.0.0.1:27182/mcp).
Read commands are unrestricted. Write commands (run, exec, undo, redo, save, open, close, raw)
must pass these gates:
  1. --write (or FUSION_ALLOW_WRITE=1)
  2. --doc "<name>" (or FUSION_EXPECT_DOC): aborts if the active document has a different name
  3. No command or dialog may be open in Fusion
  4. Interactive confirmation (or --yes)
  5. Static analysis (lint) of scripts: dangerous calls are blocked
Write attempts are recorded in <state dir>/audit.jsonl.
Note: the lint is a safety net against accidents, not a security boundary.
Never run a script you do not trust.
"""
from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import json
import os
import sys
import textwrap
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_URL = os.environ.get("FUSION_MCP_URL", "http://127.0.0.1:27182/mcp")
STATE_DIR = Path(os.environ.get("FUSION_MCP_STATE_DIR", Path.home() / ".fusion-mcp")).expanduser()
AUDIT_FILE = STATE_DIR / "audit.jsonl"
SHOTS_DIR = STATE_DIR / "shots"
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
MAX_SCRIPT_BYTES = 200_000
MAX_RESPONSE_BYTES = 50_000_000
READ_TOOLS = {"fusion_mcp_read", "fusion_mcp_electronics_read"}

ORIENTATIONS = {
    "front": "FrontViewOrientation",
    "back": "BackViewOrientation",
    "top": "TopViewOrientation",
    "bottom": "BottomViewOrientation",
    "left": "LeftViewOrientation",
    "right": "RightViewOrientation",
    "iso-top-left": "IsoTopLeftViewOrientation",
    "iso-top-right": "IsoTopRightViewOrientation",
    "iso-bottom-left": "IsoBottomLeftViewOrientation",
    "iso-bottom-right": "IsoBottomRightViewOrientation",
}


class FusionError(Exception):
    pass


# --------------------------------------------------------------------------- HTTP / MCP client


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # never follow redirects
        return None


class Client:
    def __init__(self, url: str, timeout: float):
        self.url, self.timeout = url, timeout
        self.sid: str | None = None
        self._id = 0
        # Environment proxies are disabled so requests only reach the configured server.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)

    def _post(self, body: dict, timeout: float | None = None):
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if self.sid:
            headers["MCP-Session-Id"] = self.sid
        req = urllib.request.Request(self.url, data=json.dumps(body).encode(), headers=headers, method="POST")
        try:
            with self.opener.open(req, timeout=timeout or self.timeout) as r:
                raw = r.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise FusionError("Response too large; aborted.")
                self.sid = self.sid or r.headers.get("MCP-Session-Id")
                ctype = r.headers.get("Content-Type", "")
        except urllib.error.HTTPError as e:
            raise FusionError(f"Server returned HTTP {e.code}.") from e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise FusionError(
                f"Could not reach the server ({self.url}): {e}. Is Fusion running with the MCP server enabled?"
            ) from e
        text = raw.decode("utf-8", "replace").strip()
        if not text:
            return None
        if "event-stream" in ctype:
            data = [ln[5:].strip() for ln in text.splitlines() if ln.startswith("data:")]
            text = data[-1] if data else ""
        return json.loads(text) if text else None

    def rpc(self, method: str, params: dict | None = None):
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        resp = self._post(msg)
        if resp is None:
            raise FusionError(f"'{method}' returned an empty response.")
        if "error" in resp:
            raise FusionError(f"MCP error: {resp['error'].get('message', resp['error'])}")
        return resp.get("result", {})

    def initialize(self):
        info = self.rpc(
            "initialize",
            {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "fusion.py", "version": "1"}},
        )
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return info

    def call(self, tool: str, arguments: dict):
        res = self.rpc("tools/call", {"name": tool, "arguments": arguments})
        texts = [c.get("text", "") for c in res.get("content", []) if c.get("type") == "text"]
        images = [c for c in res.get("content", []) if c.get("type") == "image"]
        if res.get("isError"):
            raise FusionError("Tool error: " + ("\n".join(texts) or "unknown"))
        return texts, images

    def read(self, args: dict):
        texts, _ = self.call("fusion_mcp_read", args)
        return _maybe_json("\n".join(texts))

    def close(self):
        if not self.sid:
            return
        try:  # best effort: close the session
            req = urllib.request.Request(self.url, headers={"MCP-Session-Id": self.sid}, method="DELETE")
            self.opener.open(req, timeout=2).close()
        except Exception:
            pass


def _maybe_json(text: str):
    try:
        return json.loads(text)
    except ValueError:
        return text


@contextmanager
def session(args):
    check_url(args.url)
    c = Client(args.url, args.timeout)
    c.initialize()
    try:
        yield c
    finally:
        c.close()


def check_url(url: str):
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise FusionError(f"Invalid URL: {url}")
    if p.hostname not in LOCAL_HOSTS and os.environ.get("FUSION_MCP_ALLOW_REMOTE") != "1":
        raise FusionError(
            f"'{p.hostname}' is not a local host. Scripts run in Fusion with full privileges; "
            "set FUSION_MCP_ALLOW_REMOTE=1 to use a remote server."
        )


# --------------------------------------------------------------------------- Script static analysis (lint)

UNSAFE_IMPORTS = {
    "os", "sys", "subprocess", "shutil", "socket", "ssl", "urllib", "http", "requests", "ftplib", "smtplib",
    "ctypes", "importlib", "builtins", "pickle", "marshal", "multiprocessing", "threading", "webbrowser",
    "tempfile", "glob", "zipfile", "tarfile", "sqlite3", "pathlib", "signal", "pty", "code", "runpy",
}
UNSAFE_CALLS = {"eval", "exec", "compile", "open", "__import__", "input", "breakpoint", "globals", "vars"}
UNSAFE_ATTRS = {"system", "popen", "startfile", "executeTextCommand", "fireCustomEvent"}
SANDBOX_ESCAPE = {"__builtins__", "__class__", "__subclasses__", "__globals__", "__bases__", "__mro__"}
DESTRUCTIVE_ATTRS = {
    "deleteMe", "deleteAll", "deleteAllTimelineItems", "save", "saveAs", "saveCopy", "close", "exportManager",
}


def lint(source: str) -> dict:
    rep = {"errors": [], "destructive": [], "warnings": []}
    if len(source.encode()) > MAX_SCRIPT_BYTES:
        rep["errors"].append(f"Script exceeds the {MAX_SCRIPT_BYTES // 1000} KB limit.")
        return rep
    if "\x00" in source:
        rep["errors"].append("Script contains a NUL character.")
        return rep
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        rep["errors"].append(f"Syntax error: line {e.lineno}: {e.msg}")
        return rep
    has_run = False
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "run" and len(node.args.args) >= 1:
            has_run = True
    if not has_run:
        rep["errors"].append("Missing `def run(_context: str):` entry point.")
    for node in ast.walk(tree):
        line = getattr(node, "lineno", "?")
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] in UNSAFE_IMPORTS:
                    rep["errors"].append(f"line {line}: forbidden import '{a.name}'")
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in UNSAFE_IMPORTS:
                rep["errors"].append(f"line {line}: forbidden import '{node.module}'")
        elif isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name) and f.id in UNSAFE_CALLS:
                rep["errors"].append(f"line {line}: forbidden call '{f.id}()'")
            if isinstance(f, ast.Name) and f.id in ("getattr", "setattr", "delattr", "hasattr"):
                if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                    name = str(node.args[1].value)
                    if name in UNSAFE_ATTRS or name in SANDBOX_ESCAPE:
                        rep["errors"].append(f"line {line}: indirect access via {f.id}(..., '{name}')")
                    elif name in DESTRUCTIVE_ATTRS:
                        rep["destructive"].append(f"line {line}: {f.id}(..., '{name}')")
        elif isinstance(node, ast.Attribute):
            if node.attr in UNSAFE_ATTRS or node.attr in SANDBOX_ESCAPE:
                rep["errors"].append(f"line {line}: forbidden attribute access '.{node.attr}'")
            elif node.attr in DESTRUCTIVE_ATTRS:
                rep["destructive"].append(f"line {line}: '.{node.attr}' may be permanent or irreversible")
        elif isinstance(node, ast.Name) and node.id in SANDBOX_ESCAPE:
            rep["errors"].append(f"line {line}: forbidden name '{node.id}'")
    if "deleteMe" not in source and ("delete" in source.lower()):
        rep["warnings"].append("The source mentions 'delete'; check what is being deleted.")
    return rep


def print_lint(rep: dict):
    for k, title in (("errors", "ERROR"), ("destructive", "DESTRUCTIVE"), ("warnings", "WARNING")):
        for m in rep[k]:
            print(f"  [{title}] {m}", file=sys.stderr)


# --------------------------------------------------------------------------- Built-in (read-only) scripts

_HEAD = "import adsk.core, adsk.fusion\n\n"
_DES = (
    "    app = adsk.core.Application.get()\n"
    "    des = adsk.fusion.Design.cast(app.activeProduct)\n"
    "    if not des:\n"
    "        print('Active product is not a Design.')\n"
    "        return\n"
    "    root = des.rootComponent\n"
)

SNIPPETS: dict[str, tuple[str, str]] = {
    "info": (
        "Fusion version, document, units, up axis, counts",
        _HEAD
        + "def run(_context: str):\n"
        "    app = adsk.core.Application.get()\n"
        "    print('Fusion', app.version)\n"
        "    print('Document:', app.activeDocument.name)\n"
        "    des = adsk.fusion.Design.cast(app.activeProduct)\n"
        "    if not des:\n"
        "        print('Active product is not a Design:', app.activeProduct.productType)\n"
        "        return\n"
        "    parametric = des.designType == adsk.fusion.DesignTypes.ParametricDesignType\n"
        "    print('Design type:', 'Parametric (has timeline)' if parametric else 'Direct')\n"
        "    print('Length unit:', des.unitsManager.defaultLengthUnits)\n"
        "    z_up = app.preferences.generalPreferences.defaultModelingOrientation == 1\n"
        "    print('Up axis:', 'Z up' if z_up else 'Y up')\n"
        "    root = des.rootComponent\n"
        "    print('Occurrences (all):', root.allOccurrences.count)\n"
        "    print('Bodies (root):', root.bRepBodies.count)\n"
        "    print('User parameters:', des.userParameters.count)\n",
    ),
    "tree": (
        "Component/occurrence tree (body counts and visibility)",
        _HEAD
        + "def walk(occs, depth):\n"
        "    for o in occs:\n"
        "        c = o.component\n"
        "        print('  ' * depth + '- %s  [%s]  bodies=%d  visible=%s' % (o.name, c.name, c.bRepBodies.count, o.isLightBulbOn))\n"
        "        walk(o.childOccurrences, depth + 1)\n\n"
        "def run(_context: str):\n" + _DES + "    print('(root) %s  bodies=%d' % (root.name, root.bRepBodies.count))\n"
        "    for b in root.bRepBodies:\n"
        "        print('  * ' + b.name)\n"
        "    walk(root.occurrences, 1)\n",
    ),
    "bodies": (
        "All bodies: size (mm), min corner, volume (mm3)",
        _HEAD
        + "def show(b, owner):\n"
        "    bb = b.boundingBox\n"
        "    mn, mx = bb.minPoint, bb.maxPoint\n"
        "    size = [round((mx.x - mn.x) * 10, 2), round((mx.y - mn.y) * 10, 2), round((mx.z - mn.z) * 10, 2)]\n"
        "    print('%s / %s  size(mm)=%s  min(mm)=(%.1f, %.1f, %.1f)  volume=%.0f mm3' % (owner, b.name, size, mn.x * 10, mn.y * 10, mn.z * 10, b.volume * 1000))\n\n"
        "def run(_context: str):\n" + _DES + "    for b in root.bRepBodies:\n"
        "        show(b, '(root)')\n"
        "    for o in root.allOccurrences:\n"
        "        for b in o.bRepBodies:\n"
        "            show(b, o.fullPathName)\n",
    ),
    "params": (
        "User parameters",
        _HEAD
        + "def run(_context: str):\n" + _DES + "    if des.userParameters.count == 0:\n"
        "        print('No user parameters.')\n"
        "    for p in des.userParameters:\n"
        "        print('%s = %s  (%s)  %s' % (p.name, p.expression, p.unit, p.comment))\n",
    ),
    "timeline": (
        "Timeline entries (parametric designs)",
        _HEAD
        + "def run(_context: str):\n" + _DES + "    if des.designType != adsk.fusion.DesignTypes.ParametricDesignType:\n"
        "        print('Direct modeling: no timeline.')\n"
        "        return\n"
        "    tl = des.timeline\n"
        "    print('Marker: %d / %d' % (tl.markerPosition, tl.count))\n"
        "    for i in range(tl.count):\n"
        "        it = tl.item(i)\n"
        "        try:\n"
        "            kind = it.entity.objectType.split('::')[-1]\n"
        "        except Exception:\n"
        "            kind = '?'\n"
        "        print('%3d  %s  [%s]%s' % (i, it.name, kind, '  (suppressed)' if it.isSuppressed else ''))\n",
    ),
    "props": (
        "Root component physical properties (mass, volume, center of mass)",
        _HEAD
        + "def run(_context: str):\n" + _DES + "    pp = root.physicalProperties\n"
        "    com = pp.centerOfMass\n"
        "    print('Mass: %.3f kg (depends on material)' % pp.mass)\n"
        "    print('Volume: %.0f mm3' % (pp.volume * 1000))\n"
        "    print('Area: %.0f mm2' % (pp.area * 100))\n"
        "    print('Center of mass (mm): (%.1f, %.1f, %.1f)' % (com.x * 10, com.y * 10, com.z * 10))\n",
    ),
    "interference": (
        "Interference check between root occurrences",
        _HEAD
        + "def run(_context: str):\n" + _DES + "    col = adsk.core.ObjectCollection.create()\n"
        "    for o in root.occurrences:\n"
        "        col.add(o)\n"
        "    if col.count < 2:\n"
        "        print('Need at least 2 occurrences.')\n"
        "        return\n"
        "    res = des.analyzeInterference(des.createInterferenceInput(col))\n"
        "    print('Interference count:', res.count)\n"
        "    def owner(e):\n"
        "        ctx = getattr(e, 'assemblyContext', None)\n"
        "        return ctx.name if ctx else e.parentComponent.name\n"
        "    for r in res:\n"
        "        print('%s x %s  %.2f mm3' % (owner(r.entityOne), owner(r.entityTwo), r.interferenceBody.volume * 1000))\n",
    ),
}


def fit_script(direction: str | None) -> str:
    set_dir = ""
    if direction:
        set_dir = f"    cam.viewOrientation = adsk.core.ViewOrientations.{ORIENTATIONS[direction]}\n"
    return (
        "import adsk.core\n\ndef run(_context: str):\n"
        "    vp = adsk.core.Application.get().activeViewport\n"
        "    cam = vp.camera\n" + set_dir + "    cam.isFitView = True\n    vp.camera = cam\n    print('ok')\n"
    )


# --------------------------------------------------------------------------- Safety gates


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def audit(args, entry: dict):
    if args.no_audit:
        return
    STATE_DIR.mkdir(mode=0o700, exist_ok=True)
    entry = {"ts": now(), **entry}
    fd = os.open(AUDIT_FILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def require_write(args, what: str):
    if not (args.write or os.environ.get("FUSION_ALLOW_WRITE") == "1"):
        raise FusionError(f"'{what}' is a write operation: --write (or FUSION_ALLOW_WRITE=1) is required.")
    if not (args.doc or os.environ.get("FUSION_EXPECT_DOC") or args.any_doc):
        raise FusionError(
            "Writes apply to the active document. Name the expected target with --doc \"<name>\" "
            "(or FUSION_EXPECT_DOC), or pass --any-doc to deliberately allow any document."
        )


def preflight(c: Client, args) -> dict:
    docs = c.read({"queryType": "document", "operation": "open"})
    items = docs.get("results", []) if isinstance(docs, dict) else []
    active = next((d for d in items if d.get("isActive")), None)
    if not active:
        raise FusionError("No active document.")
    expect = args.doc or os.environ.get("FUSION_EXPECT_DOC")
    if expect and active.get("name", "").casefold() != expect.casefold():
        raise FusionError(f"Active document is '{active.get('name')}', expected '{expect}'. Aborted.")
    if active.get("isReadOnly"):
        raise FusionError(f"'{active.get('name')}' is read-only.")
    cmd = c.read({"queryType": "activeCommand"})
    if isinstance(cmd, dict) and cmd.get("isDefaultCommand") is False:
        raise FusionError(f"A command is open in Fusion ('{cmd.get('commandName')}'). Close it first.")
    return active


def confirm(args, message: str, always_interactive: bool = False):
    if args.yes and not always_interactive:
        return
    if not sys.stdin.isatty():
        raise FusionError("Cannot prompt for confirmation (no interactive terminal). Pass --yes to proceed.")
    if input(f"{message} [y/N] ").strip().lower() not in ("y", "yes"):
        raise FusionError("Not confirmed by the user.")


def guarded(args, tool: str, arguments: dict, label: str, detail: dict, sha: str | None = None, hint: str = ""):
    """Write call: safety gates plus audit logging."""
    require_write(args, label)
    with session(args) as c:
        active = preflight(c, args)
        note = " (has unsaved changes)" if active.get("isModified") else ""
        print(f"Target document: {active.get('name')}{note}", file=sys.stderr)
        confirm(args, f"Run '{label}' in Fusion?")
        base = {"cmd": label, "doc": active.get("name"), "sha256": sha, **detail}
        try:
            texts, _ = c.call(tool, arguments)
        except FusionError as e:
            audit(args, {**base, "ok": False, "error": str(e)[:300]})
            raise
        audit(args, {**base, "ok": True})
    print(render_exec(texts))
    if hint:
        print(hint, file=sys.stderr)


def vet_script(args, source: str) -> str:
    rep = lint(source)
    print_lint(rep)
    if rep["errors"] and not args.allow_unsafe:
        raise FusionError("Script lint failed (can be bypassed with --allow-unsafe, which is not recommended).")
    if rep["destructive"] and not args.allow_destructive:
        raise FusionError("Script contains destructive calls; add --allow-destructive if this is intentional.")
    return hashlib.sha256(source.encode()).hexdigest()


# --------------------------------------------------------------------------- Output helpers


def show(args, value):
    if args.json:
        print(json.dumps(value, ensure_ascii=False, indent=2))
    elif isinstance(value, (dict, list)):
        print(json.dumps(value, ensure_ascii=False, indent=2))
    else:
        print(value)


def render_exec(texts):
    """Unwrap the {"message", "success"} envelope; Fusion output may arrive UTF-8 bytes decoded as latin-1."""
    out = []
    for t in texts:
        v = _maybe_json(t)
        if isinstance(v, dict) and "message" in v:
            msg = str(v["message"])
            if v.get("success") is False:
                msg = "[FAILED] " + msg
            extra = {k: x for k, x in v.items() if k not in ("message", "success")}
            if extra:
                msg += "\n" + json.dumps(extra, ensure_ascii=False)
            t = msg
        try:
            t = t.encode("latin-1").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass
        out.append(t)
    return "\n".join(out)


def run_builtin(args, name: str, source: str):
    """Run a built-in read-only script (no write gates)."""
    with session(args) as c:
        texts, _ = c.call("fusion_mcp_execute", {"featureType": "script", "object": {"script": source}})
    print(render_exec(texts))


# --------------------------------------------------------------------------- Commands


def cmd_status(args):
    check_url(args.url)
    c = Client(args.url, args.timeout)
    info = c.initialize()
    try:
        srv = info.get("serverInfo", {})
        tools = c.rpc("tools/list").get("tools", [])
        docs = c.read({"queryType": "document", "operation": "open"})
        act = next((d for d in docs.get("results", []) if d.get("isActive")), {}) if isinstance(docs, dict) else {}
        print(f"Server  : {srv.get('name')} {srv.get('version')}  ({args.url})")
        print(f"Tools   : {', '.join(t['name'] for t in tools)}")
        print(f"Active  : {act.get('name', '-')}  (project: {act.get('parentProject', '-')}, "
              f"unsaved changes: {act.get('isModified')})")
    finally:
        c.close()


def cmd_tools(args):
    with session(args) as c:
        for t in c.rpc("tools/list").get("tools", []):
            print(f"## {t['name']}\n{t.get('description', '').strip()}\n")


def _read_cmd(query: dict):
    def f(args):
        with session(args) as c:
            show(args, c.read(query(args) if callable(query) else query))
    return f


def cmd_shot(args):
    q = {"queryType": "screenshot", "direction": args.dir, "antiAliasing": True,
         "transparentBackground": not args.opaque}
    if args.size:
        try:
            w, h = (int(x) for x in args.size.lower().split("x"))
        except ValueError:
            raise FusionError("--size format: 1600x800") from None
        if not (32 <= w <= 4096 and 32 <= h <= 4096):
            raise FusionError("--size must be between 32 and 4096 px.")
        q.update(width=w, height=h)
    with session(args) as c:
        _, images = c.call("fusion_mcp_read", q)
    if not images:
        raise FusionError("No screenshot was returned.")
    if args.out:
        out = Path(args.out).expanduser()
    else:
        SHOTS_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        out = SHOTS_DIR / f"shot-{datetime.now():%Y%m%d-%H%M%S}-{args.dir}.png"
    if out.exists() and not args.force:
        raise FusionError(f"{out} already exists (use --force to overwrite).")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(base64.b64decode(images[0]["data"]))
    print(out)


def cmd_api(args):
    q = {"queryType": "apiDocumentation", "searchPattern": args.pattern, "apiCategory": args.category}
    if args.filter:
        q["filter"] = args.filter
    with session(args) as c:
        show(args, c.read(q))


def cmd_find(args):
    q = {"queryType": "document", "operation": "search", "name": args.name}
    if args.project:
        q["project"] = args.project
    with session(args) as c:
        show(args, c.read(q))


def cmd_elec(args):
    obj: dict = {"pagination": {"limit": args.limit}}
    if args.fields:
        obj["fields"] = [f.strip() for f in args.fields.split(",") if f.strip()]
    if args.filter:
        obj["filters"] = [{"property": p, "op": o, "value": v} for p, o, v in args.filter]
    et = args.entity if args.entity.startswith("electronics.") else f"electronics.{args.entity}"
    with session(args) as c:
        texts, _ = c.call("fusion_mcp_electronics_read", {"entity_type": et, "object": obj})
        show(args, _maybe_json("\n".join(texts)))


def cmd_snippets(args):
    if args.name:
        if args.name not in SNIPPETS:
            raise FusionError(f"Unknown built-in script: {args.name}")
        print(SNIPPETS[args.name][1])
        return
    for k, (desc, _) in SNIPPETS.items():
        print(f"{k:13} {desc}")
    print(f"{'fit':13} Fit the camera to the model (view only; model unchanged) [--dir DIRECTION]")


def _snippet_cmd(name):
    return lambda args: run_builtin(args, name, SNIPPETS[name][1])


def cmd_fit(args):
    run_builtin(args, "fit", fit_script(args.dir))


def cmd_lint(args):
    src = Path(args.file).read_text(encoding="utf-8")
    rep = lint(src)
    print_lint(rep)
    print(f"sha256: {hashlib.sha256(src.encode()).hexdigest()}")
    print("RESULT:", "clean" if not any(rep.values()) else
          ("BLOCKED" if rep["errors"] else "destructive calls found" if rep["destructive"] else "warnings found"))
    return 1 if rep["errors"] else 0


def cmd_run(args):
    path = Path(args.file).expanduser()
    source = path.read_text(encoding="utf-8")
    sha = vet_script(args, source)
    if args.dry_run:
        print(f"[dry-run] {path} sha256={sha[:12]} not sent.")
        return
    guarded(args, "fusion_mcp_execute", {"featureType": "script", "object": {"script": source}},
            f"run {path.name}", {"file": str(path)}, sha, "Tip: to revert, run `fusion.py undo --write ...`")


def cmd_exec(args):
    code = args.code
    if "def run(" not in code:
        body = textwrap.indent(textwrap.dedent(code).strip("\n"), "    ")
        code = ("import adsk.core, adsk.fusion\n\ndef run(_context: str):\n"
                "    app = adsk.core.Application.get()\n"
                "    des = adsk.fusion.Design.cast(app.activeProduct)\n"
                "    root = des.rootComponent if des else None\n" + body + "\n")
    sha = vet_script(args, code)
    if args.dry_run:
        print(f"[dry-run] sha256={sha[:12]}\n{code}")
        return
    guarded(args, "fusion_mcp_execute", {"featureType": "script", "object": {"script": code}},
            "exec -c", {"preview": code[:120]}, sha, "Tip: to revert, run `fusion.py undo --write ...`")


def _update_cmd(kind):
    def f(args):
        if args.dry_run:
            print(f"[dry-run] {kind}")
            return
        guarded(args, "fusion_mcp_update", {"featureType": kind}, kind, {})
    return f


def cmd_save(args):
    if args.dry_run:
        print("[dry-run] save")
        return
    guarded(args, "fusion_mcp_execute", {"featureType": "document", "object": {"operation": "save"}}, "save", {})


def cmd_open(args):
    if args.dry_run:
        print(f"[dry-run] open {args.file_id}")
        return
    guarded(args, "fusion_mcp_execute",
            {"featureType": "document", "object": {"operation": "open", "fileId": args.file_id}},
            "open", {"fileId": args.file_id})


def cmd_close(args):
    if not args.allow_destructive:
        raise FusionError("close is destructive: --allow-destructive is required.")
    if args.save == args.discard:
        raise FusionError("close requires exactly one of --save or --discard.")
    obj = {"operation": "close"}
    obj["userConfirmedSaveAndClose" if args.save else "userConfirmedCloseWithoutSave"] = True
    if args.dry_run:
        print(f"[dry-run] close {'--save' if args.save else '--discard'}")
        return
    if args.discard:  # closing without saving always requires manual confirmation
        confirm(args, "Unsaved changes may be LOST. Close without saving?", always_interactive=True)
    guarded(args, "fusion_mcp_execute", {"featureType": "document", "object": obj},
            "close --save" if args.save else "close --discard", {})


def cmd_raw(args):
    try:
        arguments = json.loads(args.json_args or "{}")
    except ValueError as e:
        raise FusionError(f"Invalid JSON: {e}") from None
    if args.tool in READ_TOOLS:
        with session(args) as c:
            texts, _ = c.call(args.tool, arguments)
        print("\n".join(texts))
        return
    if not args.allow_destructive:
        raise FusionError("Non-read tools via raw require --allow-destructive.")
    guarded(args, args.tool, arguments, f"raw {args.tool}", {"args": json.dumps(arguments)[:200]})


# --------------------------------------------------------------------------- CLI


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    S = argparse.SUPPRESS
    g = common.add_argument_group("common options")
    g.add_argument("--url", default=S, help=f"MCP server URL (default {DEFAULT_URL})")
    g.add_argument("--timeout", type=float, default=S, help="request timeout in seconds (default 60)")
    g.add_argument("--json", action="store_true", default=S, help="print raw JSON output")
    g.add_argument("--write", action="store_true", default=S, help="allow write commands")
    g.add_argument("--doc", default=S, help="expected active document name (required for writes)")
    g.add_argument("--any-doc", action="store_true", default=S, help="allow writes without --doc")
    g.add_argument("--yes", action="store_true", default=S, help="skip confirmation prompts (except --discard)")
    g.add_argument("--allow-destructive", action="store_true", default=S, help="allow destructive calls")
    g.add_argument("--allow-unsafe", action="store_true", default=S, help="ignore lint ERRORs (not recommended)")
    g.add_argument("--dry-run", action="store_true", default=S, help="lint and show only; do not send")
    g.add_argument("--no-audit", action="store_true", default=S, help="do not write audit log entries")

    p = argparse.ArgumentParser(prog="fusion.py", parents=[common],
                                description="Fusion MCP client. Reads are free; writes are gated.")
    sub = p.add_subparsers(dest="command", required=True, metavar="command")

    def add(name, func, help_, **kw):
        sp = sub.add_parser(name, parents=[common], help=help_, description=help_, **kw)
        sp.set_defaults(func=func)
        return sp

    # read
    add("status", cmd_status, "Connection and active document summary")
    add("tools", cmd_tools, "List the server's tools and descriptions")
    add("docs", _read_cmd({"queryType": "document", "operation": "open"}), "Open documents")
    add("recent", _read_cmd({"queryType": "document", "operation": "recent"}), "Recently used documents")
    add("projects", _read_cmd({"queryType": "projects"}), "Hub projects")
    add("active", _read_cmd({"queryType": "activeCommand"}), "Command currently running in Fusion")
    sp = add("find", cmd_find, "Search for documents")
    sp.add_argument("name")
    sp.add_argument("--project")
    sp = add("shot", cmd_shot, "Capture a screenshot (PNG)")
    sp.add_argument("--dir", default="current", choices=["current", *ORIENTATIONS])
    sp.add_argument("--size", help="1600x800")
    sp.add_argument("--out", help="output path (default: <state dir>/shots/)")
    sp.add_argument("--opaque", action="store_true", help="disable the transparent background")
    sp.add_argument("--force", action="store_true", help="overwrite an existing file")
    sp = add("api", cmd_api, "Search the Fusion API documentation")
    sp.add_argument("pattern", help="regex, e.g. 'ExtrudeFeatureInput'")
    sp.add_argument("--category", default="all", choices=["class", "member", "description", "all"])
    sp.add_argument("--filter", help="e.g. adsk.fusion.Extrude")
    sp = add("elec", cmd_elec, "Read Electronics data (the active document must be an Electronics document)")
    sp.add_argument("entity", help="e.g. Part or electronics.Part")
    sp.add_argument("--fields", help="comma-separated, e.g. name,value")
    sp.add_argument("--limit", type=int, default=100)
    sp.add_argument("--filter", nargs=3, action="append", metavar=("PROPERTY", "OP", "VALUE"))

    # built-in read-only scripts
    for name, (desc, _) in SNIPPETS.items():
        add(name, _snippet_cmd(name), desc)
    sp = add("fit", cmd_fit, "Fit the camera to the model (view only; model unchanged)")
    sp.add_argument("--dir", choices=list(ORIENTATIONS))
    sp = add("snippets", cmd_snippets, "List built-in scripts or show a script's source")
    sp.add_argument("name", nargs="?")
    sp = add("lint", cmd_lint, "Lint a script without connecting to Fusion")
    sp.add_argument("file")

    # write
    sp = add("run", cmd_run, "[WRITE] Run a .py script")
    sp.add_argument("file")
    sp = add("exec", cmd_exec, "[WRITE] Run inline code (wrapped with app/des/root if no run() is defined)")
    sp.add_argument("-c", "--code", required=True)
    add("undo", _update_cmd("undo"), "[WRITE] Undo the last operation")
    add("redo", _update_cmd("redo"), "[WRITE] Redo")
    add("save", cmd_save, "[WRITE] Save the active document")
    sp = add("open", cmd_open, "[WRITE] Open a document (by fileId)")
    sp.add_argument("file_id")
    sp = add("close", cmd_close, "[DESTRUCTIVE] Close the document")
    sp.add_argument("--save", action="store_true", help="save and close")
    sp.add_argument("--discard", action="store_true", help="close without saving (always asks for manual confirmation)")
    sp = add("raw", cmd_raw, "Raw tool call (non-read tools are gated and need --allow-destructive)")
    sp.add_argument("tool")
    sp.add_argument("json_args", nargs="?", help="tool arguments as JSON")
    return p


DEFAULTS = {"url": DEFAULT_URL, "timeout": 60.0, "json": False, "write": False, "doc": None, "any_doc": False,
            "yes": False, "allow_destructive": False, "allow_unsafe": False, "dry_run": False, "no_audit": False}


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    for k, v in DEFAULTS.items():
        if not hasattr(args, k):
            setattr(args, k, v)
    try:
        return args.func(args) or 0
    except FusionError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
