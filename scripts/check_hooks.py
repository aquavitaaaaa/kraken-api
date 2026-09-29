#!/usr/bin/env python3
"""Development-time hook check. Resolves every class/field/method named in hooks.json against a RuneLite
injected-client jar and prints a PASS/FAIL table. Never runs at client startup; needs no JDK.

Usage:
  python3 scripts/check_hooks.py                       # jar for runeLiteVersion in build.gradle (downloaded, cached)
  python3 scripts/check_hooks.py --runelite 1.13.0
  python3 scripts/check_hooks.py --jar path/to/injected-client.jar --hooks path/to/hooks.json

Exit code 0 = all resolved, 1 = at least one FAIL. This checks structure (owner/name/descriptor kind); it cannot
prove multipliers or garbage values - use the manual-mapping guide for those and confirm at runtime.
"""
import argparse, json, re, struct, sys, urllib.request, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO = "https://repo.runelite.net/net/runelite/injected-client/{v}/injected-client-{v}.jar"


class ClassInfo:
    def __init__(self, data):
        p = 8
        n = struct.unpack_from(">H", data, p)[0]; p += 2
        cp = [None] * n
        i = 1
        while i < n:
            t = data[p]; p += 1
            if t == 1:
                l = struct.unpack_from(">H", data, p)[0]; p += 2
                cp[i] = data[p:p + l].decode("utf-8", "replace"); p += l
            elif t in (3, 4): p += 4
            elif t in (5, 6): p += 8; i += 1
            elif t in (7, 8, 16, 19, 20): cp[i] = struct.unpack_from(">H", data, p)[0]; p += 2
            elif t in (9, 10, 11, 12, 17, 18): p += 4
            elif t == 15: p += 3
            else: raise ValueError(f"bad constant tag {t}")
            i += 1
        p += 2
        self.name = cp[cp[struct.unpack_from(">H", data, p)[0]]]; p += 2
        s = struct.unpack_from(">H", data, p)[0]; p += 2
        self.super = cp[cp[s]] if s else None
        ic = struct.unpack_from(">H", data, p)[0]; p += 2 + 2 * ic
        self.fields, self.methods = [], []
        for out in (self.fields, self.methods):
            cnt = struct.unpack_from(">H", data, p)[0]; p += 2
            for _ in range(cnt):
                acc, ni, di, ac = struct.unpack_from(">HHHH", data, p); p += 8
                out.append((cp[ni], cp[di], acc))
                for _ in range(ac):
                    p += 2; l = struct.unpack_from(">I", data, p)[0]; p += 4 + l


def load(jar):
    classes = {}
    with zipfile.ZipFile(jar) as z:
        for n in z.namelist():
            if n.endswith(".class"):
                c = ClassInfo(z.read(n)); classes[c.name] = c
    return classes


def default_version():
    m = re.search(r"runeLiteVersion\s*=\s*'([^']+)'", (ROOT / "build.gradle").read_text())
    return m.group(1) if m else sys.exit("runeLiteVersion not found; pass --runelite or --jar")


def fetch(v):
    dest = Path.home() / ".cache" / "kraken-hooks" / f"injected-client-{v}.jar"
    if not dest.exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        print(f"Downloading {REPO.format(v=v)}", file=sys.stderr)
        urllib.request.urlretrieve(REPO.format(v=v), dest)
    return dest


def nparams(desc):
    return len(re.findall(r"\[*(?:L[^;]+;|[BCDFIJSZ])", desc[1:desc.index(")")]))


def build_checks(h):
    r, l, s = h["reflectionHooks"], h["loginHooks"], h["securityHooks"]
    C = []  # (hook, kind, owner, name, descriptor-regex or None, param count or None)
    cls = lambda hook, o: C.append((hook, "class", o, None, None, None))
    fld = lambda hook, o, n, d=None: C.append((hook, "field", o, n, d, None))
    mth = lambda hook, o, n, d=None, pc=None: C.append((hook, "method", o, n, d, pc))
    for k in ("clientPacketClassName", "packetWriterClassName", "classContainingPacketBufferNodeName", "bufferClassName",
              "extendedBufferClassName", "mouseHandlerLastPressedClass", "packetBufferNodeClassName", "doActionClassName"):
        cls("reflectionHooks." + k, r[k])
    fld("reflectionHooks.isaacCipherFieldName", r["packetWriterClassName"], r["isaacCipherFieldName"])
    fld("reflectionHooks.packetWriterFieldName", "client", r["packetWriterFieldName"], f"^L{r['packetWriterClassName']};$")
    if r["addNodeClassName"].lower() == "client":  # instance method on the PacketWriter (client.<writer>.addNode)
        mth("reflectionHooks.addNodeMethod", r["packetWriterClassName"], r["addNodeMethodName"], f"^\\(L{r['packetBufferNodeClassName']};I\\)V$")
    else:  # static helper taking the writer as first parameter
        mth("reflectionHooks.addNodeMethod", r["addNodeClassName"], r["addNodeMethodName"], f"^\\(L{r['packetWriterClassName']};")
    fld("reflectionHooks.clientPacketLengthField", r["clientPacketClassName"], r["clientPacketLengthField"], "^I$")
    mth("reflectionHooks.packetBufferNodeFactory", r["classContainingPacketBufferNodeName"], r["packetBufferNodeFactoryMethodName"],
        f"\\)L{r['packetBufferNodeClassName']};$")
    fld("reflectionHooks.bufferOffsetField", r["bufferClassName"], r["bufferOffsetField"], "^I$")
    fld("reflectionHooks.bufferArrayField", r["bufferClassName"], r["bufferArrayField"], r"^\[B$")
    fld("reflectionHooks.mouseHandlerLastPressed", r["mouseHandlerLastPressedClass"], r["mouseHandlerLastPressedField"], "^J$")
    fld("reflectionHooks.clientMillisField", "client", r["clientMillisField"], "^J$")
    fld("reflectionHooks.packetBufferField", r["packetBufferNodeClassName"], r["packetBufferFieldName"],
        f"^L{r['bufferClassName']};$")
    mth("reflectionHooks.doAction", r["doActionClassName"], r["doActionMethodName"], None, 11)
    mth("loginHooks.loginIndexMethod", l["loginIndexClassName"], l["loginIndexMethodName"], r"^\(II\)V$")
    for n in ("session", "accountId", "accessToken", "refreshToken", "credentialLookup"):
        mth(f"loginHooks.{n}Method", l[n + "ClassName"], l[n + "MethodName"])
    fld("loginHooks.displayNameField", l["displayNameClassName"], l["displayNameFieldName"], "^Ljava/lang/String;$")
    fld("loginHooks.accountCheckField", l["accountCheckClassName"], l["accountCheckFieldName"], f"^L{l['jagexValueClassName']};$")
    fld("loginHooks.jagexValue", l["jagexValueClassName"], l["jagexValueFieldName"], f"^L{l['jagexValueClassName']};$")
    fld("loginHooks.legacyValue", l["legacyValueClassName"], l["legacyValueFieldName"], f"^L{l['legacyValueClassName']};$")
    mth("securityHooks.mouseHookDllMethod", s["mouseHookDllClassName"], s["mouseHookDllMethodName"])
    fld("securityHooks.clientLogField", "client", s["clientLogFieldName"], r"^Lorg/slf4j/Logger;$")
    cls("securityHooks.platformInfoClassName", s["platformInfoClassName"])
    mth("securityHooks.platformInfoMethod", s["platformInfoClassName"], s["platformInfoMethodName"], None,
        s["platformInfoMethodArgCount"])
    fld("securityHooks.agentField", s["platformInfoClassName"], s["agentField"], "^Ljava/lang/String;$")
    fld("securityHooks.callStackField", s["platformInfoClassName"], s["callStackField"], "^Ljava/lang/String;$")
    for p in h["packets"]:
        fld(f"packets.{p['name']}", r["clientPacketClassName"], p["obfuscatedName"], f"^L{r['clientPacketClassName']};$")
        for i, w in enumerate(p["writes"]):
            mth(f"packets.{p['name']}.writes[{i}]", r["extendedBufferClassName"], w["methodName"])
    return C


def check(classes, c):
    hook, kind, owner, name, dre, pc = c
    if owner not in classes: return False, f"class '{owner}' not found"
    if kind == "class": return True, owner
    chain, seen = [], set()
    o = classes[owner]
    while o and o.name not in seen:  # inherited members count (buffer writes live on a superclass)
        chain.append(o); seen.add(o.name); o = classes.get(o.super)
    pool = "fields" if kind == "field" else "methods"
    cands = [(cn.name, m) for cn in chain for m in getattr(cn, pool) if m[0] == name]
    if not cands: return False, f"{kind} {owner}.{name} not found"
    good = [x for x in cands if (dre is None or re.search(dre, x[1][1])) and (pc is None or nparams(x[1][1]) == pc)]
    if not good:
        return False, f"{owner}.{name} exists but is {cands[0][1][1]} (expected /{dre or ''}/ params={pc})"
    return True, f"{good[0][0]}.{name}{good[0][1][1]}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hooks", default=str(ROOT / "src/main/resources/hooks.json"))
    ap.add_argument("--jar"); ap.add_argument("--runelite")
    a = ap.parse_args()
    jar = Path(a.jar) if a.jar else fetch(a.runelite or default_version())
    if not jar.is_file(): sys.exit(f"jar not found: {jar}")
    try:
        hooks = json.load(open(a.hooks))
        checks = build_checks(hooks)
    except OSError as e: sys.exit(f"cannot read hooks: {e}")
    except json.JSONDecodeError as e: sys.exit(f"hooks.json is not valid JSON: {e}")
    except (KeyError, TypeError) as e: sys.exit(f"hooks.json is missing or has a malformed key: {e}")
    classes = load(jar)
    fails = 0
    print(f"jar: {jar}\nhooks: {a.hooks}\n")
    print(f"{'STATUS':<7}{'HOOK':<52}RESOLVED / REASON")
    for c in checks:
        ok, msg = check(classes, c)
        fails += not ok
        print(f"{'PASS' if ok else 'FAIL':<7}{c[0]:<52}{msg}")
    print(f"\n{len(checks) - fails} PASS, {fails} FAIL. Not checked statically: multipliers, garbage values, cleanCallStackValue.")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
