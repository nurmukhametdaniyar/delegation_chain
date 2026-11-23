#!/usr/bin/env python3
"""Which MCP tools can the policy language authorize? (D-105; exploratory)

Classifies every live-probed tool of a pinned MCP-Eco release by whether a
DelegationChain policy can authorize every call its input schema admits, some
of them, or none, under the MCP binding (SPEC §10.6) and the closed-world
evaluation of SPEC §9.4. Then cross-checks the classes against the
implementation: the generated `tools/call` requests run through the binding's
parser, the policy's leaf mapping and `evaluate` (`dc-mcp-calls`).

Subcommands:
  classify   --tools mcp_tools.parquet --out DIR --calls calls.jsonl
  crosscheck --calls calls.jsonl --got got.jsonl --out DIR
  report     --out DIR [--paper-dir DIR]

The model of a call, from the implementation (crates/dc-policy/src/eval.rs,
crates/dc-verifier/src/mcp.rs):
- The tool name and every key on a leaf's path must be identifiers
  (letter (letter | digit | "_" | "-")*). A call with any other key matches no
  rule (`flatten` returns None).
- A leaf is typed when it is an integer, a string or a boolean. Null, arrays
  and nested empty maps are leaves of no type and match no declaration; a
  number with a fraction or an exponent makes the request malformed.
- Closed world: a rule matches only a call whose typed leaves are exactly the
  rule's declarations. Each set of (path, type) pairs a schema admits is a
  *shape*, and authorizing every shape takes one rule per shape; a scope holds
  at most 96 rules (MAX_RULES, D-103).

The schema reading, which is this study's choice (D-105):
- A property's admitted types come from `type`, or from `enum`/`const` values,
  `anyOf`/`oneOf` (union), a single-member or object-merging `allOf`, `$ref` to
  the same document, and OpenAPI's `nullable`. `integer`, `string` and
  `boolean` are typed; `number` admits integers (typed) and non-integers
  (malformed); a property with no type admits any value.
- The declared properties of an object are its parameters. An object with no
  declared properties, or with an `additionalProperties` or
  `patternProperties` schema, admits keys the caller chooses ("free-form"),
  which a rule cannot name in advance; it is counted as inexpressible, the
  conservative reading. A top-level object with no properties is a tool
  without parameters.
- A nested object whose properties are all optional admits `{}`, a leaf of no
  type.
- Arguments nest at most 15 levels, themselves included (D-104).
"""

import argparse
import collections
import csv
import gzip
import hashlib
import io
import json
import os
import random
import re
import sys

IDENT = re.compile(r"[A-Za-z][A-Za-z0-9_-]*\Z")
MAX_RULES = 96
MAX_DEPTH = 15
ENUM_CAP = 4096
META_KEY = "io.github.nurmukhametdaniyar/delegationchain"

# Why some admitted calls cannot be authorized, in the report's order.
REASONS = [
    "tool name",
    "parameter name",
    "array",
    "null",
    "non-integer number",
    "free-form object",
    "empty object",
    "no type",
    "unreadable schema",
    "over 96 rules",
]
# Values that no policy can authorize, by reason, for the cross-check.
BAD_VALUE = {
    "array": [],
    "null": None,
    "non-integer number": 1.5,
    "empty object": {},
    "no type": [],
}
DUMMY = {"int": 7, "string": "x", "bool": True}


class Many:
    """More than ENUM_CAP shapes."""

    def __repr__(self):
        return "MANY"


MANY = Many()
EMPTY_SHAPE = frozenset()


def size(s):
    return ENUM_CAP + 1 if s is MANY else len(s)


def union(a, b):
    if a is MANY or b is MANY:
        return MANY
    u = a | b
    return MANY if len(u) > ENUM_CAP else u


def product(a, b):
    """Shapes of two disjoint sets of paths, combined."""
    if size(a) == 0 or size(b) == 0:
        return set()
    if a is MANY or b is MANY or len(a) * len(b) > ENUM_CAP:
        return MANY
    return {x | y for x in a for y in b}


class Node:
    """What a schema admits at one position: its shapes, the reasons some
    admitted values are inexpressible (with the paths where they occur), and,
    when nothing is expressible, the reasons why."""

    def __init__(self):
        self.shapes = set()
        self.sites = []  # (path tuple, reason)
        self.blocking = set()


class Schema:
    def __init__(self, root):
        self.root = root

    def resolve(self, s, hops=0):
        while isinstance(s, dict) and isinstance(s.get("$ref"), str):
            ref = s["$ref"]
            if hops > 32 or not ref.startswith("#"):
                return None
            target = self.root
            for part in ref[1:].split("/")[1:] if ref != "#" else []:
                part = part.replace("~1", "/").replace("~0", "~")
                if isinstance(target, dict) and part in target:
                    target = target[part]
                elif isinstance(target, list) and part.isdigit() and int(part) < len(target):
                    target = target[int(part)]
                else:
                    return None
            extra = {k: v for k, v in s.items() if k != "$ref"}
            s = dict(target, **extra) if isinstance(target, dict) else target
            hops += 1
        return s

    def alternatives(self, s, hops=0):
        """The kinds of value `s` admits: ('int'|'string'|'bool',), ('object', schema)
        or ('untyped', reason)."""
        if s is True:
            s = {}
        if s is False:
            return []
        s = self.resolve(s, hops)
        if not isinstance(s, dict):
            return [("untyped", "unreadable schema")]
        if hops > 32:
            return [("untyped", "unreadable schema")]
        alts = []
        for key in ("anyOf", "oneOf"):
            if isinstance(s.get(key), list):
                base = {k: v for k, v in s.items() if k not in ("anyOf", "oneOf")}
                for sub in s[key]:
                    if isinstance(sub, dict):
                        merged = dict(sub)
                        for k in ("type", "properties", "required"):
                            if k in base and k not in merged:
                                merged[k] = base[k]
                        sub = merged
                    alts += self.alternatives(sub, hops + 1)
                if s.get("nullable") is True:
                    alts.append(("untyped", "null"))
                return alts
        if isinstance(s.get("allOf"), list):
            subs = [self.resolve(x, hops) for x in s["allOf"]]
            if not all(isinstance(x, dict) for x in subs):
                return [("untyped", "unreadable schema")]
            merged = {k: v for k, v in s.items() if k != "allOf"}
            for x in subs:
                for k, v in x.items():
                    if k == "properties" and isinstance(v, dict):
                        merged["properties"] = dict(merged.get("properties", {}), **v)
                    elif k == "required" and isinstance(v, list):
                        merged["required"] = list(merged.get("required", [])) + v
                    elif k not in merged:
                        merged[k] = v
                    elif merged[k] != v and k in ("type", "anyOf", "oneOf", "allOf", "$ref"):
                        return [("untyped", "unreadable schema")]
            return self.alternatives(merged, hops + 1)
        t = s.get("type")
        if t is None and ("_def" in s or "~standard" in s):
            # A library's internal object serialized in place of a schema.
            return [("untyped", "unreadable schema")]
        if t is None:
            if isinstance(s.get("properties"), dict):
                t = "object"
            elif "enum" in s or "const" in s:
                values = s["enum"] if "enum" in s else [s["const"]]
                if not isinstance(values, list):
                    return [("untyped", "unreadable schema")]
                kinds = {value_type(v) for v in values}
                if "number" in kinds:
                    # Only non-integer values: none of them can be sent.
                    alts.append(("untyped", "non-integer number"))
                    kinds.discard("number")
                t = sorted(kinds)
            elif "items" in s:
                t = "array"
            else:
                alts = [("int",), ("string",), ("bool",), ("untyped", "no type")]
                return alts
        types = t if isinstance(t, list) else [t]
        for ty in types:
            if ty == "integer":
                alts.append(("int",))
            elif ty == "number":
                alts += [("int",), ("untyped", "non-integer number")]
            elif ty == "string":
                alts.append(("string",))
            elif ty == "boolean":
                alts.append(("bool",))
            elif ty == "null":
                alts.append(("untyped", "null"))
            elif ty == "array":
                alts.append(("untyped", "array"))
            elif ty == "object":
                alts.append(("object", s))
            else:
                alts.append(("untyped", "unreadable schema"))
        if s.get("nullable") is True:
            alts.append(("untyped", "null"))
        return alts

    def node(self, s, path, depth):
        n = Node()
        alt_blocking = set()
        for alt in self.alternatives(s):
            if alt[0] in DUMMY:
                n.shapes = union(n.shapes, {frozenset({(".".join(path), alt[0])})})
            elif alt[0] == "object":
                o = self.obj(alt[1], path, depth + 1, nested=True)
                n.shapes = union(n.shapes, o.shapes)
                n.sites += o.sites
                alt_blocking |= o.blocking
            else:
                n.sites.append((path, alt[1]))
                alt_blocking.add(alt[1])
        if size(n.shapes) == 0:
            n.blocking = alt_blocking or {"unreadable schema"}
        return n

    def obj(self, s, path, depth, nested):
        """An object schema at `path`, `depth` levels deep (the arguments are 1)."""
        n = Node()
        if depth > MAX_DEPTH:
            n.sites.append((path, "unreadable schema"))
            n.blocking = {"unreadable schema"}
            return n
        props = s.get("properties")
        props = props if isinstance(props, dict) else {}
        required = s.get("required")
        required = {r for r in required if isinstance(r, str)} if isinstance(required, list) else set()
        for r in sorted(required - set(props)):
            props = dict(props, **{r: True})
        extra = s.get("additionalProperties")
        free = (isinstance(extra, dict) and extra != {}) or bool(s.get("patternProperties"))
        if not props:
            if not nested and not free:
                n.shapes = {EMPTY_SHAPE}
                return n
            if nested:
                reason = "free-form object" if (free or extra is not False) else "empty object"
                n.sites.append((path, reason))
                n.blocking = {reason}
                return n
            # Top level, free-form: only `{}` is expressible.
            n.shapes = {EMPTY_SHAPE}
            n.sites.append((path, "free-form object"))
            return n
        if free:
            n.sites.append((path, "free-form object"))
        acc = {EMPTY_SHAPE}
        for name in props:
            sub_path = path + (name,)
            if not IDENT.match(name):
                child = Node()
                child.sites.append((sub_path, "parameter name"))
                child.blocking = {"parameter name"}
            else:
                child = self.node(props[name], sub_path, depth)
            n.sites += child.sites
            shapes = child.shapes
            if name in required:
                if size(shapes) == 0:
                    n.blocking |= child.blocking
            else:
                shapes = union(shapes, {EMPTY_SHAPE})
            acc = product(acc, shapes)
        if nested and not (required & set(props)):
            n.sites.append((path, "empty object"))
            if acc is not MANY:
                acc = acc - {EMPTY_SHAPE}
            if size(acc) == 0:
                n.blocking.add("empty object")
        n.shapes = acc
        return n


def value_type(v):
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, int):
        return "integer"
    if isinstance(v, float):
        return "integer" if v.is_integer() else "number"
    if isinstance(v, str):
        return "string"
    if v is None:
        return "null"
    if isinstance(v, list):
        return "array"
    return "object"


def classify(name, schema):
    """Returns (class, rules, blocking, lossy, node) for one tool."""
    sch = Schema(schema)
    root = sch.resolve(schema)
    if root is True or root == {}:
        root = {"type": "object"}
    if not isinstance(root, dict):
        n = Node()
        n.sites.append(((), "unreadable schema"))
        n.blocking = {"unreadable schema"}
    else:
        # The arguments are an object (D-104), so only the schema's object
        # alternatives can be called; a schema with no type at all is a tool
        # without declared parameters.
        alts = sch.alternatives(root)
        objs = [a for a in alts if a[0] == "object"]
        if objs:
            n = Node()
            blocking = set()
            for o in objs:
                m = sch.obj(o[1], (), 1, nested=False)
                n.shapes = union(n.shapes, m.shapes)
                n.sites += m.sites
                blocking |= m.blocking
            if size(n.shapes) == 0:
                n.blocking = blocking
        elif ("untyped", "no type") in alts:
            n = sch.obj({"type": "object"}, (), 1, nested=False)
        else:
            n = Node()
            n.sites.append(((), "unreadable schema"))
            n.blocking = {"unreadable schema"}
    lossy = {r for _, r in n.sites}
    rules = size(n.shapes)
    if not IDENT.match(name):
        cls, blocking = "none", {"tool name"} | (n.blocking if rules == 0 else set())
    elif rules == 0:
        cls, blocking = "none", set(n.blocking)
    else:
        blocking = set()
        if rules > MAX_RULES:
            lossy.add("over 96 rules")
        cls = "some" if lossy else "all"
    if not IDENT.match(name):
        lossy.add("tool name")
    return cls, rules, blocking, lossy, n


def ordered(reasons):
    return [r for r in REASONS if r in reasons]


def nest(path, value):
    out = value
    for seg in reversed(path):
        out = {seg: out}
    return out


def args_for(shape):
    args = {}
    for path, ty in sorted(shape):
        cur = args
        segs = path.split(".") if path else []
        for seg in segs[:-1]:
            cur = cur.setdefault(seg, {})
        cur[segs[-1]] = DUMMY[ty]
    return args


def request(name, args):
    params = '{"name":%s,"arguments":%s,"_meta":{%s:"AA"}}' % (
        json.dumps(name, ensure_ascii=False),
        json.dumps(args, ensure_ascii=False, separators=(",", ":")),
        json.dumps(META_KEY),
    )
    return '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":%s}' % params


def rule_text(name, shape):
    decl = ", ".join(f"{p}: {t}" for p, t in sorted(shape))
    head = f"allow at=v:service:mcp tool={name} action=call"
    return head + (f" params {{ {decl} }}" if decl else "")


def calls_for(name, cls, n, rng):
    """The cross-check's calls for one tool: authorizable shapes (expected to
    be allowed by a scope of one rule per shape) and inexpressible values
    (expected to be rejected whatever the policy)."""
    calls, scope = [], None
    if IDENT.match(name) and n.shapes is not MANY and n.shapes:
        shapes = sorted(n.shapes, key=lambda s: (len(s), sorted(s)))
        picked = {shapes[0], shapes[-1], shapes[rng.randrange(len(shapes))]}
        rules = shapes if len(shapes) <= MAX_RULES else sorted(picked, key=lambda s: (len(s), sorted(s)))
        scope = "\n".join(rule_text(name, s) for s in rules)
        for s in sorted(picked, key=lambda s: (len(s), sorted(s))):
            calls.append({"request": request(name, args_for(s)), "expect": "allow"})
    if not IDENT.match(name):
        calls.append({"request": request(name, {}), "expect": "reject"})
    seen = set()
    for path, reason in n.sites:
        if (path, reason) in seen:
            continue
        seen.add((path, reason))
        if reason == "parameter name":
            calls.append({"request": request(name, nest(path, "x")), "expect": "reject"})
        elif reason in BAD_VALUE and path:
            calls.append({"request": request(name, nest(path, BAD_VALUE[reason])), "expect": "reject"})
    return scope, calls


def load_probe_rows(path):
    import pyarrow.parquet as pq  # pinned in scripts/mcp-expressiveness-requirements.txt

    t = pq.read_table(path, columns=["server_id", "tool_name", "input_json_schema", "source"])
    rows = []
    for r in t.to_pylist():
        if r["source"] != "probe":
            continue
        rows.append((str(r["server_id"]), r["tool_name"], r["input_json_schema"]))
    rows.sort()
    return rows, t.num_rows


def utf8(s):
    try:
        s.encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False


def cmd_classify(a):
    rows, total = load_probe_rows(a.tools)
    os.makedirs(a.out, exist_ok=True)
    h = hashlib.sha256()
    with open(a.tools, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    corpus = {"dataset": a.dataset, "revision": a.revision, "file": a.file, "sha256": h.hexdigest(),
              "license": "CC BY 4.0", "rows_in_table": total, "probe_rows": len(rows)}
    with open(os.path.join(a.out, "corpus.json"), "w") as f:
        json.dump(corpus, f, indent=2, sort_keys=True)
        f.write("\n")
    rng = random.Random(105)
    seen = {}
    counts = collections.Counter()
    # mtime=0: the archive regenerates byte-identically.
    raw = gzip.GzipFile(os.path.join(a.out, "tools.csv.gz"), "wb", mtime=0)
    with io.TextIOWrapper(raw, encoding="utf-8", newline="") as f, open(a.calls, "w", encoding="utf-8") as cf:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["server_id", "tool_name", "schema_sha256", "class", "rules", "blocking", "lossy"])
        for server, name, text in rows:
            digest = hashlib.sha256((text or "").encode("utf-8")).hexdigest()
            key = (name, digest)
            if key not in seen:
                try:
                    schema = json.loads(text) if text is not None else None
                except ValueError:
                    schema = None
                cls, rules, blocking, lossy, n = classify(name, schema if schema is not None else "unreadable")
                seen[key] = (cls, rules, blocking, lossy)
                scope, calls = calls_for(name, cls, n, rng)
                kept = [c for c in calls if utf8(c["request"])]
                counts["calls_not_utf8"] += len(calls) - len(kept)
                calls = kept
                if calls:
                    cf.write(json.dumps({"tool": name, "key": digest, "scope": scope, "calls": calls}, ensure_ascii=False) + "\n")
                    counts["calls"] += len(calls)
            cls, rules, blocking, lossy = seen[key]
            w.writerow([server, name, digest, cls, rules if rules <= ENUM_CAP else f">{ENUM_CAP}",
                        ";".join(ordered(blocking)), ";".join(ordered(lossy))])
    meta = {"rows_in_table": total, "probe_rows": len(rows), "distinct_name_schema": len(seen),
            "calls_generated": counts["calls"], "calls_not_utf8": counts["calls_not_utf8"]}
    with open(os.path.join(a.out, "classify.json"), "w") as f:
        json.dump(meta, f, indent=2, sort_keys=True)
        f.write("\n")
    print(json.dumps(meta))


def cmd_crosscheck(a):
    expect = []
    with open(a.calls, encoding="utf-8") as f:
        for line in f:
            d = json.loads(line)
            for c in d["calls"]:
                expect.append((d["tool"], c["expect"]))
    got = []
    with open(a.got, encoding="utf-8") as f:
        for line in f:
            got.append(json.loads(line)["got"])
    if len(got) != len(expect):
        sys.exit(f"{len(got)} results for {len(expect)} calls")
    tally = collections.Counter()
    disagree = []
    for (tool, e), g in zip(expect, got):
        ok = (g == "allow") if e == "allow" else (g in ("tool name", "key", "untyped") or g.startswith("malformed"))
        tally[(e, "agree" if ok else "disagree")] += 1
        tally[("got", e, g.split(":")[0])] += 1
        if not ok:
            disagree.append({"tool": tool, "expect": e, "got": g})
    out = {
        "calls": len(expect),
        "allow_expected": tally[("allow", "agree")] + tally[("allow", "disagree")],
        "allow_agreed": tally[("allow", "agree")],
        "reject_expected": tally[("reject", "agree")] + tally[("reject", "disagree")],
        "reject_agreed": tally[("reject", "agree")],
        "outcomes": {f"{k[1]} -> {k[2]}": v for k, v in sorted(tally.items(), key=str) if k[0] == "got"},
        "disagreements": disagree[:50],
        "disagreements_total": len(disagree),
    }
    with open(os.path.join(a.out, "crosscheck.json"), "w") as f:
        json.dump(out, f, indent=2, sort_keys=True)
        f.write("\n")
    print(json.dumps({k: v for k, v in out.items() if k != "disagreements"}))
    if disagree:
        sys.exit(1)


def pct(n, d):
    return f"{100 * n / d:.1f}"


def cmd_report(a):
    rows = []
    with gzip.open(os.path.join(a.out, "tools.csv.gz"), "rt", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            rows.append(r)
    servers = collections.defaultdict(list)
    for r in rows:
        servers[r["server_id"]].append(r["class"])
    distinct = {}
    for r in rows:
        distinct[(r["tool_name"], r["schema_sha256"])] = r
    def classes(rs):
        c = collections.Counter(r["class"] for r in rs)
        return {k: c[k] for k in ("all", "some", "none")}
    def reasons(rs, field):
        c = collections.Counter()
        for r in rs:
            for x in filter(None, r[field].split(";")):
                c[x] += 1
        return {k: c[k] for k in REASONS if c[k]}
    not_all = [r for r in rows if r["class"] != "all"]
    none = [r for r in rows if r["class"] == "none"]
    srv = collections.Counter("all" if all(c == "all" for c in cs) else
                              "none" if all(c == "none" for c in cs) else "mixed" for cs in servers.values())
    rules = collections.Counter()
    for r in rows:
        if r["class"] == "all":
            n = int(r["rules"])
            rules["1" if n == 1 else "2-8" if n <= 8 else "9-96"] += 1
    summary = {
        "tools": len(rows),
        "servers": len(servers),
        "classes": classes(rows),
        "distinct_name_schema": len(distinct),
        "classes_distinct": classes(distinct.values()),
        "servers_by_class": {k: srv[k] for k in ("all", "mixed", "none")},
        "reasons_not_all": reasons(not_all, "lossy"),
        "reasons_none": reasons(none, "blocking"),
        "rules_needed_all": {k: rules[k] for k in ("1", "2-8", "9-96")},
    }
    with open(os.path.join(a.out, "corpus.json")) as f:
        corpus = json.load(f)
    with open(os.path.join(a.out, "crosscheck.json")) as f:
        cross = json.load(f)
    summary["crosscheck"] = {k: cross[k] for k in ("calls", "allow_expected", "allow_agreed",
                                                   "reject_expected", "reject_agreed", "disagreements_total")}
    with open(os.path.join(a.out, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2, sort_keys=True)
        f.write("\n")
    t = len(rows)
    md = [
        "# MCP tools the policy language can authorize (D-105; exploratory)",
        "",
        f"Generated by `scripts/mcp_expressiveness.py report` from `tools.csv.gz` and `crosscheck.json`.",
        f"Corpus: {corpus['dataset']} at revision `{corpus['revision']}`, `{corpus['file']}` "
        f"(SHA-256 `{corpus['sha256']}`), rows with `source = probe` (tools listed live by `tools/list`).",
        "",
        f"- Tools: {t:,} from {len(servers):,} servers; {len(distinct):,} distinct (name, schema) pairs.",
        "",
        "| Class | Tools | % | Distinct (name, schema) | % |",
        "|---|---:|---:|---:|---:|",
    ]
    cd = summary["classes_distinct"]
    for k, label in (("all", "every admitted call"), ("some", "some calls"), ("none", "no call")):
        md.append(f"| {label} | {summary['classes'][k]:,} | {pct(summary['classes'][k], t)} | {cd[k]:,} | {pct(cd[k], len(distinct))} |")
    md += ["", "Servers: " + ", ".join(f"{k} {v:,}" for k, v in summary["servers_by_class"].items()), "",
           "| Reason some admitted calls are inexpressible | Tools | % of tools |", "|---|---:|---:|"]
    for k, v in summary["reasons_not_all"].items():
        md.append(f"| {k} | {v:,} | {pct(v, t)} |")
    md += ["", "| Reason no call is expressible | Tools |", "|---|---:|"]
    for k, v in summary["reasons_none"].items():
        md.append(f"| {k} | {v:,} |")
    c = summary["crosscheck"]
    md += ["", f"Rules needed by tools in the first class: " +
           ", ".join(f"{k}: {v:,}" for k, v in summary["rules_needed_all"].items()), "",
           f"Cross-check against the implementation (`dc-mcp-calls`): {c['calls']:,} generated calls; "
           f"{c['allow_agreed']:,} of {c['allow_expected']:,} expected allowed were allowed, "
           f"{c['reject_agreed']:,} of {c['reject_expected']:,} expected rejected were rejected by the binding or "
           f"the leaf mapping; {c['disagreements_total']} disagreements.", ""]
    with open(os.path.join(a.out, "summary.md"), "w") as f:
        f.write("\n".join(md))
    if a.paper_dir:
        write_table(summary, corpus, os.path.join(a.paper_dir, "tables", "mcp_expressiveness.tex"))
    print(json.dumps(summary["classes"]), json.dumps(summary["reasons_not_all"]))


def write_table(s, corpus, path):
    t = s["tools"]
    lines = [
        "% Generated by scripts/mcp_expressiveness.py (D-105). Do not edit.",
        "\\begin{tabular}{@{}lrr@{}}",
        "\\toprule",
        "Live-probed tools & Tools & \\% \\\\",
        "\\midrule",
    ]
    for k, label in (("all", "Every call the schema admits"), ("some", "Some calls"), ("none", "No call")):
        lines.append(f"{label} & {s['classes'][k]:,} & {pct(s['classes'][k], t)} \\\\")
    lines += ["\\midrule", "\\multicolumn{3}{@{}l}{Why some admitted calls are not expressible (a tool may have several reasons)} \\\\"]
    for k, v in s["reasons_not_all"].items():
        lines.append(f"\\quad {k} & {v:,} & {pct(v, t)} \\\\")
    lines += ["\\midrule", f"All tools & {t:,} & 100.0 \\\\", "\\bottomrule", "\\end{tabular}", ""]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write("\n".join(lines))


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("classify")
    c.add_argument("--tools", required=True)
    c.add_argument("--dataset", required=True)
    c.add_argument("--revision", required=True)
    c.add_argument("--file", required=True)
    c.add_argument("--out", required=True)
    c.add_argument("--calls", required=True)
    x = sub.add_parser("crosscheck")
    x.add_argument("--calls", required=True)
    x.add_argument("--got", required=True)
    x.add_argument("--out", required=True)
    r = sub.add_parser("report")
    r.add_argument("--out", required=True)
    r.add_argument("--paper-dir")
    a = p.parse_args()
    {"classify": cmd_classify, "crosscheck": cmd_crosscheck, "report": cmd_report}[a.cmd](a)


if __name__ == "__main__":
    main()
