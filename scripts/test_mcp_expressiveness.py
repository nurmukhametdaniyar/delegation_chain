#!/usr/bin/env python3
"""Unit tests for scripts/mcp_expressiveness.py (D-105)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mcp_expressiveness as m  # noqa: E402


def obj(props=None, required=(), **kw):
    s = {"type": "object"}
    if props is not None:
        s["properties"] = props
    if required:
        s["required"] = list(required)
    s.update(kw)
    return s


INT, STR, BOOL = {"type": "integer"}, {"type": "string"}, {"type": "boolean"}


class Classify(unittest.TestCase):
    def check(self, schema, cls, rules=None, lossy=(), blocking=(), name="t"):
        c, r, b, lo, _ = m.classify(name, schema)
        self.assertEqual(c, cls)
        if rules is not None:
            self.assertEqual(r, rules)
        self.assertEqual(set(lo), set(lossy))
        self.assertEqual(set(b), set(blocking))

    def test_no_parameters(self):
        self.check(obj(), "all", 1)
        self.check({}, "all", 1)
        self.check(obj(additionalProperties=False), "all", 1)

    def test_required_scalars(self):
        self.check(obj({"amount": INT, "to": STR, "ok": BOOL}, ["amount", "to", "ok"]), "all", 1)

    def test_optional_doubles_the_rules(self):
        self.check(obj({"a": STR}), "all", 2)
        six = {f"p{i}": STR for i in range(6)}
        self.check(obj(six), "all", 64)

    def test_over_the_rule_cap(self):
        seven = {f"p{i}": STR for i in range(7)}
        self.check(obj(seven), "some", 128, lossy={"over 96 rules"})

    def test_arrays(self):
        arr = {"type": "array", "items": STR}
        self.check(obj({"xs": arr}, ["xs"]), "none", 0, lossy={"array"}, blocking={"array"})
        self.check(obj({"xs": arr}), "some", 1, lossy={"array"})
        self.check(obj({"xs": {"items": STR}}), "some", 1, lossy={"array"})

    def test_number_admits_integers_only(self):
        self.check(obj({"n": {"type": "number"}}, ["n"]), "some", 1, lossy={"non-integer number"})
        self.check(obj({"n": {"enum": [0.5, 1.5]}}, ["n"]), "none", 0,
                   lossy={"non-integer number"}, blocking={"non-integer number"})

    def test_null(self):
        self.check(obj({"s": {"type": ["string", "null"]}}, ["s"]), "some", 1, lossy={"null"})
        optional = {"anyOf": [STR, {"type": "null"}], "default": None}
        self.check(obj({"s": optional}), "some", 2, lossy={"null"})
        self.check(obj({"s": {"type": "string", "nullable": True}}, ["s"]), "some", 1, lossy={"null"})

    def test_nested_objects(self):
        inner = obj({"b": INT}, ["b"])
        self.check(obj({"a": inner}, ["a"]), "all", 1)
        _, _, _, _, n = m.classify("t", obj({"a": inner}, ["a"]))
        self.assertEqual(n.shapes, {frozenset({("a.b", "int")})})
        self.check(obj({"a": obj({"b": INT})}, ["a"]), "some", 1, lossy={"empty object"})

    def test_free_form_objects(self):
        free = {"type": "object", "additionalProperties": STR}
        self.check(obj({"env": free}, ["env"]), "none", 0, lossy={"free-form object"},
                   blocking={"free-form object"})
        self.check(obj({"env": {"type": "object"}}), "some", 1, lossy={"free-form object"})
        self.check(obj({"a": STR}, ["a"], additionalProperties=STR), "some", 1, lossy={"free-form object"})

    def test_names(self):
        self.check(obj(), "none", lossy={"tool name"}, blocking={"tool name"}, name="get.issue")
        self.check(obj(), "none", lossy={"tool name"}, blocking={"tool name"}, name="_private")
        self.check(obj(), "all", 1, name="get-issue_2")
        self.check(obj({"page[size]": INT}), "some", 1, lossy={"parameter name"})
        self.check(obj({"page[size]": INT}, ["page[size]"]), "none", 0, lossy={"parameter name"},
                   blocking={"parameter name"})

    def test_refs_and_combinators(self):
        s = {"type": "object", "properties": {"q": {"$ref": "#/$defs/Q"}}, "required": ["q"],
             "$defs": {"Q": obj({"text": STR}, ["text"])}}
        self.check(s, "all", 1)
        self.check(obj({"x": {"oneOf": [INT, STR]}}, ["x"]), "all", 2)
        self.check(obj({"x": {"allOf": [STR]}}, ["x"]), "all", 1)
        self.check(obj({"x": {"$ref": "#/$defs/missing"}}, ["x"]), "none", 0,
                   lossy={"unreadable schema"}, blocking={"unreadable schema"})

    def test_untyped_and_enums(self):
        self.check(obj({"v": {"description": "anything"}}, ["v"]), "some", 3, lossy={"no type"})
        self.check(obj({"mode": {"enum": ["a", "b"]}}, ["mode"]), "all", 1)

    def test_depth(self):
        s = INT
        for i in range(15):
            s = obj({"a": s}, ["a"])
        self.check(s, "all", 1)  # the arguments and 14 nested objects: 15 levels
        self.check(obj({"a": s}, ["a"]), "none", 0, lossy={"unreadable schema"},
                   blocking={"unreadable schema"})

    def test_library_internals(self):
        self.check({"_def": {"typeName": "ZodObject"}, "~standard": {}}, "none", 0,
                   lossy={"unreadable schema"}, blocking={"unreadable schema"})


class Calls(unittest.TestCase):
    def test_calls(self):
        import random

        schema = obj({"a": INT, "xs": {"type": "array"}, "n": {"type": "number"}}, ["a"])
        cls, _, _, _, n = m.classify("t", schema)
        scope, calls = m.calls_for("t", cls, n, random.Random(1))
        self.assertEqual(scope.count("allow"), 2)
        self.assertIn('"arguments":{"a":7}', calls[0]["request"])
        rejects = [c["request"] for c in calls if c["expect"] == "reject"]
        self.assertTrue(any('"xs":[]' in r for r in rejects))
        self.assertTrue(any('"n":1.5' in r for r in rejects))
        self.assertIn('"io.github.nurmukhametdaniyar/delegationchain":"AA"', calls[0]["request"])


if __name__ == "__main__":
    unittest.main()
