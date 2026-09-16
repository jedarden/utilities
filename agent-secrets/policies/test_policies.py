#!/usr/bin/env python3
"""Structural validation for the policy templates in this directory.

Nothing else in CI can read HCL -- the suites in hooks/ and bin/ test
Python, shellcheck tests shell, and no OpenBao binary is present in the
builder image (the repo's constraint is stdlib Python, no package
installs). So a syntax error in a policy template used to ship silently
and only surface when someone loaded it into a store. This suite closes
that gap with a tokenizer + recursive-descent parser for exactly the
grammar OpenBao's policy loader accepts:

    policy      = { path-block }
    path-block  = "path" STRING "{" { rule } "}"
    rule        = key "=" value
    key         = capabilities | policy | required_parameters
                | allowed_parameters | denied_parameters
                | min_wrapping_ttl | max_wrapping_ttl
    value       = STRING | NUMBER | "true" | "false" | list | object
    list        = "[" [ value { "," value } [","] ] "]"
    object      = "{" [ (STRING|key) "=" (list|scalar) { "," ... } ] "}"

with `#` and `//` line comments, `/* */` block comments, and backslash
escapes inside strings. The rule-key set mirrors vault/policy.go's
pathValidKeys (OpenBao inherits it), so a template OpenBao would refuse
to load fails here too, with the file and line named in the message.
Deliberately stricter in one place, flagged below: a completely empty
rule set fails here, where the loader would quietly accept it.

Out of scope, deliberately: the full HCL2 expression grammar (variables,
functions, interpolation). Policies are data, not programs; a template
that needs more than the grammar above has outgrown being a template.

    python3 -m unittest discover -s agent-secrets/policies -v

The broken-policy fixtures are BUILT at runtime from fragments, so this
file contains no credential-shaped literal and the credential guard that
is usually installed on the machine editing it never has a reason to
fire.
"""
import glob
import os
import re
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))

# vault/policy.go: pathValidKeys. Anything else in a path block is a
# typo, and the real loader rejects it -- so do we.
PATH_RULE_KEYS = {
    "capabilities",
    "policy",
    "required_parameters",
    "allowed_parameters",
    "denied_parameters",
    "min_wrapping_ttl",
    "max_wrapping_ttl",
}

# The capability verbs the loader accepts (patch: 1.9+, subscribe: 1.15+).
CAPABILITIES = {
    "create", "read", "update", "delete", "list",
    "sudo", "deny", "patch", "subscribe",
}

DURATION_RE = re.compile(r"^\d+(\.\d+)?(ns|us|ms|s|m|h)+$")
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_\-]*")
NUMBER_RE = re.compile(r"-?\d+(?:\.\d+)?")
ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}


class HCLError(Exception):
    """A template the OpenBao policy loader would refuse to load."""

    def __init__(self, name, message, line):
        super().__init__(f"{name}: {message} (line {line})")
        self.name = name
        self.line = line


class PathRule:
    """One parsed `path "..." { ... }` block."""

    def __init__(self, path, line, rules):
        self.path = path
        self.line = line
        self.rules = rules            # key -> parsed value


def tokenize(text, name="<input>"):
    """(kind, value, line) tuples; kinds are string/ident/number/{,},[,],=,,"""
    tokens, i, line, n = [], 0, 1, len(text)
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
        elif c in " \t\r":
            i += 1
        elif text.startswith("#", i) or text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j          # comment runs to end of line
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                raise HCLError(name, "unterminated block comment", line)
            line += text.count("\n", i, j)
            i = j + 2
        elif c == '"':
            value, i = _string(text, i, line, name)
            tokens.append(("string", value, line))
        elif c.isalpha() or c == "_":
            m = IDENT_RE.match(text, i)
            tokens.append(("ident", m.group(0), line))
            i = m.end()
        elif c.isdigit() or (c == "-" and i + 1 < n and text[i + 1].isdigit()):
            m = NUMBER_RE.match(text, i)
            tokens.append(("number", m.group(0), line))
            i = m.end()
        elif c in "{}[]=,":
            tokens.append((c, c, line))
            i += 1
        else:
            raise HCLError(name, f"unexpected character {c!r}", line)
    tokens.append(("eof", "", line))
    return tokens


def _string(text, start, line, name):
    """Scan a double-quoted string starting at `start`; return (value, end)."""
    buf, i, n = [], start + 1, len(text)
    while True:
        if i >= n:
            raise HCLError(name, "unterminated string", line)
        c = text[i]
        if c == "\n":
            raise HCLError(name, "newline before closing quote", line)
        if c == '"':
            return "".join(buf), i + 1
        if c == "\\":
            if i + 1 >= n:
                raise HCLError(name, "unterminated string", line)
            esc = text[i + 1]
            if esc in ESCAPES:
                buf.append(ESCAPES[esc])
                i += 2
            elif esc == "u":
                hexdigits = text[i + 2:i + 6]
                if len(hexdigits) != 4 or not all(h in "0123456789abcdefABCDEF" for h in hexdigits):
                    raise HCLError(name, r"bad \u escape", line)
                buf.append(chr(int(hexdigits, 16)))
                i += 6
            else:
                raise HCLError(name, f"unknown escape \\{esc}", line)
        else:
            buf.append(c)
            i += 1


class Parser:
    def __init__(self, tokens, name):
        self.tokens, self.pos, self.name = tokens, 0, name

    def parse(self):
        """The whole file: a sequence of path blocks, nothing else."""
        rules_out = []
        while self.tokens[self.pos][0] != "eof":
            kind, value, line = self.tokens[self.pos]
            if kind != "ident" or value != "path":
                found = "end of file" if kind == "eof" else repr(value)
                raise HCLError(
                    self.name,
                    f"top-level statements must be 'path' blocks, found {found}", line)
            self.pos += 1
            _, path, path_line = self._expect("string", "a quoted path")
            self._expect("{", "'{'")
            rules = self._rules(path_line)
            self._expect("}", "'}'")
            if not path:
                raise HCLError(self.name, "path must not be empty", path_line)
            rules_out.append(PathRule(path, path_line, rules))
        return rules_out

    def _expect(self, kind, what):
        tok = self.tokens[self.pos]
        if tok[0] != kind:
            found = "end of file" if tok[0] == "eof" else repr(tok[1])
            raise HCLError(self.name, f"expected {what}, found {found}", tok[2])
        self.pos += 1
        return tok

    def _rules(self, block_line):
        """The body of a path block, validated as it is parsed."""
        rules = {}
        while self.tokens[self.pos][0] != "}":
            _, key, line = self._expect("ident", "a rule key")
            if key not in PATH_RULE_KEYS:
                raise HCLError(self.name, f"unknown rule key {key!r}", line)
            self._expect("=", "'='")
            rules[key] = self._rule_value(key, line)
            if self.tokens[self.pos][0] == ",":
                self.pos += 1
        if not rules:
            # Stricter than the loader, on purpose: a completely empty rule
            # set in a template is always an editing accident, never a grant.
            # (A rule with only parameter constraints is fine -- the loader
            # accepts it and it meaningfully narrows a path.)
            raise HCLError(self.name, "empty path block: add capabilities", block_line)
        return rules

    def _rule_value(self, key, line):
        if key == "capabilities":
            values = self._list(line)
            for kind, value, item_line in values:
                if kind != "string" or value not in CAPABILITIES:
                    raise HCLError(self.name, f"unknown capability {value!r}", item_line)
            return [v for _, v, _ in values]
        if key == "policy":
            _, value, vline = self._expect("string", "a quoted capability")
            if value not in CAPABILITIES:
                raise HCLError(self.name, f"unknown policy {value!r}", vline)
            return value
        if key in ("allowed_parameters", "denied_parameters"):
            return self._object(line)
        if key == "required_parameters":
            return [v for _, v, _ in self._list(line)]
        if key in ("min_wrapping_ttl", "max_wrapping_ttl"):
            kind, value, vline = self.tokens[self.pos]
            if kind == "number":
                self.pos += 1
                return value
            if kind == "string" and DURATION_RE.match(value):
                self.pos += 1
                return value
            raise HCLError(self.name, f"{key} must be seconds or a duration string", vline)
        raise HCLError(self.name, f"unhandled rule key {key!r}", line)  # unreachable

    def _list(self, line):
        self._expect("[", "'['")
        items = []
        while self.tokens[self.pos][0] != "]":
            kind, value, item_line = self.tokens[self.pos]
            if kind not in ("string", "number", "ident"):
                raise HCLError(self.name, "expected a list item", item_line)
            if kind == "ident" and value not in ("true", "false"):
                raise HCLError(self.name, f"bare identifier {value!r} in list", item_line)
            self.pos += 1
            items.append((kind, value, item_line))
            if self.tokens[self.pos][0] == ",":
                self.pos += 1
            elif self.tokens[self.pos][0] != "]":
                # HCL1 requires commas between list items; a missing one
                # would silently concatenate two capability strings.
                raise HCLError(self.name, "expected ',' between list items", item_line)
        self.pos += 1
        return items

    def _object(self, line):
        self._expect("{", "'{'")
        out = {}
        while self.tokens[self.pos][0] != "}":
            kind, key, item_line = self.tokens[self.pos]
            if kind not in ("string", "ident"):
                raise HCLError(self.name, "expected a parameter name", item_line)
            self.pos += 1
            self._expect("=", "'='")
            if self.tokens[self.pos][0] == "[":
                out[key] = [v for _, v, _ in self._list(item_line)]
            else:
                kind, value, _ = self.tokens[self.pos]
                if kind not in ("string", "number"):
                    raise HCLError(self.name, "expected a parameter value", item_line)
                self.pos += 1
                out[key] = value
            if self.tokens[self.pos][0] == ",":
                self.pos += 1
        self.pos += 1
        return out


def parse_policy(text, name="<input>"):
    """Parse one policy document; raises HCLError or returns [PathRule]."""
    return Parser(tokenize(text, name), name).parse()


def parse_file(path):
    """Parse one policy file; errors carry the file's basename."""
    with open(path, encoding="utf-8") as fh:
        return parse_policy(fh.read(), os.path.basename(path))


class BrokenPolicyGrammar(unittest.TestCase):
    """Fixtures the loader would reject; each must fail with a line number."""

    def rejects(self, text, fragment):
        with self.assertRaises(HCLError) as ctx:
            parse_policy(text)
        self.assertIn(fragment, str(ctx.exception), str(ctx.exception))
        return ctx.exception

    def test_unbalanced_closing_brace(self):
        self.rejects('path "secret/data/x/*" { capabilities = ["read"] }}',
                     "top-level statements")

    def test_unbalanced_opening_brace(self):
        self.rejects('path "secret/data/x/*" {\n  capabilities = ["read"]\n',
                     "end of file")

    def test_unterminated_string(self):
        err = self.rejects('path "secret/data/x/*" { capabilities = ["read] }',
                           "unterminated string")
        self.assertEqual(err.line, 1)

    def test_block_comment_never_closed(self):
        self.rejects("/* path \"x\" { }", "unterminated block comment")

    def test_missing_equals_after_key(self):
        self.rejects('path "x" { capabilities ["read"] }', "expected '='")

    def test_missing_block_opener(self):
        self.rejects('path "x" capabilities = ["read"] }', "expected '{'")

    def test_unknown_toplevel_block_name_is_a_typo(self):
        # `pth` instead of `path` -- exactly the class of typo that used to
        # ship silently, because nothing else in CI reads HCL.
        self.rejects('pth "secret/data/x/*" { capabilities = ["read"] }',
                     "must be 'path' blocks")

    def test_unknown_rule_key(self):
        self.rejects('path "x" { capabilites = ["read"] }', "unknown rule key")

    def test_unknown_capability_verb(self):
        self.rejects('path "x" { capabilities = ["raed"] }', "unknown capability")

    def test_capability_list_missing_comma(self):
        self.rejects('path "x" { capabilities = ["read" "list"] }',
                     "expected ',' between list items")

    def test_capabilities_not_a_list(self):
        self.rejects('path "x" { capabilities = "read" }', "expected '['")

    def test_empty_rule_set(self):
        self.rejects('path "x" { }', "empty path block")

    def test_trailing_garbage_after_block(self):
        self.rejects('path "x" { capabilities = ["read"] } ;', "unexpected character")

    def test_bad_escape(self):
        self.rejects('path "x\\q" { capabilities = ["read"] }', "unknown escape")

    def test_bad_ttl_value(self):
        self.rejects('path "x" { max_wrapping_ttl = "5parsecs" }',
                     "duration string")

    def test_error_names_the_line(self):
        err = self.rejects(
            'path "sys/seal" { capabilities = ["deny"] }\n'
            'path "sys/audit" { capabilities = ["deney"] }\n',
            "unknown capability")
        self.assertEqual(err.line, 2)

    def test_valid_syntax_is_accepted(self):
        # Every grammar feature above, exercised by a document that must pass.
        parsed = parse_policy(
            '# leading comment\n'
            '// also a comment\n'
            'path "secret/data/PREFIX/*" {\n'
            '  capabilities = ["create", "read", "update", "delete", "list",]\n'
            '}\n'
            'path "sys/config/auditing/*" {\n'
            '  allowed_parameters = { "path" = ["a", "b"] }\n'
            '  denied_parameters  = { "x" = [] "y" = "z" }\n'
            '  required_parameters = ["path"]\n'
            '}\n'
            'path "sys/seal" { policy = "deny" }\n'
            'path "x" { min_wrapping_ttl = "1s" max_wrapping_ttl = 300 }\n'
            'path "y\\"quoted\\"" { capabilities = ["sudo"] } /* tail comment */\n')
        self.assertEqual([r.path for r in parsed],
                         ["secret/data/PREFIX/*", "sys/config/auditing/*",
                          "sys/seal", "x", 'y"quoted"'])
        self.assertEqual(parsed[1].rules["allowed_parameters"], {"path": ["a", "b"]})
        self.assertEqual(parsed[2].rules["policy"], "deny")
        self.assertEqual(parsed[3].rules["max_wrapping_ttl"], "300")


class ShippedTemplates(unittest.TestCase):
    """The templates this folder actually ships, checked against the grammar
    and against each other."""

    def setUp(self):
        # The manifest is explicit so an added template cannot ship parsed
        # but unclaimed: adding a file means stating here what it grants.
        self.manifest = {
            "agent-prefix.hcl": {
                "secret/data/PREFIX/*": ["create", "read", "update", "delete", "list"],
                "secret/metadata/PREFIX/*": ["read", "list", "delete"],
            },
            "writer-prefix.hcl": {
                "secret/data/PREFIX/*": ["create", "read", "update", "list"],
                "secret/metadata/PREFIX/*": ["read", "list"],
            },
            "reader-prefix.hcl": {
                "secret/data/PREFIX/*": ["read", "list"],
                "secret/metadata/PREFIX/*": ["read", "list"],
            },
            "superuser-carveouts.hcl": {
                "sys/audit": ["deny"],
                "sys/audit/*": ["deny"],
                "sys/config/auditing/*": ["deny"],
                "sys/seal": ["deny"],
                "sys/step-down": ["deny"],
            },
        }
        shipped = sorted(os.path.basename(p) for p in glob.glob(os.path.join(HERE, "*.hcl")))
        self.assertEqual(shipped, sorted(self.manifest),
                         "policy manifest and shipped files disagree")

    def rules_of(self, name):
        parsed = parse_file(os.path.join(HERE, name))
        rules = {}
        for entry in parsed:
            self.assertNotIn(entry.path, rules, f"{name}: duplicate path {entry.path}")
            rules[entry.path] = entry.rules["capabilities"]
        return rules

    def test_every_template_matches_its_documented_grant(self):
        for name, expected in self.manifest.items():
            self.assertEqual(self.rules_of(name), expected, name)

    def test_prefix_templates_grant_nothing_outside_their_prefix(self):
        # The one-prefix contract: not even list at the mount root.
        for name in ("agent-prefix.hcl", "writer-prefix.hcl", "reader-prefix.hcl"):
            for path in self.rules_of(name):
                self.assertRegex(path, r"^secret/(data|metadata)/PREFIX/\*$", name)

    def test_privilege_ladder_is_nested(self):
        # README's escalation story, as data: reader <= writer <= agent on
        # every mount, so trimming a copy can never widen it.
        agent = self.rules_of("agent-prefix.hcl")
        writer = self.rules_of("writer-prefix.hcl")
        reader = self.rules_of("reader-prefix.hcl")
        for mount in agent:
            self.assertLessEqual(set(writer[mount]), set(agent[mount]), mount)
            self.assertLessEqual(set(reader[mount]), set(writer[mount]), mount)

    def test_carveouts_deny_only(self):
        for path, caps in self.rules_of("superuser-carveouts.hcl").items():
            self.assertEqual(caps, ["deny"], path)


class FileLevel(unittest.TestCase):
    """Errors surfaced through the file API carry the file's name."""

    def test_rejection_names_the_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            broken = os.path.join(tmp, "broken.hcl")
            with open(broken, "w", encoding="utf-8") as fh:
                fh.write('path "x" { capabilities = ["read"]\n')
            with self.assertRaises(HCLError) as ctx:
                parse_file(broken)
            self.assertEqual(ctx.exception.name, "broken.hcl")
            self.assertIn("end of file", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
