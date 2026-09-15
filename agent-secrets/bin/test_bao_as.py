#!/usr/bin/env python3
"""Tests for bin/bao-as.

The wrapper's whole job is keeping a token out of the transcript, so the
suite runs it the way a user does -- a stub `bao` placed first on PATH, a
throwaway BAO_AS_CONFIG_DIR -- and then inspects what actually happened:
the stub's argv log, the child command's environment, the exit code and
stdio that come back. Nothing here contacts a store.

BAO_AS_UNDER_TEST names the script under test, defaulting to the copy
beside this file. Point it at any other copy of this same script (a mirror,
a staged install destination) to prove that copy behaves identically. It is
NOT a promise that every wrapper named bao-as satisfies this contract: the
fleet variant installed on some boxes hard-codes its instances and its
credential layout and will rightly fail most of these fixtures.

    python3 -m unittest discover -s agent-secrets/bin -v

Every credential-shaped fixture is BUILT at runtime from fragments, so this
file never contains a token-shaped literal -- which matters, because the
credential guard is usually installed on the machine editing this file and
it would (correctly) refuse to write one.
"""
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BAO_AS = os.environ.get("BAO_AS_UNDER_TEST") or os.path.join(HERE, "bao-as")

ADDR = "https://bao-fixture.invalid:8200"   # .invalid: never a real store

EX_USAGE, EX_NOPERM, EX_CONFIG = 2, 77, 78


def alnum(n, seed=0):
    """A deterministic, non-repeating alphanumeric body of length n."""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(alphabet[(i * 7 + seed) % len(alphabet)] for i in range(n))


def read_lines(path):
    with open(path) as fh:
        return fh.read().splitlines()


# The stub `bao`, written fresh into a PATH-first directory by setUp. It
# records every argv it is handed (one argument per line, calls separated by
# a marker) and the content of every @file argument it resolves itself,
# answers the AppRole login from a token file, and can be told to fail so
# the wrapper's failure paths get exercised.
STUB_BAO = """\
#!/usr/bin/env bash
printf '=== call ===\\n' >>"$BAO_STUB_ARGV"
for a in "$@"; do printf '%s\\n' "$a" >>"$BAO_STUB_ARGV"; done
for a in "$@"; do
  case "$a" in
    *=@*) printf '%s=%s\\n' "${a%%=*}" "$(cat "${a#*=@}")" >>"$BAO_STUB_RESOLVED" ;;
  esac
done
if [ "${BAO_STUB_FAIL:-0}" != 0 ]; then
  echo "stub bao: login refused" >&2
  exit 1
fi
if [ "${1:-}" = write ] && [ "${3:-}" = auth/approle/login ]; then
  cat "$BAO_STUB_ISSUED_TOKEN"
fi
exit 0
"""


def child(body):
    """A command for bao-as to exec, expressed as bash -c <body>."""
    return ["bash", "-c", body]


def envdump_child(outfile):
    """A child that hands its secret-related environment to a file.

    Only the BAO_*/VAULT_* variables are kept -- the file must be safe to
    assert about, and a failure must print half a dozen fixture lines, not
    the whole inherited environment.
    """
    return child("env | grep -E '^(BAO|VAULT)_' > " + shlex.quote(outfile))


class BaoAsCase(unittest.TestCase):
    """One throwaway config dir, HOME and PATH per test."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bao-as-test-")
        self.conf = os.path.join(self.tmp, "conf")
        self.home = os.path.join(self.tmp, "home")
        self.pathdir = os.path.join(self.tmp, "path")   # stub `bao` lives here
        for d in (self.conf, self.home, self.pathdir):
            os.mkdir(d)
        self.issued = "hvs." + alnum(28, seed=5)
        self.role_id = "role-id-" + alnum(16, seed=1)
        self.secret_id = "secret-id-" + alnum(24, seed=2)
        self.argv_log = os.path.join(self.tmp, "stub-argv.log")
        self.resolved_log = os.path.join(self.tmp, "stub-resolved.log")
        self.token_file = os.path.join(self.tmp, "issued-token")
        with open(self.token_file, "w") as fh:
            fh.write(self.issued)
        with open(os.path.join(self.pathdir, "bao"), "w") as fh:
            fh.write(STUB_BAO)
        os.chmod(os.path.join(self.pathdir, "bao"), 0o700)
        self.add_instance("prod", ADDR)
        self.write_creds("prod")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- fixture helpers ---------------------------------------------------

    def add_instance(self, name, addr):
        with open(os.path.join(self.conf, "instances.conf"), "a") as fh:
            fh.write("%s %s\n" % (name, addr))

    def cred(self, inst, name):
        return os.path.join(self.conf, inst, name)

    def write_creds(self, inst, role_mode=0o600, secret_mode=0o600,
                    with_role=True, with_secret=True):
        os.mkdir(os.path.join(self.conf, inst))
        for name, value, mode, wanted in (
                ("role_id", self.role_id, role_mode, with_role),
                ("secret_id", self.secret_id, secret_mode, with_secret)):
            if not wanted:
                continue
            with open(self.cred(inst, name), "w") as fh:
                fh.write(value + "\n")
            os.chmod(self.cred(inst, name), mode)

    def child_env(self, **over):
        e = dict(os.environ)
        e["BAO_AS_CONFIG_DIR"] = self.conf
        e["HOME"] = self.home
        e["PATH"] = self.pathdir + os.pathsep + e.get("PATH", "")
        e["BAO_STUB_ARGV"] = self.argv_log
        e["BAO_STUB_RESOLVED"] = self.resolved_log
        e["BAO_STUB_ISSUED_TOKEN"] = self.token_file
        for k in ("BAO_TOKEN", "VAULT_TOKEN", "BAO_ADDR", "VAULT_ADDR",
                  "BAO_AS_BIN", "BAO_STUB_FAIL"):
            e.pop(k, None)
        e.update(over)
        return e

    def run_bao_as(self, *args, stdin=b"", **env_over):
        # via bash explicitly: a lost exec bit must not fail the suite for
        # the wrong reason
        return subprocess.run(["bash", BAO_AS, *args], input=stdin,
                              capture_output=True,
                              env=self.child_env(**env_over), timeout=20)

    def stub_was_never_called(self):
        self.assertFalse(os.path.exists(self.argv_log),
                         "the stub CLI was invoked on a path that must fail closed")


class Login(BaoAsCase):
    """What actually reaches the AppRole login."""

    def test_login_argv_carries_atfile_never_values(self):
        proc = self.run_bao_as("prod", *child("exit 0"))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        argv = read_lines(self.argv_log)
        self.assertEqual(argv.count("=== call ==="), 1, argv)
        call = argv[argv.index("=== call ===") + 1:]
        self.assertEqual(call, [
            "write", "-field=token", "auth/approle/login",
            "role_id=@" + self.cred("prod", "role_id"),
            "secret_id=@" + self.cred("prod", "secret_id"),
        ])
        joined = "\n".join(argv)
        self.assertNotIn(self.role_id, joined)
        self.assertNotIn(self.secret_id, joined)

    def test_atfile_arguments_resolve_to_the_credential_files(self):
        # the @file form is not just spelling: the stub reads those very
        # files, so the values demonstrably arrive as files, not argv
        proc = self.run_bao_as("prod", *child("exit 0"))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        resolved = set(read_lines(self.resolved_log))
        self.assertEqual(resolved, {"role_id=" + self.role_id,
                                    "secret_id=" + self.secret_id})

    def test_bao_as_bin_override_selects_the_cli(self):
        # the documented BAO_AS_BIN=vault escape hatch
        other = os.path.join(self.tmp, "other-cli")
        with open(other, "w") as fh:
            fh.write("#!/usr/bin/env bash\necho other-token\n")
        os.chmod(other, 0o700)
        outfile = os.path.join(self.tmp, "child.env")
        proc = self.run_bao_as("prod", *envdump_child(outfile), BAO_AS_BIN=other)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("BAO_TOKEN=other-token", set(read_lines(outfile)))
        self.stub_was_never_called()


class TokenHandling(BaoAsCase):
    """The issued token exists only in the child's environment."""

    def test_issued_token_and_addr_land_in_child_environment(self):
        outfile = os.path.join(self.tmp, "child.env")
        proc = self.run_bao_as("prod", *envdump_child(outfile))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = set(read_lines(outfile))
        for expected in ("BAO_TOKEN=" + self.issued,
                         "VAULT_TOKEN=" + self.issued,
                         "BAO_ADDR=" + ADDR,
                         "VAULT_ADDR=" + ADDR):
            self.assertIn(expected, lines)

    def test_token_is_never_printed(self):
        # the only stdout/stderr is the child's own
        proc = self.run_bao_as("prod", *child("echo child-out; echo child-err >&2"))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, b"child-out\n")
        self.assertEqual(proc.stderr, b"child-err\n")
        self.assertNotIn(self.issued.encode(), proc.stdout + proc.stderr)

    def test_stale_inherited_tokens_do_not_survive(self):
        stale = "hvs." + alnum(28, seed=9)
        outfile = os.path.join(self.tmp, "child.env")
        proc = self.run_bao_as("prod", *envdump_child(outfile),
                               BAO_TOKEN=stale, VAULT_TOKEN=stale)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = set(read_lines(outfile))
        self.assertIn("BAO_TOKEN=" + self.issued, lines)
        self.assertIn("VAULT_TOKEN=" + self.issued, lines)
        self.assertNotIn("BAO_TOKEN=" + stale, lines)
        self.assertNotIn("VAULT_TOKEN=" + stale, lines)

    def test_no_token_helper_file_in_home(self):
        # the reason the wrapper exists: no ~/.vault-token, ever
        proc = self.run_bao_as("prod", *child("exit 0"))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(os.listdir(self.home), [])


class ExecPassthrough(BaoAsCase):
    """The child runs as if invoked directly."""

    def test_exit_code_and_stdio_are_preserved(self):
        proc = self.run_bao_as(
            "prod", *child("echo out-marker; echo err-marker >&2; exit 42"))
        self.assertEqual(proc.returncode, 42)
        self.assertEqual(proc.stdout, b"out-marker\n")
        self.assertEqual(proc.stderr, b"err-marker\n")

    def test_stdin_flows_to_the_child(self):
        proc = self.run_bao_as("prod", *child("cat"),
                               stdin=b"piped-by-reference\n")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, b"piped-by-reference\n")


class FailClosed(BaoAsCase):
    """Every bad state stops before the CLI is invoked or the child runs."""

    def test_missing_role_id_fails_closed(self):
        os.remove(self.cred("prod", "role_id"))
        proc = self.run_bao_as("prod", *child("exit 0"))
        self.assertEqual(proc.returncode, EX_CONFIG)
        self.assertIn(b"missing", proc.stderr)
        self.stub_was_never_called()

    def test_missing_secret_id_fails_closed(self):
        os.remove(self.cred("prod", "secret_id"))
        proc = self.run_bao_as("prod", *child("exit 0"))
        self.assertEqual(proc.returncode, EX_CONFIG)
        self.assertIn(b"missing", proc.stderr)
        self.stub_was_never_called()

    def test_world_readable_role_id_fails_closed(self):
        os.chmod(self.cred("prod", "role_id"), 0o644)
        proc = self.run_bao_as("prod", *child("exit 0"))
        self.assertEqual(proc.returncode, EX_CONFIG)
        self.assertIn(b"group/other-readable", proc.stderr)
        self.stub_was_never_called()

    def test_world_readable_secret_id_fails_closed(self):
        os.chmod(self.cred("prod", "secret_id"), 0o644)
        proc = self.run_bao_as("prod", *child("exit 0"))
        self.assertEqual(proc.returncode, EX_CONFIG)
        self.assertIn(b"group/other-readable", proc.stderr)
        self.stub_was_never_called()

    def test_group_readable_role_id_fails_closed(self):
        # 0600 is the contract: group-readable is not 0600 either
        os.chmod(self.cred("prod", "role_id"), 0o640)
        proc = self.run_bao_as("prod", *child("exit 0"))
        self.assertEqual(proc.returncode, EX_CONFIG)
        self.assertIn(b"group/other-readable", proc.stderr)
        self.stub_was_never_called()

    def test_unknown_instance_fails_closed(self):
        proc = self.run_bao_as("nope", *child("exit 0"))
        self.assertEqual(proc.returncode, EX_CONFIG)
        self.assertIn(b"unknown instance", proc.stderr)
        self.stub_was_never_called()

    def test_missing_instance_table_fails_closed(self):
        empty = os.path.join(self.tmp, "empty-conf")
        os.mkdir(empty)
        proc = self.run_bao_as("prod", *child("exit 0"),
                               BAO_AS_CONFIG_DIR=empty)
        self.assertEqual(proc.returncode, EX_CONFIG)
        self.assertIn(b"no instance table", proc.stderr)
        self.stub_was_never_called()

    def test_failed_login_fails_closed(self):
        marker = os.path.join(self.tmp, "child-ran")
        proc = self.run_bao_as("prod", *child("touch " + shlex.quote(marker)),
                               BAO_STUB_FAIL="1")
        self.assertEqual(proc.returncode, EX_NOPERM)
        self.assertIn(b"login failed", proc.stderr)
        self.assertTrue(os.path.exists(self.argv_log))   # the CLI was tried
        self.assertFalse(os.path.exists(marker), "child ran despite failed login")


class InstanceTable(BaoAsCase):
    """The table itself, and the front door."""

    def test_list_prints_names_ignoring_comments(self):
        with open(os.path.join(self.conf, "instances.conf"), "a") as fh:
            fh.write("# a comment line\n\n   staging https://staging.invalid:8200\n")
        proc = self.run_bao_as("--list")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.decode().split(), ["prod", "staging"])

    def test_no_command_is_a_usage_error(self):
        proc = self.run_bao_as("prod")
        self.assertEqual(proc.returncode, EX_USAGE)
        self.assertIn(b"usage:", proc.stderr)


if __name__ == "__main__":
    unittest.main()
