#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0

import ast
import contextlib
import io
import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
import urllib.error


def rehearsal_types():
    script = Path(__file__).with_name("e2e-openbao.sh")
    python = script.read_text(encoding="utf-8").split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    tree = ast.parse(python, filename=str(script))
    entrypoint = tree.body.pop()
    if not isinstance(entrypoint, ast.Try):
        raise AssertionError("expected rehearsal entry point at the end of the script")
    scope = {}
    exec(compile(tree, filename=str(script), mode="exec"), scope)
    return scope


class Response(io.BytesIO):
    status = 200


class SyntheticOpenBao:
    def __init__(self, sealed=False, health=None, redirect=False):
        self.sealed = sealed
        self.health = iter(health or [])
        self.redirect = redirect
        self.calls = []

    def open(self, request, *, timeout):
        path = request.full_url.split("/v1/", 1)[1]
        self.calls.append(path)
        if path == "sys/health":
            status = next(self.health, 200)
            if status != 200:
                raise urllib.error.HTTPError(request.full_url, status, "standby", {}, None)
            return Response(b'{"standby":false}')
        if path == "sys/mounts/scratch":
            if self.redirect:
                raise urllib.error.HTTPError(request.full_url, 307, "redirect",
                                             {"Location": "https://arbitrary-credential.invalid/"}, None)
            response = Response(b"")
            response.status = 204
            return response
        if path == "scratch/data/probe":
            return Response(b'{"data":{"data":{"value":"probe"}}}')
        if request.get_method() == "PUT" and request.full_url.endswith("/v1/sys/unseal"):
            if timeout < 3:
                raise TimeoutError("synthetic unseal takes three seconds")
            if timeout > 60:
                raise AssertionError("unseal request exceeded its budget")
            if json.loads(request.data) != {"key": "synthetic-share", "migrate": True}:
                raise AssertionError("unexpected unseal request")
            return Response(json.dumps({"sealed": self.sealed, "migration": True}).encode())
        if request.get_method() != "GET" or timeout != 2:
            raise AssertionError("unexpected poll or poll timeout")
        return Response(b'{"type":"static","initialized":true,"sealed":false,"migration":false,"recovery_seal":true}')


class RunningChild:
    def poll(self):
        return None


class RehearsalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scope = rehearsal_types()
        cls.rehearsal_type, cls.failure = cls.scope["Rehearsal"], cls.scope["Failure"]

    def rehearsal(self, sealed=False):
        rehearsal = self.rehearsal_type.__new__(self.rehearsal_type)
        rehearsal.base = "https://127.0.0.1"
        rehearsal.http = SyntheticOpenBao(sealed)
        rehearsal.stage = "initialize under exoscale"
        rehearsal.reset_diagnostics()
        return rehearsal

    def test_slow_unseal_waits_for_migration_via_status(self):
        rehearsal = self.rehearsal()
        rehearsal.unseal("synthetic-share", migrate=True)
        rehearsal.status(RunningChild(), "static", sealed=False)

    def test_sealed_reply_still_fails(self):
        with self.assertRaisesRegex(self.failure, "unseal did not complete"):
            self.rehearsal(sealed=True).unseal("synthetic-share", migrate=True)

    def test_waits_for_active_after_unseal_and_before_each_probe_call(self):
        rehearsal = self.rehearsal()
        rehearsal.http = SyntheticOpenBao(health=[429, 200, 200] * 4)
        child = RunningChild()
        with patch.object(self.scope["time"], "sleep"):
            rehearsal.status(child, "static", sealed=False)
            rehearsal.write_probe(child, "synthetic-token", "probe")
            rehearsal.read_probe(child, "synthetic-token", "probe")
        self.assertEqual(rehearsal.http.calls, [
            "sys/seal-status", "sys/health", "sys/health", "sys/health",
            "sys/health", "sys/health", "sys/health", "sys/mounts/scratch",
            "sys/health", "sys/health", "sys/health", "scratch/data/probe",
            "sys/health", "sys/health", "sys/health", "scratch/data/probe",
        ])

    def test_waits_through_a_transient_active_response(self):
        rehearsal = self.rehearsal()
        rehearsal.http = SyntheticOpenBao(health=[200, 429, 200, 200])
        with patch.object(self.scope["time"], "sleep") as sleep:
            rehearsal.active(RunningChild(), self.scope["time"].monotonic() + 1)
        self.assertEqual(rehearsal.http.calls, ["sys/health"] * 4)
        self.assertEqual(sleep.call_args_list[0].args, (0.3,))
        self.assertEqual(sleep.call_args_list[-1].args, (0.3,))

    def test_unprefixed_seal_diagnostic_survives_in_report(self):
        for line, diagnostic, refused in (
            (b'Error configuring seal "exoscale": Exoscale KMS configure: '
             b'HTTP 400 (#/kms-key/not-found)\n',
             "Exoscale KMS configure: HTTP 400 (#/kms-key/not-found)", False),
            (b'Error configuring seal "exoscale": Exoscale KMS configure: HTTP 403\n',
             "Exoscale KMS configure: HTTP 403", True),
            (b'Error configuring seal "exoscale": Exoscale KMS configure: HTTP 403 (unclassified)\n',
             "Exoscale KMS configure: HTTP 403 (unclassified)", True),
            (b'Error configuring seal "exoscale": Exoscale KMS configure: HTTP 403 (#/private/do-not-print)\n',
             "seal configuration failed", False),
        ):
            with self.subTest(diagnostic=diagnostic):
                rehearsal = self.rehearsal()
                rehearsal.bao, rehearsal.config, rehearsal.env = "synthetic-bao", "synthetic.hcl", {}
                later_logs = b"[WARN] raw-log-do-not-print\n" * 10
                child = Mock(stdout=io.BytesIO(line + later_logs), pid=12345)
                with patch.object(self.scope["subprocess"], "Popen", return_value=child), patch.object(
                    self.scope["os"], "killpg"
                ), rehearsal.server() as (_, refused_event, reader):
                    reader.join(timeout=2)
                    self.assertFalse(reader.is_alive())
                    self.assertEqual(refused_event.is_set(), refused)
                transcript = io.StringIO()
                with contextlib.redirect_stderr(transcript):
                    rehearsal.report("OpenBao exited before the expected seal status")
                self.assertIn(f"server [ERROR] {diagnostic}\n", transcript.getvalue())
                self.assertIn("seal configuration error logged", transcript.getvalue())
                self.assertNotIn("do-not-print", transcript.getvalue())

    def test_openbao_272_config_omits_unsupported_field(self):
        rehearsal = self.rehearsal()
        rehearsal.port, rehearsal.cluster = 8200, 8201
        rehearsal.version, rehearsal.digest = "v0.2.0-rc.1", "synthetic-digest"
        with tempfile.TemporaryDirectory() as path:
            rehearsal.scratch = Path(path)
            rehearsal.config = rehearsal.scratch / "test.hcl"
            for plugin in (True, False):
                with self.subTest(plugin=plugin):
                    rehearsal.configure("raft", "", plugin=plugin)
                    hcl = rehearsal.config.read_text()
                    self.assertNotIn("disable_mlock", hcl)
                    self.assertIn('storage "raft"', hcl)
                    self.assertEqual('plugin "kms" "exoscale"' in hcl, plugin)

    def test_redirect_is_terminal_and_failure_report_is_safe(self):
        rehearsal = self.rehearsal()
        rehearsal.http = SyntheticOpenBao(redirect=True)
        transcript = io.StringIO()
        scratch = None

        def make_rehearsal(_root, _bao, _key, _zone, _key_file, _secret_file, _binary, path):
            nonlocal scratch
            scratch = path
            self.assertTrue(scratch.is_dir())
            return rehearsal

        def fail_during_write():
            child = RunningChild()
            rehearsal.status(child, "static", sealed=False)
            for line in (
                b"2026-01-01T00:00:00.000Z [INFO] arbitrary-info",
                b"2026-01-01T00:00:00.000Z [WARN] core: no known leader: arbitrary-token",
                b"[ERROR] arbitrary-secret credential=do-not-print",
                b'[ERROR] core: Error configuring seal "exoscale": '
                b'Exoscale KMS configure: HTTP 400 (#/kms-key/not-found) token=do-not-print',
                b"[WARN] core: Exoscale KMS decrypt: HTTP 400 (#/private/do-not-print)",
            ):
                safe = self.scope["safe_server_line"](line)
                if safe:
                    rehearsal.server_diagnostics.append(safe)
            rehearsal.write_probe(child, "synthetic-token", "probe")

        with patch.dict(self.scope, Rehearsal=make_rehearsal), patch.object(
            rehearsal, "auto_unseal", fail_during_write
        ), contextlib.redirect_stderr(transcript):
            self.assertEqual(self.scope["rehearse"](None, None, None, None, [None, None], None), 1)
        self.assertFalse(scratch.exists())
        self.assertEqual(rehearsal.http.calls[-1], "sys/mounts/scratch")
        self.assertNotIn("scratch/data/probe", rehearsal.http.calls)
        output = transcript.getvalue()
        self.assertIn("FAIL initialize under exoscale", output)
        self.assertIn("HTTP status 307", output)
        self.assertIn("server [WARN] Raft leader unavailable", output)
        self.assertIn("server [ERROR] [message redacted]", output)
        self.assertIn("server [ERROR] Exoscale KMS configure: HTTP 400 (#/kms-key/not-found)", output)
        self.assertIn("server [WARN] [message redacted]", output)
        seal = next(line for line in output.splitlines() if line.startswith("seal-status "))
        self.assertEqual(json.loads(seal.removeprefix("seal-status ")), {
            "type": "static", "sealed": False, "initialized": True,
            "migration": False, "recovery_seal": True,
        })
        for sensitive in ("arbitrary", "do-not-print", "synthetic-token"):
            self.assertNotIn(sensitive, output)
        policy = self.scope["NoRedirect"]()
        self.assertIsNone(policy.redirect_request(None, None, 307, "", {}, "https://elsewhere.invalid"))


if __name__ == "__main__":
    unittest.main()
