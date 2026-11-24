#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Rehearse the OpenBao 2.7.2 seal workflow against an enabled test key.

set -eu
if [[ $# -lt 5 || $# -gt 6 ]]; then
    printf 'Usage: %s OPENBAO KEY_UUID ZONE API_KEY_FILE API_SECRET_FILE [PLUGIN_BINARY]\n' "$0" >&2
    exit 2
fi
source_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
exec python3 -I - "$source_root" "$@" <<'PY'
from collections import deque
import contextlib
import hashlib
import json
import os
import pathlib
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request


class Failure(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def require(ok, message):
    if not ok:
        raise Failure(message)


def executable(value):
    path = shutil.which(value)
    require(path is not None, "required executable unavailable")
    return str(pathlib.Path(path).resolve())


def run(argv, *, cwd=None, env=None, capture=False):
    result = subprocess.run(argv, cwd=cwd, env=env, stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, check=False, timeout=180)
    require(result.returncode == 0, "a required local command failed")
    return result.stdout


def hcl(value):
    return json.dumps(str(value).replace("${", "$${").replace("%{", "%%{"), ensure_ascii=False)


def local_ports():
    with socket.socket() as one, socket.socket() as two:
        one.bind(("127.0.0.1", 0))
        two.bind(("127.0.0.1", 0))
        return one.getsockname()[1], two.getsockname()[1]


def safe_seal_status(status):
    seal = status.get("type")
    fields = {"type": seal if seal in ("shamir", "exoscalekms", "static") else None}
    for name in ("sealed", "initialized", "migration", "recovery_seal"):
        value = status.get(name)
        fields[name] = value if type(value) is bool else None
    return fields


def seal_error_line(line):
    return re.match(rb'^\s*Error configuring seal (?:"exoscale"|exoscale):', line) is not None


def safe_server_line(line):
    # Render known events as fixed strings. Even a token with an unknown
    # format in a message, logger name or field cannot reach the report.
    match = re.match(rb"^\s*(?:[\dT:.+Z-]+\s+)?\[(WARN|ERROR)\]\s", line)
    if match:
        level = match[1].decode("ascii")
    elif seal_error_line(line):
        level = "ERROR"
    else:
        return None
    diagnostic = re.search(
        rb"Exoscale KMS (configure|encrypt|decrypt): HTTP ([1-5][0-9]{2})"
        rb"(?: \((#/crypto/invalid-ciphertext|#/kms-key/key-disabled|"
        rb"#/kms-key/multi-zone/key-is-not-multi-zone|#/kms-key/not-found|"
        rb"#/http-problem-types/request-invalid-parameters|#/kms-key/manual-rotation-limit|"
        rb"#/kms-key/multi-zone/operation-not-allowed-on-a-replica|unclassified)\)|(?=\s*$))",
        line,
    )
    if diagnostic:
        operation, status = (value.decode("ascii") for value in diagnostic.groups()[:2])
        problem = diagnostic[3]
        suffix = f" ({problem.decode('ascii')})" if problem else ""
        return f"[{level}] Exoscale KMS {operation}: HTTP {status}{suffix}"
    for fragment, event in (
        (b"Error configuring seal", "seal configuration failed"),
        (b"failed to unseal", "unseal failed"),
        (b"failed to contact quorum", "Raft quorum unavailable"),
        (b"failed to acquire lock", "Raft lock acquisition failed"),
        (b"no known leader", "Raft leader unavailable"),
    ):
        if fragment in line:
            return f"[{level}] {event}"
    return f"[{level}] [message redacted]"


class Rehearsal:
    def __init__(self, root, bao, key, zone, key_file, secret_file, binary, scratch):
        self.bao, self.key, self.zone = bao, key, zone
        self.key_file, self.secret_file = key_file, secret_file
        self.scratch = scratch
        self.stage = "prepare"
        self.reset_diagnostics()
        self.config = scratch / "server.hcl"
        self.wrong_secret = scratch / "refused-fixture"
        self.wrong_secret.write_bytes(secrets.token_hex(32).encode())
        self.static_key = scratch / "static.key"
        self.static_key.write_bytes(secrets.token_bytes(32))
        self.version = "v0.2.0-rc.3"
        (scratch / "plugins").mkdir()
        plugin = scratch / "plugins/openbao-plugin-kms-exoscale"
        if binary:
            with open(executable(binary), "rb") as source:
                with os.fdopen(os.open(plugin, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700), "wb") as dest:
                    shutil.copyfileobj(source, dest)
        else:
            os.environ.update(CGO_ENABLED="0", GOTOOLCHAIN="local")
            run([executable("go"), "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
                 "-ldflags=-s -w", "-o", str(plugin), "./cmd/openbao-plugin-kms-exoscale"], cwd=root)
        with plugin.open("rb") as file:
            self.digest = hashlib.file_digest(file, "sha256").hexdigest()
        run([executable("openssl"), "req", "-x509", "-newkey", "ec", "-pkeyopt",
             "ec_paramgen_curve:prime256v1", "-nodes", "-days", "1", "-subj",
             "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
             "-keyout", str(scratch / "tls.key"), "-out", str(scratch / "tls.crt")])
        tls = ssl.create_default_context(cafile=str(scratch / "tls.crt"))
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                NoRedirect(), urllib.request.HTTPSHandler(context=tls))
        self.port, self.cluster = local_ports()
        self.base = f"https://127.0.0.1:{self.port}"
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(("VAULT_", "BAO_", "EXOSCALE_API_", "EXOSCALEKMS_"))}
        self.env.update(NO_PROXY="127.0.0.1", no_proxy="127.0.0.1")
        self.env.update(BAO_ADDR=self.base, BAO_CACERT=str(scratch / "tls.crt"))

    def exoscale(self, *, disabled=False, wrong=False):
        secret = self.wrong_secret if wrong else self.secret_file
        flag = '  disabled = "true"\n' if disabled else ""
        return f'''seal "exoscale" {{
  key_id = {hcl(self.key)}
  zone = {hcl(self.zone)}
  endpoint = "https://api-{self.zone}.exoscale.com/v2"
  api_key = {hcl("file://" + str(self.key_file))}
  api_secret = {hcl("file://" + str(secret))}
{flag}}}
'''

    def static(self, *, disabled=False):
        flag = '  disabled = "true"\n' if disabled else ""
        return f'''seal "static" {{
  current_key_id = "static-rehearsal-key"
  current_key = {hcl("file://" + str(self.static_key))}
{flag}}}
'''

    def configure(self, store, seals, *, plugin):
        raft = self.scratch / store
        raft.mkdir(exist_ok=True)
        registration = ""
        if plugin:
            registration = f'''plugin_directory = {hcl(str(self.scratch / "plugins"))}
plugin "kms" "exoscale" {{
  command = "openbao-plugin-kms-exoscale"
  version = "{self.version}"
  sha256sum = "{self.digest}"
}}
'''
        self.config.write_text(f'''api_addr = "{self.base}"
cluster_addr = "https://127.0.0.1:{self.cluster}"
storage "raft" {{
  path = {hcl(str(raft))}
  node_id = "rehearsal-node"
}}
listener "tcp" {{
  address = "127.0.0.1:{self.port}"
  tls_cert_file = {hcl(str(self.scratch / "tls.crt"))}
  tls_key_file = {hcl(str(self.scratch / "tls.key"))}
}}
{registration}{seals}''', encoding="utf-8")

    def reset_diagnostics(self):
        self.last_http = None
        self.last_seal = safe_seal_status({})
        self.server_diagnostics = deque(maxlen=8)
        self.seal_diagnostic = None

    def report(self, reason):
        print(f"FAIL {self.stage}: {reason}", file=sys.stderr)
        print("seal-status " + json.dumps(self.last_seal), file=sys.stderr)
        print(f"HTTP status {self.last_http if self.last_http is not None else 'unavailable'}", file=sys.stderr)
        if self.seal_diagnostic:
            print("seal configuration error logged", file=sys.stderr)
            print(f"server {self.seal_diagnostic}", file=sys.stderr)
        for line in self.server_diagnostics:
            print(f"server {line}", file=sys.stderr)

    def request(self, method, path, body=None, token=None, *, timeout=2):
        headers = {"Content-Type": "application/json"}
        if token is not None:
            headers["X-Vault-Token"] = token
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + "/v1/" + path, data=data, headers=headers, method=method)
        self.last_http = None
        try:
            with self.http.open(req, timeout=timeout) as resp:
                self.last_http = resp.status
                if resp.status == 204:
                    return {}
                return json.load(resp)
        except urllib.error.HTTPError as error:
            self.last_http = error.code
            error.close()
            raise Failure("OpenBao returned an unexpected HTTP status") from None
        except OSError:
            raise Failure("OpenBao did not answer the request") from None

    @contextlib.contextmanager
    def server(self):
        self.reset_diagnostics()
        child = subprocess.Popen([self.bao, "server", f"-config={self.config}"], env=self.env,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        refused = threading.Event()

        def scan():
            with child.stdout:
                for line in child.stdout:
                    diagnostic = safe_server_line(line)
                    if seal_error_line(line) or (diagnostic and (
                        b'Error configuring seal "exoscale":' in line or b'Error configuring seal exoscale:' in line
                    )):
                        self.seal_diagnostic = diagnostic
                        if diagnostic in ("[ERROR] Exoscale KMS configure: HTTP 403",
                                          "[ERROR] Exoscale KMS configure: HTTP 403 (unclassified)"):
                            refused.set()
                    elif diagnostic:
                        self.server_diagnostics.append(diagnostic)

        reader = threading.Thread(target=scan, daemon=True)
        reader.start()
        try:
            yield child, refused, reader
        finally:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(child.pid, signal.SIGKILL)
                child.wait()
            reader.join(timeout=10)

    def status(self, child, seal, *, sealed, initialized=True, migration=False):
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            require(child.poll() is None, "OpenBao exited before the expected seal status")
            try:
                status = self.request("GET", "sys/seal-status")
            except Failure:
                time.sleep(0.2)
                continue
            self.last_seal = safe_seal_status(status)
            if (status.get("type"), status.get("sealed"), status.get("initialized"),
                    bool(status.get("migration"))) == (seal, sealed, initialized, migration):
                require(bool(status.get("recovery_seal")) == (seal != "shamir"), "unexpected recovery seal status")
                if not sealed:
                    self.active(child, deadline)
                return
            time.sleep(0.2)
        raise Failure("OpenBao did not reach the expected seal status")

    def active(self, child, deadline):
        # OpenBao may already be unsealed while the local Raft node is a
        # standby. Recheck health after the node has had time to step down
        # and resume during the observed post-unseal setup cycles.
        while time.monotonic() < deadline:
            require(child.poll() is None, "OpenBao exited before becoming active")
            try:
                self.request("GET", "sys/health")
                if self.last_http == 200:
                    time.sleep(0.3)
                    if time.monotonic() >= deadline:
                        break
                    self.request("GET", "sys/health")
                    if self.last_http == 200:
                        return
            except Failure:
                pass
            time.sleep(0.2)
        raise Failure("OpenBao did not become active")

    def init(self, recovery):
        self.last_http = None # The init CLI does not expose HTTP status.
        options = ["-recovery-shares=1", "-recovery-threshold=1"] if recovery else ["-key-shares=1", "-key-threshold=1"]
        init = run([self.bao, "operator", "init", "-format=json", *options], env=self.env, capture=True)
        data = json.loads(init)
        share = data.get("recovery_keys_b64" if recovery else "unseal_keys_b64")
        if recovery:
            require(not data.get("unseal_keys_b64"), "auto-unseal initialization returned unseal shares")
        require(isinstance(share, list) and len(share) == 1 and data.get("root_token"),
                "initialization did not return one share and a root token")
        return share[0], data["root_token"]

    def unseal(self, share, migrate):
        status = self.request("PUT", "sys/unseal", {"key": share, "migrate": migrate}, timeout=60)
        self.last_seal = safe_seal_status(status)
        require(status.get("sealed") is False, "unseal did not complete")

    def write_probe(self, child, token, value):
        self.active(child, time.monotonic() + 35)
        self.request("POST", "sys/mounts/scratch", {"type": "kv", "options": {"version": "2"}}, token)
        self.active(child, time.monotonic() + 35)
        self.request("POST", "scratch/data/probe", {"data": {"value": value}}, token)

    def read_probe(self, child, token, value):
        self.active(child, time.monotonic() + 35)
        result = self.request("GET", "scratch/data/probe", token=token)
        require(result.get("data", {}).get("data", {}).get("value") == value, "probe readback differed")

    def auto_unseal(self):
        self.stage = "initialize under exoscale"
        storage = "auto-raft"
        self.configure(storage, self.exoscale(), plugin=True)
        value = secrets.token_hex(24)
        with self.server() as (child, _, _):
            self.status(child, "exoscalekms", sealed=True, initialized=False)
            _, token = self.init(recovery=True)
            self.status(child, "exoscalekms", sealed=False)
            self.write_probe(child, token, value)
        print("PASS initialization under exoscale", flush=True)
        self.stage = "restart under exoscale"
        with self.server() as (child, _, _):
            self.status(child, "exoscalekms", sealed=False)
            self.read_probe(child, token, value)
        print("PASS restart auto-unsealed and read the probe", flush=True)
        self.stage = "restart with refused credential"
        self.configure(storage, self.exoscale(wrong=True), plugin=True)
        with self.server() as (child, refused, reader):
            try:
                rc = child.wait(timeout=35)
            except subprocess.TimeoutExpired:
                raise Failure("OpenBao started or stalled with the refused credential") from None
            reader.join(timeout=5)
            if refused.is_set():
                self.last_http = 403
            require(rc != 0 and refused.is_set(), "expected startup refusal with HTTP 403")
        print("PASS wrong credential refused with HTTP 403", flush=True)
        print(f"server {self.seal_diagnostic}", flush=True)
        self.stage = "restart with restored credential"
        self.configure(storage, self.exoscale(), plugin=True)
        with self.server() as (child, _, _):
            self.status(child, "exoscalekms", sealed=False)
            self.read_probe(child, token, value)
        print("PASS restored credential auto-unsealed and read the probe", flush=True)

    def migrations(self):
        self.stage = "initialize under Shamir"
        storage = "migration-raft"
        self.configure(storage, "", plugin=False)
        value = secrets.token_hex(24)
        with self.server() as (child, _, _):
            self.status(child, "shamir", sealed=True, initialized=False)
            share, token = self.init(recovery=False)
            self.unseal(share, migrate=False)
            self.status(child, "shamir", sealed=False)
            self.write_probe(child, token, value)
        for before, after, transition, final, have_plugin, final_plugin in [
            ("shamir", "exoscalekms", self.exoscale(), self.exoscale(), True, True),
            ("exoscalekms", "static", self.exoscale(disabled=True) + self.static(), self.static(), True, False),
            ("static", "exoscalekms", self.static(disabled=True) + self.exoscale(), self.exoscale(), True, True),
            ("exoscalekms", "shamir", self.exoscale(disabled=True), "", True, False),
        ]:
            self.stage = f"migrate {before} -> {after}"
            self.configure(storage, transition, plugin=have_plugin)
            with self.server() as (child, _, _):
                self.status(child, after, sealed=True, migration=True)
                self.unseal(share, migrate=True)
                self.status(child, after, sealed=False)
                self.read_probe(child, token, value)
            self.stage = f"restart after migration {before} -> {after}"
            self.configure(storage, final, plugin=final_plugin)
            with self.server() as (child, _, _):
                if after == "shamir":
                    self.status(child, after, sealed=True)
                    self.unseal(share, migrate=False)
                self.status(child, after, sealed=False)
                self.read_probe(child, token, value)
            print(f"PASS migration {before} -> {after}, clean restart and probe readback", flush=True)


def interrupted(_signum, _frame):
    raise Failure("rehearsal interrupted")


def rehearse(root, bao, key, zone, credentials, binary):
    with tempfile.TemporaryDirectory(prefix="openbao-e2e-") as tmp:
        rehearsal = Rehearsal(root, bao, key, zone, *credentials, binary, pathlib.Path(tmp))
        try:
            rehearsal.auto_unseal()
            rehearsal.migrations()
        except Failure as error:
            rehearsal.report(str(error))
            return 1
        except (KeyboardInterrupt, OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, AttributeError):
            rehearsal.report("local command, response, or connection failed")
            return 1
    return 0


def main():
    root, bao, key, zone, key_file, secret_file, *plugin = sys.argv[1:]
    require(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", key), "invalid key UUID")
    require(re.fullmatch(r"[a-z]{2}-[a-z]{2,3}-[0-9]{1,3}", zone), "invalid zone")
    credentials = [pathlib.Path(value).resolve(strict=True) for value in (key_file, secret_file)]
    require(all(path.is_file() for path in credentials), "credential paths must be regular files")
    bao = executable(bao)
    require(re.search(rb"\bv2\.7\.2\b", run([bao, "version"], capture=True)), "expected OpenBao 2.7.2")
    os.umask(0o077)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    return rehearse(root, bao, key, zone, credentials, plugin[0] if plugin else None)


try:
    sys.exit(main())
except Failure as error:
    print(f"FAIL prepare: {error}", file=sys.stderr)
    sys.exit(1)
except (KeyboardInterrupt, OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError):
    print("FAIL prepare: local command, response, or connection failed", file=sys.stderr)
    sys.exit(1)
PY
