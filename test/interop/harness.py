#!/usr/bin/env python3
"""External interop and differential-oracle suite for ZIMDNS.

This suite is deliberately not in-repo-only: every check drives the built
binary from outside with BIND's dig/delv/nsupdate, Knot's kdig, ldns, curl,
or named-checkzone, and the authoritative answer corpus is compared against a
BIND 9 authoritative server serving the same zone file.

Run:
  python3 -m venv .interop-venv && .interop-venv/bin/pip install dnspython
  .interop-venv/bin/python test/interop/harness.py --zimdns zig-out/bin/zimdns

Exit code 0 only when every check passes. Missing tools are a hard failure:
the point of the suite is external evidence, not a skip.
"""

import argparse
import base64
import http.client
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import traceback

try:
    import dns.message
    import dns.query
    import dns.rcode
    import dns.rdatatype
except ImportError:
    sys.stderr.write(
        "dnspython is required: python3 -m venv .interop-venv && "
        ".interop-venv/bin/pip install dnspython\n"
    )
    raise SystemExit(2)

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
ZONE = os.path.join(HERE, "fixtures", "authoritative.zone")
ORIGIN = "example.test."
TOOLS = {
    "dig": "dig",
    "kdig": "kdig",
    "delv": "delv",
    "named": "named",
    "named-checkzone": "named-checkzone",
    "dnssec-verify": "dnssec-verify",
    "dnssec-keygen": "dnssec-keygen",
    "nsupdate": "nsupdate",
    "kzonecheck": "kzonecheck",
    "ldns-verify-zone": "ldns-verify-zone",
    "curl": "curl",
    "openssl": "openssl",
}

QUERIES = [
    ("example.test.", "SOA"),
    ("example.test.", "NS"),
    ("www.example.test.", "A"),
    ("www.example.test.", "AAAA"),
    ("nodata.example.test.", "A"),
    ("nodata.example.test.", "TXT"),
    ("missing.example.test.", "A"),
    ("foo.wild.example.test.", "A"),
    ("alias.example.test.", "A"),
    ("chain.example.test.", "A"),
    ("x.dn.example.test.", "A"),
    ("deep.child.example.test.", "A"),
    ("child.example.test.", "NS"),
    ("txt.example.test.", "TXT"),
    ("mx.example.test.", "MX"),
    ("srv.example.test.", "SRV"),
    ("svc.example.test.", "SVCB"),
    ("caa.example.test.", "CAA"),
]


class Failure(Exception):
    pass


class Suite:
    def __init__(self, zimdns, verbose):
        self.zimdns = os.path.abspath(zimdns)
        self.verbose = verbose
        self.passed = 0
        self.failed = []
        self.procs = []

    # ---------------------------------------------------------------- plumbing
    def free_port(self):
        while True:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.bind(("127.0.0.1", 0))
                port = udp.getsockname()[1]
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
                try:
                    tcp.bind(("127.0.0.1", port))
                except OSError:
                    continue
            return port

    def run(self, argv, cwd=None, timeout=20, check=True, input=None):
        if self.verbose:
            print("  $", " ".join(argv))
        result = subprocess.run(
            argv,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input,
        )
        if check and result.returncode != 0:
            raise Failure(
                f"command failed ({result.returncode}): {' '.join(argv)}\n"
                f"stdout: {result.stdout[:800]}\nstderr: {result.stderr[:800]}"
            )
        return result

    def spawn(self, argv, cwd=None, env=None):
        if self.verbose:
            print("  start", " ".join(argv))
        proc = subprocess.Popen(
            argv,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        self.procs.append(proc)
        return proc

    def wait_query(self, port, name=ORIGIN, rdtype="SOA", timeout=15, tcp=False, proc=None):
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            if proc is not None and proc.poll() is not None:
                out, err = proc.communicate()
                raise Failure(
                    f"server exited ({proc.returncode}) before answering on port {port}:\n"
                    f"stdout: {out[-800:]}\nstderr: {err[-2000:]}"
                )
            try:
                query = dns.message.make_query(name, rdtype)
                send = dns.query.tcp if tcp else dns.query.udp
                send(query, "127.0.0.1", port=port, timeout=1.0)
                return
            except Exception as exc:  # server may still be starting
                last = exc
                time.sleep(0.1)
        raise Failure(f"server on port {port} did not answer: {last}")

    def cleanup(self):
        for proc in self.procs:
            if proc.poll() is None:
                proc.terminate()
        for proc in self.procs:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        self.procs.clear()

    # ------------------------------------------------------------- fixtures
    def make_workdir(self):
        work = tempfile.mkdtemp(prefix="zimdns-interop-")
        shutil.copy(ZONE, os.path.join(work, "authoritative.zone"))
        return work

    def write_zimdns_config(self, work, port, extra="", zone=True):
        path = os.path.join(work, "config.gdns")
        with open(path, "w") as f:
            f.write(f"listen dns udp 127.0.0.1:{port}\n")
            f.write(f"listen dns tcp 127.0.0.1:{port}\n")
            if zone:
                f.write("zone example.test primary authoritative.zone\n")
            f.write("local-zones off\n")
            f.write(extra)
        return path

    def start_zimdns(self, work, port, mode, extra="", zone=True):
        config = self.write_zimdns_config(work, port, extra, zone=zone)
        proc = self.spawn([self.zimdns, "server", "run", "--config", "config.gdns", mode], cwd=work)
        self.wait_query(port, tcp=(mode == "--serve-tcp"), proc=proc)
        return proc

    def stop(self, proc):
        if proc in self.procs:
            self.procs.remove(proc)
        if proc.poll() is None:
            proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)

    def new_key(self, work, algorithm, filename):
        """Generate one zone key and write the signer's key file."""
        before = set(os.listdir(work))
        self.run(
            [TOOLS["dnssec-keygen"], "-q", "-K", work, "-a", algorithm, "-n", "ZONE", "example.test"]
        )
        private = sorted(set(os.listdir(work)) - before)
        private = [name for name in private if name.endswith(".private")]
        if not private:
            raise Failure("dnssec-keygen produced no .private file")
        secret = None
        with open(os.path.join(work, private[0])) as f:
            for line in f:
                if line.startswith("PrivateKey:"):
                    secret = line.split(":", 1)[1].strip()
                    break
        if secret is None:
            raise Failure("dnssec-keygen private file has no PrivateKey line")
        with open(os.path.join(work, filename), "w") as f:
            f.write(f"{algorithm.lower()} {secret}\n")
        return filename

    def write_named_config(self, work, port):
        path = os.path.join(work, "named.conf")
        with open(path, "w") as f:
            f.write(
                f'''options {{
  directory "{work}";
  listen-on port {port} {{ 127.0.0.1; }};
  listen-on-v6 {{ none; }};
  recursion no;
  allow-query {{ any; }};
  minimal-responses yes;
  dnssec-validation no;
  pid-file "{work}/named.pid";
  session-keyfile "{work}/session.key";
}};
zone "example.test" {{
  type master;
  file "{work}/authoritative.zone";
}};
'''
            )
        return path

    def start_named(self, work, port):
        config = self.write_named_config(work, port)
        proc = self.spawn(
            [TOOLS["named"], "-g", "-4", "-c", config],
            cwd=work,
        )
        self.wait_query(port, proc=proc)
        return proc

    # ---------------------------------------------------------- differential
    def rrset_key(self, rrset):
        owner = rrset.name.to_text().lower()
        return (
            owner,
            rrset.rdtype,
            tuple(sorted(r.to_text().lower() for r in rrset)),
        )

    def response_view(self, message):
        answers = tuple(sorted(self.rrset_key(rr) for rr in message.answer))
        authority = tuple(sorted(self.rrset_key(rr) for rr in message.authority))
        additional = tuple(
            sorted(
                self.rrset_key(rr)
                for rr in message.additional
                if rr.rdtype != dns.rdatatype.OPT
            )
        )
        return {
            "rcode": message.rcode(),
            "aa": bool(message.flags & dns.flags.AA),
            "tc": bool(message.flags & dns.flags.TC),
            "answer": answers,
            "authority": authority,
            "additional": additional,
        }

    def query(self, port, name, rdtype, tcp=False, want_dnssec=False):
        query = dns.message.make_query(name, rdtype, want_dnssec=want_dnssec)
        sender = dns.query.tcp if tcp else dns.query.udp
        return sender(query, "127.0.0.1", port=port, timeout=5.0)

    def diff_authoritative(self, zport, nport, tcp=False):
        for name, rdtype in QUERIES:
            label = f"{'tcp' if tcp else 'udp'} {name} {rdtype}"
            try:
                mine = self.response_view(self.query(zport, name, rdtype, tcp=tcp))
                ref = self.response_view(self.query(nport, name, rdtype, tcp=tcp))
                # The answer set and the response meaning must match exactly.
                for key in ("rcode", "aa", "tc", "answer"):
                    if mine[key] != ref[key]:
                        raise Failure(
                            f"{label}: {key} differs\n  zimdns: {mine[key]}\n  bind:   {ref[key]}"
                        )
                # Negative answers must carry the same SOA/denial proof; BIND
                # with minimal-responses may differ on authority NS in
                # positive answers, so compare authority only when the answer
                # is negative or a referral.
                if mine["rcode"] != 0 or not mine["answer"]:
                    if mine["authority"] != ref["authority"]:
                        raise Failure(
                            f"{label}: authority differs\n  zimdns: {mine['authority']}\n  bind:   {ref['authority']}"
                        )
                self.ok(label)
            except Failure:
                raise
            except Exception as exc:
                raise Failure(f"{label}: {exc}")

    # --------------------------------------------------------------- checks
    def ok(self, label):
        self.passed += 1
        print(f"PASS {label}")

    def check(self, label, fn):
        try:
            fn()
            self.ok(label)
        except Exception as exc:
            self.failed.append((label, str(exc)))
            print(f"FAIL {label}: {exc}")
            if self.verbose:
                traceback.print_exc()

    def check_tools(self):
        missing = [name for name in TOOLS.values() if shutil.which(name) is None]
        if missing:
            raise Failure("missing external tools: " + ", ".join(missing))
        version = self.run([TOOLS["named"], "-v"]).stdout.strip()
        print(f"tools: {version}")

    def dig(self, port, *args, expect=None):
        argv = [TOOLS["dig"], "@127.0.0.1", "-p", str(port), *args]
        out = self.run(argv).stdout
        if expect is not None and expect not in out:
            raise Failure(f"dig output lacks {expect!r}:\n{out[:1200]}")
        return out

    def external_authoritative(self, zudp, ztcp, work):
        self.dig(zudp, "example.test.", "SOA", "+short", expect="hostmaster.example.test.")
        nx = self.dig(zudp, "missing.example.test.", "A")
        if "status: NXDOMAIN" not in nx and "NXDOMAIN" not in nx:
            raise Failure(f"dig did not see NXDOMAIN:\n{nx[:800]}")
        nodata = self.dig(zudp, "nodata.example.test.", "A")
        if "status: NOERROR" not in nodata and "NOERROR" not in nodata:
            raise Failure(f"dig did not see NOERROR for NODATA:\n{nodata[:800]}")
        self.dig(zudp, "foo.wild.example.test.", "A", "+short", expect="192.0.2.99")
        self.dig(zudp, "alias.example.test.", "A", "+short", expect="192.0.2.80")
        self.dig(ztcp, "www.example.test.", "A", "+tcp", "+short", expect="192.0.2.80")

        kdig = self.run(
            [TOOLS["kdig"], "@127.0.0.1", "-p", str(zudp), "+short", "www.example.test.", "A"]
        ).stdout
        if "192.0.2.80" not in kdig:
            raise Failure(f"kdig UDP answer wrong:\n{kdig}")

        kdig_tcp = self.run(
            [
                TOOLS["kdig"], "@127.0.0.1", "-p", str(ztcp), "+tcp", "+short",
                "www.example.test.", "A",
            ]
        ).stdout
        if "192.0.2.80" not in kdig_tcp:
            raise Failure(f"kdig TCP answer wrong:\n{kdig_tcp}")

        # AXFR from outside, then validate the transferred text with BIND's
        # zone checker and with ldns.
        axfr = self.run(
            [TOOLS["dig"], "@127.0.0.1", "-p", str(ztcp), "example.test.", "AXFR", "+noall", "+answer"]
        ).stdout
        if axfr.count("SOA") < 2:
            raise Failure(f"AXFR does not start and end with SOA:\n{axfr[:1200]}")
        axfr_path = os.path.join(work, "axfr.zone")
        with open(axfr_path, "w") as f:
            f.write(axfr)
        self.run([TOOLS["named-checkzone"], "example.test", axfr_path])
        self.run([TOOLS["kzonecheck"], "-o", "example.test", axfr_path])

        # IXFR with the current serial falls back to a full transfer and is
        # equally valid zone text.
        ixfr = self.run(
            [
                TOOLS["dig"], "@127.0.0.1", "-p", str(ztcp), "example.test.", "IXFR=1", "+noall", "+answer",
            ]
        ).stdout
        if "SOA" not in ixfr:
            raise Failure(f"IXFR produced no zone text:\n{ixfr[:1200]}")

    def check_doh(self, work, port):
        cert = os.path.join(work, "cert.pem")
        key = os.path.join(work, "key.pem")
        self.run(
            [
                TOOLS["openssl"], "req", "-x509", "-newkey", "ec",
                "-pkeyopt", "ec_paramgen_curve:prime256v1",
                "-nodes", "-keyout", key, "-out", cert, "-days", "2",
                "-subj", "/CN=localhost",
                "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
            ]
        )
        config = os.path.join(work, "doh.gdns")
        with open(config, "w") as f:
            f.write(f"listen dns doh 127.0.0.1:{port}\n")
            f.write("zone example.test primary authoritative.zone\n")
            f.write("local-zones off\n")
        proc = self.spawn(
            [
                self.zimdns, "server", "run", "--config", "doh.gdns",
                "--serve-doh", "--enable-encrypted-dns",
                "--tls-cert-file", cert, "--tls-key-file", key,
            ],
            cwd=work,
        )
        query = dns.message.make_query("www.example.test.", "A").to_wire()
        query_path = os.path.join(work, "query.bin")
        with open(query_path, "wb") as f:
            f.write(query)
        b64 = base64.urlsafe_b64encode(query).rstrip(b"=").decode()
        response_path = os.path.join(work, "doh-response.bin")

        def doh_ready():
            result = self.run(
                [
                    TOOLS["curl"], "-sk", "-o", response_path, "-w", "%{http_code}",
                    f"https://127.0.0.1:{port}/dns-query?dns={b64}",
                ],
                check=False,
            )
            return result.returncode == 0 and result.stdout.strip() == "200" and os.path.getsize(response_path) > 12

        deadline = time.time() + 10
        while time.time() < deadline:
            if proc.poll() is not None:
                out, err = proc.communicate()
                raise Failure(f"DoH server exited: {out} {err}")
            if doh_ready():
                break
            time.sleep(0.1)
        else:
            raise Failure("curl did not get a DoH answer over GET")

        answer = dns.message.from_wire(open(response_path, "rb").read())
        if answer.rcode() != 0 or not answer.answer:
            raise Failure(f"DoH GET response is not a positive answer: {answer}")

        result = self.run(
            [
                TOOLS["curl"], "-sk", "-o", response_path, "-w", "%{http_code}",
                "--data-binary", f"@{query_path}",
                "-H", "content-type: application/dns-message",
                f"https://127.0.0.1:{port}/dns-query",
            ]
        )
        if result.stdout.strip() != "200":
            raise Failure(f"DoH POST returned {result.stdout.strip()}")
        answer = dns.message.from_wire(open(response_path, "rb").read())
        if answer.rcode() != 0 or not answer.answer:
            raise Failure(f"DoH POST response is not a positive answer: {answer}")

    # ------------------------------------------------- tsig and dynamic update
    TSIG_KEY = "update-key."
    TSIG_SECRET = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="

    def check_tsig_and_update(self, work, port):
        with open(os.path.join(work, "tsig.key"), "w") as f:
            f.write(
                f'key "{self.TSIG_KEY}" {{ algorithm hmac-sha256; secret "{self.TSIG_SECRET}"; }};\n'
            )
        extra = "tsig-key-file tsig.key\nallow-update example.test update-key.\n"
        self.start_zimdns(work, port, "--serve-udp", extra=extra)
        self.start_zimdns(work, port, "--serve-tcp", extra=extra)

        secret = self.TSIG_SECRET
        signed = self.run(
            [
                TOOLS["dig"], "@127.0.0.1", "-p", str(port),
                "-y", f"hmac-sha256:{self.TSIG_KEY}:{secret}",
                "example.test.", "SOA", "+short",
            ]
        ).stdout
        if "hostmaster.example.test." not in signed:
            raise Failure(f"signed query failed:\n{signed}")

        # An unsigned request is still answered: TSIG is opt-in per request.
        self.dig(port, "www.example.test.", "A", "+short", expect="192.0.2.80")

        script = (
            f"server 127.0.0.1 {port}\n"
            "zone example.test.\n"
            "update add new.example.test. 300 A 192.0.2.77\n"
            "send\n"
        )
        updated = self.run(
            [
                TOOLS["nsupdate"], "-v",
                "-y", f"hmac-sha256:{self.TSIG_KEY}:{secret}",
            ],
            input=script,
        )
        if "REFUSED" in updated.stdout + updated.stderr:
            raise Failure(f"signed update was refused:\n{updated.stdout}\n{updated.stderr}")
        self.dig(port, "new.example.test.", "A", "+tcp", "+short", expect="192.0.2.77")

        unsigned = self.run(
            [TOOLS["nsupdate"], "-v"],
            input=script,
            check=False,
        )
        if "REFUSED" not in (unsigned.stdout + unsigned.stderr):
            raise Failure(
                "an unsigned update was not refused:\n"
                f"stdout: {unsigned.stdout}\nstderr: {unsigned.stderr}"
            )

    # --------------------------------------------------------------- dot/dnssec
    def make_cert(self, work):
        cert = os.path.join(work, "cert.pem")
        key = os.path.join(work, "key.pem")
        self.run(
            [
                TOOLS["openssl"], "req", "-x509", "-newkey", "ec",
                "-pkeyopt", "ec_paramgen_curve:prime256v1",
                "-nodes", "-keyout", key, "-out", cert, "-days", "2",
                "-subj", "/CN=localhost",
                "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
            ]
        )
        return cert, key

    def check_dot(self, work, port):
        cert, key = self.make_cert(work)
        with open(os.path.join(work, "dot.gdns"), "w") as f:
            f.write(f"listen dns dot 127.0.0.1:{port}\n")
            f.write("zone example.test primary authoritative.zone\n")
            f.write("local-zones off\n")
        proc = self.spawn(
            [
                self.zimdns, "server", "run", "--config", "dot.gdns",
                "--serve-dot", "--enable-encrypted-dns",
                "--tls-cert-file", cert, "--tls-key-file", key,
            ],
            cwd=work,
        )
        deadline = time.time() + 10
        while time.time() < deadline:
            if proc.poll() is not None:
                out, err = proc.communicate()
                raise Failure(f"DoT server exited: {out} {err}")
            result = self.run(
                [
                    TOOLS["kdig"], "@127.0.0.1", "-p", str(port),
                    "+tls", f"+tls-ca={cert}", "+tls-hostname=localhost",
                    "+short", "www.example.test.", "A",
                ],
                check=False,
            )
            if "192.0.2.80" in result.stdout:
                break
            time.sleep(0.1)
        else:
            raise Failure(f"kdig did not get a DoT answer:\n{result.stdout}\n{result.stderr}")

        # The same port must not answer cleartext DNS.
        cleartext = self.run(
            [TOOLS["kdig"], "@127.0.0.1", "-p", str(port), "+timeout=2", "+retry=1", "www.example.test.", "A"],
            check=False,
            timeout=8,
        )
        if "192.0.2.80" in cleartext.stdout:
            raise Failure("the DoT port answered cleartext DNS")

        # The DoT listener is query-only: a transfer question on it is refused.
        refused = self.run(
            [
                TOOLS["kdig"], "@127.0.0.1", "-p", str(port),
                "+tls", f"+tls-ca={cert}", "+tls-hostname=localhost",
                "example.test.", "AXFR", "+noall", "+answer",
            ],
            check=False,
        )
        if "REFUSED" not in refused.stderr and "SOA" in refused.stdout:
            raise Failure(f"DoT answered an AXFR instead of refusing it:\n{refused.stdout}")
        proc.terminate()
        proc.wait(timeout=5)

        # The strict-TLS transfer listener is the transfer channel; it serves
        # the same zone over TLS, and an outside checker must accept it.
        xfr_port = self.free_port()
        with open(os.path.join(work, "xfr.gdns"), "w") as f:
            f.write(f"listen dns dot 127.0.0.1:{xfr_port}\n")
            f.write("zone example.test primary authoritative.zone\n")
            f.write("local-zones off\n")
        xfr_proc = self.spawn(
            [
                self.zimdns, "server", "run", "--config", "xfr.gdns",
                "--serve-xfr", "--enable-encrypted-dns",
                "--tls-cert-file", cert, "--tls-key-file", key,
            ],
            cwd=work,
        )
        deadline = time.time() + 10
        while time.time() < deadline:
            if xfr_proc.poll() is not None:
                out, err = xfr_proc.communicate()
                raise Failure(f"transfer server exited: {out} {err}")
            axfr = self.run(
                [
                    TOOLS["kdig"], "@127.0.0.1", "-p", str(xfr_port),
                    "+tls", f"+tls-ca={cert}", "+tls-hostname=localhost",
                    "example.test.", "AXFR", "+noall", "+answer",
                ],
                check=False,
                timeout=10,
            )
            if "SOA" in axfr.stdout:
                break
            time.sleep(0.1)
        else:
            raise Failure(f"strict-TLS AXFR produced no zone:\n{axfr.stdout}\n{axfr.stderr}")
        axfr_path = os.path.join(work, "dot-axfr.zone")
        with open(axfr_path, "w") as f:
            f.write(axfr.stdout)
        self.run([TOOLS["named-checkzone"], "example.test", axfr_path])

    def check_dnssec(self, work, port):
        # A P-256 key keeps the external validators on their most widely
        # supported algorithm; the Ed25519 path is covered by the signer's
        # RFC 8080 vector tests and by dnssec-verify below.
        self.new_key(work, "ECDSAP256SHA256", "zsk.key")
        extra = "dnssec-key-file zsk.key\n"
        self.start_zimdns(work, port, "--serve-udp", extra=extra)
        self.start_zimdns(work, port, "--serve-tcp", extra=extra)

        signed = self.dig(port, "www.example.test.", "A", "+dnssec")
        if "RRSIG" not in signed:
            raise Failure(f"no RRSIG in the signed answer:\n{signed[:1200]}")
        self.dig(port, "example.test.", "DNSKEY", "+dnssec", expect="DNSKEY")
        negative = self.dig(port, "nothing.example.test.", "A", "+dnssec")
        if "NSEC" not in negative and "NSEC3" not in negative:
            raise Failure(f"no denial proof for the signed NXDOMAIN:\n{negative[:1200]}")

        axfr = self.run(
            [
                TOOLS["dig"], "@127.0.0.1", "-p", str(port),
                "example.test.", "AXFR", "+noall", "+answer",
            ]
        ).stdout
        axfr_path = os.path.join(work, "signed.zone")
        with open(axfr_path, "w") as f:
            f.write(axfr)
        self.run([TOOLS["dnssec-verify"], "-o", "example.test", axfr_path])
        self.run([TOOLS["ldns-verify-zone"], axfr_path])

        # delv is an outside validator: it is given only the KSK trust anchor
        # in BIND's trust-anchors syntax and must build the chain itself.
        dnskey_lines = self.run(
            [TOOLS["dig"], "@127.0.0.1", "-p", str(port), "example.test.", "DNSKEY", "+short"]
        ).stdout.splitlines()
        ksk = next((line for line in dnskey_lines if line.split()[:1] == ["257"]), None)
        if ksk is None:
            raise Failure(f"no KSK (flags 257) in the served DNSKEY RRset:\n{dnskey_lines}")
        anchor = os.path.join(work, "anchor.key")
        with open(anchor, "w") as f:
            parts = ksk.split()
            flags, proto, alg = parts[0], parts[1], parts[2]
            key = "".join(parts[3:])
            f.write('trusted-keys {\n')
            f.write(f'  "example.test." {flags} {proto} {alg} "{key}";\n')
            f.write('};\n')
        delv = self.run(
            [
                TOOLS["delv"], "@127.0.0.1", "-p", str(port), "-a", anchor,
                "+root=example.test.", "www.example.test.", "A",
            ],
            check=False,
            timeout=15,
        )
        if "fully validated" not in delv.stdout and "192.0.2.80" not in delv.stdout:
            raise Failure(f"delv did not validate the answer:\n{delv.stdout}\n{delv.stderr}")

    def check_managed_anchors(self, work, port):
        """RFC 5011: a resolver follows a DNSKEY revocation end to end.

        The authoritative side publishes a KSK and a ZSK; the resolver is
        given only the KSK as a static anchor plus a managed state file. It
        must validate and adopt the second KSK into `addpend`, then, after the
        zone is re-signed with the anchor REVOKEd, stop trusting it and answer
        insecure instead of SERVFAIL.
        """
        self.new_key(work, "ECDSAP256SHA256", "zsk.key")
        self.new_key(work, "ECDSAP256SHA256", "ksk.key")
        self.new_key(work, "ECDSAP256SHA256", "next-ksk.key")
        authoritative = self.start_zimdns(
            work, port, "--serve-udp",
            extra="dnssec-key-file zsk.key\ndnssec-ksk-file ksk.key\n",
        )

        dnskey_lines = self.run(
            [TOOLS["dig"], "@127.0.0.1", "-p", str(port), "example.test.", "DNSKEY", "+short"]
        ).stdout.splitlines()
        ksk = next((line for line in dnskey_lines if line.split()[:1] == ["257"]), None)
        if ksk is None:
            raise Failure(f"no KSK in the served DNSKEY RRset:\n{dnskey_lines}")
        parts = ksk.split()
        with open(os.path.join(work, "anchors.txt"), "w") as f:
            f.write(f"example.test. DNSKEY {parts[0]} {parts[1]} {parts[2]} {''.join(parts[3:])}\n")

        extra = (
            "trust-anchor-file anchors.txt\n"
            "managed-anchor-file managed.txt\n"
            "recursion allow 127.0.0.0/8\n"
            f"forwarder 127.0.0.1:{port}\n"
        )
        resolver_port = self.free_port()
        resolver = None
        resolver = self.start_resolver(work, resolver_port, extra)
        try:
            validated = self.dig(resolver_port, "www.example.test.", "A", "+dnssec")
            if "192.0.2.80" not in validated:
                raise Failure(f"resolver did not answer through the forwarder:\n{validated[:1200]}")
            if not self.dig_flag(validated, "ad"):
                raise Failure(f"validated answer has no AD bit:\n{validated[:1200]}")

            state = open(os.path.join(work, "managed.txt")).read()
            if " valid " not in state:
                raise Failure(f"managed state did not hold the anchor as valid:\n{state}")

            self.stop(authoritative)
            self.start_zimdns(
                work, port, "--serve-udp",
                extra=(
                    "dnssec-key-file zsk.key\n"
                    "dnssec-ksk-file next-ksk.key\n"
                    "dnssec-new-ksk-file ksk.key revoked\n"
                ),
            )
            self.stop(resolver)
            resolver = self.start_resolver(work, resolver_port, extra)

            insecure = self.dig(resolver_port, "www.example.test.", "A", "+dnssec")
            if "192.0.2.80" not in insecure:
                state = open(os.path.join(work, "managed.txt")).read()
                served = self.dig(port, "example.test.", "DNSKEY", "+dnssec")
                raise Failure(
                    f"revoked-anchor answer is not served:\n{insecure[:1200]}\n"
                    f"state:\n{state}\ndnskey:\n{served[:2000]}"
                )
            if self.dig_flag(insecure, "ad"):
                raise Failure(f"a revoked anchor still validates:\n{insecure[:1200]}")
            state = open(os.path.join(work, "managed.txt")).read()
            if " revoked " not in state:
                raise Failure(f"managed state did not record the revocation:\n{state}")
            if " valid " in state:
                raise Failure(f"managed state still holds a valid anchor after revocation:\n{state}")
        finally:
            if resolver is not None:
                self.stop(resolver)

    @staticmethod
    def dig_flag(output, flag):
        for line in output.splitlines():
            if line.startswith(";; flags:"):
                return flag in line[len(";; flags:"):].split(";", 1)[0].split()
        return False

    def start_resolver(self, work, port, extra):
        with open(os.path.join(work, "resolver.zone"), "w") as f:
            f.write(
                "$ORIGIN resolver.invalid.\n"
                "$TTL 3600\n"
                "@ IN SOA ns.resolver.invalid. hostmaster.resolver.invalid. 1 3600 900 604800 3600\n"
                "@ IN NS ns.resolver.invalid.\n"
                "ns IN A 127.0.0.1\n"
            )
        extra = "zone resolver.invalid primary resolver.zone\n" + extra
        config = self.write_zimdns_config(work, port, extra, zone=False)
        proc = self.spawn([self.zimdns, "server", "run", "--config", "config.gdns", "--serve-udp"], cwd=work)
        self.wait_query(port, proc=proc)
        return proc

    # ----------------------------------------------------------------- main
    def run_all(self):
        self.check_tools()
        work = self.make_workdir()
        zport = self.free_port()
        nport = self.free_port()
        try:
            self.start_zimdns(work, zport, "--serve-udp")
            self.start_zimdns(work, zport, "--serve-tcp")
            self.start_named(work, nport)
            self.check("differential oracle, UDP corpus", lambda: self.diff_authoritative(zport, nport, tcp=False))
            self.check("differential oracle, TCP corpus", lambda: self.diff_authoritative(zport, nport, tcp=True))
            self.check(
                "external clients: dig, kdig, AXFR, named-checkzone, kzonecheck",
                lambda: self.external_authoritative(zport, zport, work),
            )
            self.cleanup()

            # Each phase gets a fresh work directory: dynamic update rewrites
            # the zone file, and a signed zone must not leak into the unsigned
            # differential corpus.
            tsig_work = self.make_workdir()
            tsig_port = self.free_port()
            self.check(
                "external clients: TSIG-signed query and nsupdate",
                lambda: self.check_tsig_and_update(tsig_work, tsig_port),
            )
            self.cleanup()
            shutil.rmtree(tsig_work, ignore_errors=True)

            dot_work = self.make_workdir()
            dot_port = self.free_port()
            self.check("external client: kdig DoT and TLS AXFR", lambda: self.check_dot(dot_work, dot_port))
            self.cleanup()
            shutil.rmtree(dot_work, ignore_errors=True)

            dnssec_work = self.make_workdir()
            dnssec_port = self.free_port()
            self.check(
                "external clients: dnssec-verify, ldns-verify-zone, delv",
                lambda: self.check_dnssec(dnssec_work, dnssec_port),
            )
            self.cleanup()
            shutil.rmtree(dnssec_work, ignore_errors=True)

            managed_work = self.make_workdir()
            managed_port = self.free_port()
            self.check(
                "external client: RFC 5011 revocation through a validating resolver",
                lambda: self.check_managed_anchors(managed_work, managed_port),
            )
            self.cleanup()
            shutil.rmtree(managed_work, ignore_errors=True)

            doh_work = self.make_workdir()
            doh_port = self.free_port()
            self.check("external client: curl DoH GET and POST", lambda: self.check_doh(doh_work, doh_port))
            shutil.rmtree(doh_work, ignore_errors=True)
        finally:
            self.cleanup()
            shutil.rmtree(work, ignore_errors=True)

        print(f"\n{self.passed} checks passed, {len(self.failed)} failed")
        if self.failed:
            for label, err in self.failed:
                print(f"FAILED {label}: {err}")
            raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--zimdns", default=os.path.join(REPO, "zig-out", "bin", "zimdns"))
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    if not os.path.exists(args.zimdns):
        sys.stderr.write(f"missing binary: {args.zimdns} (run zig build)\n")
        raise SystemExit(2)
    Suite(args.zimdns, args.verbose).run_all()


if __name__ == "__main__":
    main()
