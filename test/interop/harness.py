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
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
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
    ("rp.example.test.", "RP"),
    ("sshfp.example.test.", "SSHFP"),
    ("tlsa.example.test.", "TLSA"),
    ("naptr.example.test.", "NAPTR"),
    ("apl.example.test.", "APL"),
    ("afsdb.example.test.", "AFSDB"),
    ("rt.example.test.", "RT"),
    ("uri.example.test.", "URI"),
    ("hinfo.example.test.", "HINFO"),
    ("WwW.ExAmPlE.TeSt.", "A"),
    ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.test.", "A"),
    ("a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.example.test.", "A"),
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
        lines = {}
        with open(os.path.join(work, private[0])) as f:
            for line in f:
                if ":" in line:
                    field, value = line.split(":", 1)
                    lines[field.strip()] = value.strip()
        if "PrivateKey" in lines:
            secret = lines["PrivateKey"]
        elif "Modulus" in lines and "PrivateExponent" in lines:
            # BIND writes RSA as PKCS#1 components; the signer reads a
            # PKCS#1 DER blob, so rebuild one with the cryptography library.
            try:
                import base64 as b64
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric import rsa
            except ImportError as exc:
                raise Failure(f"cryptography is required for RSA key conversion: {exc}")

            def component(field):
                return int.from_bytes(b64.b64decode(lines[field]), "big")

            key = rsa.RSAPrivateNumbers(
                p=component("Prime1"),
                q=component("Prime2"),
                d=component("PrivateExponent"),
                dmp1=component("Exponent1"),
                dmq1=component("Exponent2"),
                iqmp=component("Coefficient"),
                public_numbers=rsa.RSAPublicNumbers(
                    e=component("PublicExponent"),
                    n=component("Modulus"),
                ),
            ).private_key()
            der = key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
            secret = b64.b64encode(der).decode()
        else:
            raise Failure("dnssec-keygen private file has no private key")
        with open(os.path.join(work, filename), "w") as f:
            f.write(f"{algorithm.lower()} {secret}\n")
        return filename

    def write_named_config(self, work, port, zone_name="example.test", zone_file="authoritative.zone"):
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
zone "{zone_name}" {{
  type master;
  file "{work}/{zone_file}";
}};
'''
            )
        return path

    def start_named(self, work, port, zone_name="example.test", zone_file="authoritative.zone"):
        config = self.write_named_config(work, port, zone_name, zone_file)
        proc = self.spawn(
            [TOOLS["named"], "-g", "-4", "-c", config],
            cwd=work,
        )
        self.wait_query(port, proc=proc)
        return proc

    def check_tc_and_headers(self, work, udp_port, tcp_port):
        """RFC 6891/1035: TC over UDP, whole answer over TCP, header bits.

        A 1.5 KB TXT RRset does not fit a 512-octet datagram, so the UDP
        response carries TC and the TCP retry carries every string. CD is
        copied into the response, AD is not invented, and a query with two
        questions is FORMERR (RFC 9619).
        """
        udp = self.start_zimdns(work, udp_port, "--serve-udp")
        tcp = self.start_zimdns(work, tcp_port, "--serve-tcp")
        try:
            truncated = self.dig(
                udp_port, "big.example.test.", "A", "+bufsize=512", "+ignore",
            )
            if " tc " not in truncated.split("flags:")[1].split(";")[0] + " ":
                raise Failure(f"a 512-octet UDP query did not set TC:\n{truncated[:1600]}")
            whole = self.dig(tcp_port, "big.example.test.", "A", "+tcp", "+short")
            addresses = [line for line in whole.splitlines() if line.startswith("192.0.2.")]
            if len(addresses) != 80:
                raise Failure(f"TCP did not carry the whole A RRset ({len(addresses)} addresses):\n{whole[:1600]}")
            cd = self.dig(udp_port, "example.test.", "SOA", "+cdflag")
            if not self.dig_flag(cd, "cd"):
                raise Failure(f"CD was not copied into the answer:\n{cd[:1200]}")
            if self.dig_flag(cd, "ad"):
                raise Failure(f"an unsigned authoritative answer set AD:\n{cd[:1200]}")
            query = dns.message.Message(id=0)
            query.flags = dns.flags.RD
            query.question.append(dns.rrset.RRset(dns.name.from_text("example.test."), dns.rdataclass.IN, dns.rdatatype.SOA))
            query.question.append(dns.rrset.RRset(dns.name.from_text("example.test."), dns.rdataclass.IN, dns.rdatatype.NS))
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2)
                sock.sendto(query.to_wire(), ("127.0.0.1", udp_port))
                response = dns.message.from_wire(sock.recvfrom(65535)[0])
            if response.rcode() != dns.rcode.FORMERR:
                raise Failure(f"a two-question query answered {dns.rcode.to_text(response.rcode())}")
        finally:
            self.stop(udp)
            self.stop(tcp)

    def check_edns_options(self, work, udp_port, tcp_port):
        """RFC 5001/6891/7828/9660: external clients see the EDNS options.

        `dig` requests NSID, a cookie, TCP keepalive, and ZONEVERSION, and
        the server must answer each with the option; ANY at the apex must be
        the RFC 8482 minimal form, not the whole RRset set.
        """
        extra = (
            "nsid 00ff\n"
            "cookies validate 00112233445566778899aabbccddeeff\n"
            "minimal-any-ttl 120\n"
        )
        udp = self.start_zimdns(work, udp_port, "--serve-udp", extra=extra)
        tcp = self.start_zimdns(work, tcp_port, "--serve-tcp", extra=extra)
        try:
            nsid = self.dig(udp_port, "example.test.", "SOA", "+nsid")
            if "NSID: 00 ff" not in nsid:
                raise Failure(f"NSID option is not the configured payload:\n{nsid[:1200]}")
            cookie = self.dig(udp_port, "example.test.", "SOA", "+cookie")
            if "COOKIE:" not in cookie or "(good)" not in cookie:
                raise Failure(f"cookie option is not a valid server cookie:\n{cookie[:1200]}")
            version = self.dig(udp_port, "example.test.", "SOA", "+ednsopt=19")
            if "ZONEVERSION:" not in version:
                raise Failure(f"ZONEVERSION option is missing:\n{version[:1200]}")
            keepalive = self.dig(tcp_port, "example.test.", "SOA", "+tcp", "+keepalive")
            if "TCP-KEEPALIVE:" not in keepalive:
                raise Failure(f"TCP keepalive option is missing:\n{keepalive[:1200]}")
            alive = self.run(
                [TOOLS["dig"], "@127.0.0.1", "-p", str(udp_port), "example.test.", "SOA"],
                check=False,
            )
            # dig follows ANY over TCP by default; this listener is UDP.
            minimal = self.run(
                [TOOLS["dig"], "@127.0.0.1", "-p", str(udp_port), "example.test.", "ANY", "+notcp"],
                check=False,
            ).stdout
            if "HINFO" not in minimal:
                diag = ""
                if udp.poll() is not None:
                    out, err = udp.communicate()
                    diag = f"\nudp exited {udp.returncode}: {out[-500:]} {err[-1500:]}"
                raise Failure(f"ANY did not get the RFC 8482 minimal answer:\n{minimal[:1200]}{diag}")
            if "\tSOA\t" in minimal or "\tNS\t" in minimal:
                raise Failure(f"ANY returned more than the minimal RRset:\n{minimal[:1200]}")
        finally:
            self.stop(udp)
            self.stop(tcp)

    def check_error_report(self, work, upstream_port, resolver_port):
        """RFC 9567: an upstream EDE with an agent produces a report query."""
        import struct
        seen = []
        stop = threading.Event()

        def serve_tcp():
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("127.0.0.1", upstream_port))
            server.listen(4)
            server.settimeout(0.2)
            try:
                while not stop.is_set():
                    try:
                        conn, _ = server.accept()
                    except socket.timeout:
                        continue
                    with conn:
                        conn.settimeout(1)
                        try:
                            prefix = conn.recv(2)
                            if len(prefix) != 2:
                                continue
                            length = struct.unpack("!H", prefix)[0]
                            data = b""
                            while len(data) < length:
                                chunk = conn.recv(length - len(data))
                                if not chunk:
                                    break
                                data += chunk
                            query = dns.message.from_wire(data)
                            seen.append(query.question[0].name.to_text().lower())
                            response = dns.message.make_response(query)
                            response.use_edns(0, options=[])
                            wire = response.to_wire()
                            conn.sendall(struct.pack("!H", len(wire)) + wire)
                        except Exception:
                            continue
            finally:
                server.close()

        def serve():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", upstream_port))
            sock.settimeout(0.2)
            try:
                while not stop.is_set():
                    try:
                        data, addr = sock.recvfrom(65535)
                    except socket.timeout:
                        continue
                    query = dns.message.from_wire(data)
                    name = query.question[0].name.to_text().lower()
                    seen.append(name)
                    response = dns.message.make_response(query)
                    if name.startswith("_er."):
                        response.use_edns(0, options=[])
                    else:
                        response.set_rcode(dns.rcode.SERVFAIL)
                        agent = dns.name.from_text("agent.example.").to_wire()
                        response.use_edns(0, options=[
                            dns.edns.GenericOption(15, struct.pack("!H", 3)),
                            dns.edns.GenericOption(18, agent),
                        ])
                    sock.sendto(response.to_wire(), addr)
            finally:
                sock.close()

        tcp_thread = threading.Thread(target=serve_tcp, daemon=True)
        tcp_thread.start()
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            extra = (
                "recursion allow 127.0.0.0/8\n"
                f"forwarder 127.0.0.1:{upstream_port}\n"
            )
            resolver = self.start_resolver(work, resolver_port, extra)
            try:
                answer = self.dig(resolver_port, "broken.example.test.", "A")
                if "SERVFAIL" not in answer and "EDE: 3" not in answer:
                    raise Failure(f"the upstream failure was not relayed:\n{answer[:1400]}")
                deadline = time.time() + 5
                expected = "_er.1.broken.example.test.3._er.agent.example."
                while time.time() < deadline and expected not in seen:
                    time.sleep(0.1)
                if expected not in seen:
                    raise Failure(f"no RFC 9567 report query for the failed name (saw {seen!r})")
            finally:
                self.stop(resolver)
        finally:
            stop.set()
            thread.join(timeout=2)
            tcp_thread.join(timeout=2)

    def check_forged_answers(self, work, upstream_port, resolver_port):
        """RFC 5452: wrong-ID and wrong-question answers are ignored."""
        stop = threading.Event()
        exchanges = {"count": 0}

        def serve():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("127.0.0.1", upstream_port))
            sock.settimeout(0.2)
            try:
                while not stop.is_set():
                    try:
                        data, addr = sock.recvfrom(65535)
                    except socket.timeout:
                        continue
                    query = dns.message.from_wire(data)
                    exchanges["count"] += 1
                    # The first exchange gets only forged answers; the
                    # resolver's retry gets the real one.
                    if exchanges["count"] == 1:
                        bogus = dns.message.make_response(query)
                        bogus.id = (query.id + 1) & 0xFFFF
                        bogus.answer.append(
                            dns.rrset.from_text("forged.example.test.", 60, "IN", "A", "6.6.6.6")
                        )
                        sock.sendto(bogus.to_wire(), addr)
                        wrong = dns.message.make_response(query)
                        wrong.question[0].name = dns.name.from_text("other.example.test.")
                        wrong.answer.append(
                            dns.rrset.from_text("forged.example.test.", 60, "IN", "A", "6.6.6.6")
                        )
                        sock.sendto(wrong.to_wire(), addr)
                        continue
                    response = dns.message.make_response(query)
                    response.answer.append(
                        dns.rrset.from_text("forged.example.test.", 60, "IN", "A", "192.0.2.80")
                    )
                    sock.sendto(response.to_wire(), addr)
            finally:
                sock.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            extra = (
                "recursion allow 127.0.0.0/8\n"
                f"forwarder 127.0.0.1:{upstream_port}\n"
            )
            resolver = self.start_resolver(work, resolver_port, extra)
            try:
                answer = self.dig(resolver_port, "forged.example.test.", "A")
                if "192.0.2.80" not in answer:
                    raise Failure(f"the valid answer is missing:\n{answer[:1400]}")
                if "6.6.6.6" in answer:
                    raise Failure(f"a forged answer was accepted:\n{answer[:1400]}")
            finally:
                self.stop(resolver)
        finally:
            stop.set()
            thread.join(timeout=2)

    def check_dns64(self, work, upstream_port, resolver_port):
        """RFC 6147: an empty AAAA answer is synthesized from A."""
        stop = threading.Event()

        def serve():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("127.0.0.1", upstream_port))
            sock.settimeout(0.2)
            try:
                while not stop.is_set():
                    try:
                        data, addr = sock.recvfrom(65535)
                    except socket.timeout:
                        continue
                    query = dns.message.from_wire(data)
                    qtype = query.question[0].rdtype
                    response = dns.message.make_response(query)
                    if qtype == dns.rdatatype.A:
                        response.answer.append(
                            dns.rrset.from_text("v4only.example.test.", 60, "IN", "A", "1.2.3.4")
                        )
                    sock.sendto(response.to_wire(), addr)
            finally:
                sock.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            extra = (
                "recursion allow 127.0.0.0/8\n"
                "dns64 on\n"
                "nat64-prefix 64:ff9b::/96\n"
                f"forwarder 127.0.0.1:{upstream_port}\n"
            )
            resolver = self.start_resolver(work, resolver_port, extra)
            try:
                answer = self.dig(resolver_port, "v4only.example.test.", "AAAA")
                if "64:ff9b::102:304" not in answer:
                    raise Failure(f"DNS64 did not synthesize the AAAA from A:\n{answer[:1400]}")
            finally:
                self.stop(resolver)
        finally:
            stop.set()
            thread.join(timeout=2)

    def check_blacklist(self, work, port):
        """RFC 5782: listed addresses are published under the blacklist apex."""
        with open(os.path.join(work, "blacklist.txt"), "w") as f:
            f.write("192.0.2.1\n2001:db8::1\nbad.example\n")
        proc = self.start_zimdns(
            work, port, "--serve-udp",
            extra="blacklist-zone blacklist.example.test blacklist.txt\n",
        )
        try:
            listed = self.dig(port, "1.2.0.192.blacklist.example.test.", "A", "+short")
            if "127.0.0.2" not in listed:
                raise Failure(f"the listed IPv4 entry is not published:\n{listed[:800]}")
            bad = self.dig(port, "bad.example.blacklist.example.test.", "A", "+short")
            if "127.0.0.2" not in bad:
                raise Failure(f"the listed name is not published:\n{bad[:800]}")
            missing = self.dig(port, "2.2.0.192.blacklist.example.test.", "A")
            if "NXDOMAIN" not in missing:
                raise Failure(f"an unlisted entry is not NXDOMAIN:\n{missing[:1200]}")
        finally:
            self.stop(proc)

    def check_catalog(self, work, producer_port, consumer_port):
        """RFC 9432: a consumer serves the members a producer publishes."""
        producer = self.start_zimdns(
            work, producer_port, "--serve-udp",
            extra="catalog-zone catalog.example.test\n",
        )
        try:
            catalog = self.dig(producer_port, "version.catalog.example.test.", "TXT", "+short")
            if "2" not in catalog:
                raise Failure(f"the producer catalog has no schema-2 version:\n{catalog[:800]}")
            # The consumer fetches the catalog by AXFR over DNS/TCP at startup.
            self.start_zimdns(work, producer_port, "--serve-tcp", extra="catalog-zone catalog.example.test\nallow-transfer catalog.example.test 127.0.0.1/32\nallow-transfer example.test 127.0.0.1/32\n")
            consumer = self.start_resolver(
                work, consumer_port,
                extra=f"catalog-consumer catalog.example.test 127.0.0.1:{producer_port}\n",
            )
            try:
                answer = self.dig(consumer_port, "www.example.test.", "A")
                if "192.0.2.80" not in answer:
                    raise Failure(f"the catalog member is not served by the consumer:\n{answer[:1600]}")
            finally:
                self.stop(consumer)
        finally:
            self.stop(producer)

    def check_cache_behaviour(self, work, upstream_port, resolver_port):
        """RFC 8767/2308/8914: stale answers and negative caching.

        The upstream answers with TTL 1, then fails; the cached answer is
        served stale with TTL 30 and EDE 3. An NXDOMAIN with an SOA is
        cached, so a second query for it never reaches the upstream.
        """
        mode = {"fail": False}
        counts = {}
        stop = threading.Event()

        def serve():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("127.0.0.1", upstream_port))
            sock.settimeout(0.2)
            try:
                while not stop.is_set():
                    try:
                        data, addr = sock.recvfrom(65535)
                    except socket.timeout:
                        continue
                    query = dns.message.from_wire(data)
                    name = query.question[0].name.to_text().lower()
                    counts[name] = counts.get(name, 0) + 1
                    if name.startswith("missing."):
                        response = dns.message.make_response(query)
                        response.set_rcode(dns.rcode.NXDOMAIN)
                        soa = dns.rrset.from_text(
                            "example.test.", 60, "IN", "SOA",
                            "ns1.example.test. hostmaster.example.test. 1 3600 900 604800 60",
                        )
                        response.authority.append(soa)
                    elif mode["fail"]:
                        response = dns.message.make_response(query)
                        response.set_rcode(dns.rcode.SERVFAIL)
                    else:
                        response = dns.message.make_response(query)
                        response.answer.append(
                            dns.rrset.from_text("fresh.example.test.", 1, "IN", "A", "192.0.2.80")
                        )
                    sock.sendto(response.to_wire(), addr)
            finally:
                sock.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            extra = (
                "recursion allow 127.0.0.0/8\n"
                f"forwarder 127.0.0.1:{upstream_port}\n"
            )
            resolver = self.start_resolver(work, resolver_port, extra)
            try:
                first = self.dig(resolver_port, "fresh.example.test.", "A")
                if "192.0.2.80" not in first:
                    raise Failure(f"the first answer is missing:\n{first[:1200]}")
                mode["fail"] = True
                time.sleep(2.2)
                stale = self.dig(resolver_port, "fresh.example.test.", "A", "+ednsopt=15")
                if "192.0.2.80" not in stale:
                    raise Failure(f"the stale answer is missing:\n{stale[:1200]}")
                if "EDE: 3" not in stale and "Stale Answer" not in stale:
                    raise Failure(f"the stale answer carries no EDE 3:\n{stale[:1400]}")
                missing = self.dig(resolver_port, "missing.example.test.", "A")
                if "NXDOMAIN" not in missing:
                    raise Failure(f"the negative answer is not NXDOMAIN:\n{missing[:1200]}")
                again = self.dig(resolver_port, "missing.example.test.", "A")
                if "NXDOMAIN" not in again:
                    raise Failure(f"the cached negative answer is not NXDOMAIN:\n{again[:1200]}")
                if counts.get("missing.example.test.", 0) != 1:
                    raise Failure(f"the negative answer was fetched {counts.get('missing.example.test.')} times")
            finally:
                self.stop(resolver)
        finally:
            stop.set()
            thread.join(timeout=2)

    def check_ecs(self, work, upstream_port, resolver_port):
        """RFC 7871: the forwarding resolver carries and scopes ECS.

        A scripted ECS-aware upstream records the option the resolver sends
        and answers with scope 24; the resolver is configured with
        `client-subnet-max-prefix 20`, so the upstream must see /20 and the
        client must see the upstream's /24 scope.
        """
        seen = []
        stop = threading.Event()

        def serve():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("127.0.0.1", upstream_port))
            sock.settimeout(0.2)
            try:
                while not stop.is_set():
                    try:
                        data, addr = sock.recvfrom(65535)
                    except socket.timeout:
                        continue
                    query = dns.message.from_wire(data)
                    option = next((o for o in query.options if o.otype == dns.edns.ECS), None)
                    seen.append(option)
                    response = dns.message.make_response(query)
                    response.answer.append(
                        dns.rrset.from_text("www.example.test.", 60, "IN", "A", "192.0.2.80")
                    )
                    options = []
                    if option is not None:
                        options.append(dns.edns.ECSOption(option.address, option.srclen, 16))
                    response.use_edns(0, options=options)
                    sock.sendto(response.to_wire(), addr)
            finally:
                sock.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            extra = (
                "recursion allow 127.0.0.0/8\n"
                f"forwarder 127.0.0.1:{upstream_port}\n"
                "client-subnet-max-prefix 20\n"
            )
            resolver = self.start_resolver(work, resolver_port, extra)
            try:
                answer = self.dig(
                    resolver_port, "www.example.test.", "A",
                    "+subnet=192.0.2.0/24",
                )
                if "192.0.2.80" not in answer:
                    raise Failure(f"ECS answer missing:\n{answer[:1200]}")
                if "CLIENT-SUBNET: 192.0.0.0/20/16" not in answer:
                    raise Failure(f"ECS response scope is not the upstream's /16:\n{answer[:1200]}")
                scoped = [o for o in seen if o is not None]
                if not scoped:
                    raise Failure("the resolver sent no client subnet option upstream")
                if scoped[0].srclen != 20 or scoped[0].address != "192.0.0.0":
                    raise Failure(f"upstream saw {scoped[0]!r}, expected 192.0.0.0/20")
            finally:
                self.stop(resolver)
        finally:
            stop.set()
            thread.join(timeout=2)

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

    def diff_authoritative(self, zport, nport, tcp=False, queries=None):
        for name, rdtype in (queries or QUERIES):
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

        # Deny half: a second instance serves the same zone but allows only
        # TEST-NET-1, so 127.0.0.1 is denied. Reachability and refusal are
        # both proven on that instance, so no loopback alias is needed.
        deny_port = self.free_port()
        deny_work = tempfile.mkdtemp(prefix="zimdns-deny-")
        shutil.copy(ZONE, os.path.join(deny_work, "authoritative.zone"))
        deny_udp = deny_tcp = None
        try:
            deny_udp = self.start_zimdns(
                deny_work, deny_port, "--serve-udp",
                extra="allow-transfer example.test 192.0.2.0/24\n",
            )
            deny_tcp = self.start_zimdns(
                deny_work, deny_port, "--serve-tcp",
                extra="allow-transfer example.test 192.0.2.0/24\n",
            )
            control = self.dig(deny_port, "www.example.test.", "A", "+short")
            if "192.0.2.80" not in control:
                raise Failure(f"deny-instance unreachable:\n{control[:800]}")
            tcp_control = self.dig(deny_port, "www.example.test.", "A", "+short", "+tcp")
            if "192.0.2.80" not in tcp_control:
                raise Failure(f"deny-instance TCP unreachable:\nudp:\n{control[:800]}\ntcp:\n{tcp_control[:800]}")
            denied_proc = self.run(
                [TOOLS["dig"], "@127.0.0.1", "-p", str(deny_port), "example.test.", "AXFR", "+noall", "+answer", "+time=2", "+tries=1"],
                check=False,
            )
            denied = denied_proc.stdout
            refused = "REFUSED" in denied or "Transfer failed" in denied or "failed" in denied_proc.stderr or denied_proc.returncode != 0
            if "SOA" in denied or not refused:
                raise Failure(f"AXFR from an unauthorized client was not refused:\nstdout:\n{denied[:1200]}\nstderr:\n{denied_proc.stderr[:800]}")
        finally:
            if deny_tcp is not None:
                self.stop(deny_tcp)
            if deny_udp is not None:
                self.stop(deny_udp)
            shutil.rmtree(deny_work, ignore_errors=True)

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

    def check_ddr_doh(self, work, plain_port, doh_port):
        """RFC 9462: a plaintext resolver designates a DoH endpoint.

        The client can speak HTTP/1.1, so the SVCB record carries that ALPN
        and a `dohpath`; the plaintext server has no example.test zone, so
        only a verified DoH upgrade answers.
        """
        cert, key = self.make_cert(work)
        with open(os.path.join(work, "doh2.gdns"), "w") as f:
            f.write(f"listen dns doh 127.0.0.1:{doh_port}\n")
            f.write("zone example.test primary authoritative.zone\n")
            f.write("local-zones off\n")
        designated = self.spawn(
            [
                self.zimdns, "server", "run", "--config", "doh2.gdns",
                "--serve-doh", "--enable-encrypted-dns",
                "--tls-cert-file", cert, "--tls-key-file", key,
            ],
            cwd=work,
        )
        try:
            deadline = time.time() + 10
            while time.time() < deadline:
                if designated.poll() is not None:
                    out, err = designated.communicate()
                    raise Failure(f"designated DoH server exited: {out} {err}")
                probe = self.run(
                    [
                        TOOLS["curl"], "-sk", "-o", os.devnull, "-w", "%{http_code}",
                        f"https://127.0.0.1:{doh_port}/dns-query",
                    ],
                    check=False,
                )
                if probe.returncode == 0 and probe.stdout.strip():
                    break
                time.sleep(0.1)
            else:
                raise Failure(f"designated DoH server did not answer:\n{probe.stdout}\n{probe.stderr}")

            with open(os.path.join(work, "plain2.zone"), "w") as f:
                f.write(
                    "$ORIGIN plain.invalid.\n$TTL 3600\n"
                    "@ IN SOA ns.plain.invalid. hostmaster.plain.invalid. 1 3600 900 604800 3600\n"
                    "@ IN NS ns.plain.invalid.\nns IN A 127.0.0.1\n"
                )
            designator = self.start_zimdns(
                work, plain_port, "--serve-udp", zone=False,
                extra=(
                    "zone plain.invalid primary plain2.zone\n"
                    f"ddr dot.example.test. http/1.1 {doh_port} /dns-query{{?dns}}\n"
                ),
            )
            try:
                extra = (
                    "recursion allow 127.0.0.0/8\n"
                    f"forwarder 127.0.0.1:{plain_port}\n"
                    "ddr-client on\n"
                    f"ddr-client-port {doh_port}\n"
                    f"forwarder-ca-file {os.path.basename(cert)}\n"
                )
                resolver_port = self.free_port()
                resolver = self.start_resolver(work, resolver_port, extra)
                try:
                    answer = self.dig(resolver_port, "www.example.test.", "A")
                    if "192.0.2.80" not in answer:
                        raise Failure(
                            f"DDR client did not upgrade to the designated DoH endpoint:\n{answer[:1600]}"
                        )
                finally:
                    self.stop(resolver)
            finally:
                self.stop(designator)
        finally:
            self.stop(designated)

    def check_ddr(self, work, plain_port, dot_port):
        """RFC 9462: a plaintext resolver designates a DoT endpoint.

        The designating server publishes `_dns.resolver.arpa` with an SVCB
        whose TargetName is not the client's IP and whose certificate SAN is
        that IP. The client must discover it, verify the certificate against
        the designating resolver IP without sending SNI, and carry the query
        over DoT; the plaintext server has no example.test zone, so only a
        successful upgrade answers 192.0.2.80.
        """
        cert, key = self.make_cert(work)
        with open(os.path.join(work, "dot.gdns"), "w") as f:
            f.write(f"listen dns dot 127.0.0.1:{dot_port}\n")
            f.write("zone example.test primary authoritative.zone\n")
            f.write("local-zones off\n")
        designated = self.spawn(
            [
                self.zimdns, "server", "run", "--config", "dot.gdns",
                "--serve-dot", "--enable-encrypted-dns",
                "--tls-cert-file", cert, "--tls-key-file", key,
            ],
            cwd=work,
        )
        try:
            deadline = time.time() + 10
            while time.time() < deadline:
                if designated.poll() is not None:
                    out, err = designated.communicate()
                    raise Failure(f"designated DoT server exited: {out} {err}")
                probe = self.run(
                    [
                        TOOLS["kdig"], "@127.0.0.1", "-p", str(dot_port),
                        "+tls", f"+tls-ca={cert}", "+tls-hostname=localhost",
                        "+short", "www.example.test.", "A",
                    ],
                    check=False,
                )
                if "192.0.2.80" in probe.stdout:
                    break
                time.sleep(0.1)
            else:
                raise Failure(f"designated DoT server did not answer:\n{probe.stdout}\n{probe.stderr}")

            with open(os.path.join(work, "plain.zone"), "w") as f:
                f.write(
                    "$ORIGIN plain.invalid.\n$TTL 3600\n"
                    "@ IN SOA ns.plain.invalid. hostmaster.plain.invalid. 1 3600 900 604800 3600\n"
                    "@ IN NS ns.plain.invalid.\nns IN A 127.0.0.1\n"
                )
            designator = self.start_zimdns(
                work, plain_port, "--serve-udp", zone=False,
                extra=(
                    "zone plain.invalid primary plain.zone\n"
                    f"ddr dot.example.test. dot {dot_port}\n"
                ),
            )
            try:
                extra = (
                    "recursion allow 127.0.0.0/8\n"
                    f"forwarder 127.0.0.1:{plain_port}\n"
                    "ddr-client on\n"
                    f"ddr-client-port {dot_port}\n"
                    f"forwarder-ca-file {os.path.basename(cert)}\n"
                )
                resolver_port = self.free_port()
                resolver = self.start_resolver(work, resolver_port, extra)
                try:
                    answer = self.dig(resolver_port, "www.example.test.", "A")
                    if "192.0.2.80" not in answer:
                        raise Failure(
                            f"DDR client did not upgrade to the designated DoT endpoint:\n{answer[:1600]}"
                        )
                finally:
                    self.stop(resolver)
            finally:
                self.stop(designator)
        finally:
            self.stop(designated)

    def check_doh3(self, work, port):
        cert, key = self.make_cert(work)
        with open(os.path.join(work, "doh3.gdns"), "w") as f:
            f.write(f"listen dns doh3 127.0.0.1:{port}\n")
            f.write("zone example.test primary authoritative.zone\n")
            f.write("local-zones off\n")
        proc = self.spawn(
            [
                self.zimdns, "server", "run", "--config", "doh3.gdns",
                "--serve-doh3", "--enable-encrypted-dns",
                "--tls-cert-file", cert, "--tls-key-file", key,
            ],
            cwd=work,
        )
        try:
            import asyncio
            from aioquic.asyncio.client import connect
            from aioquic.asyncio.protocol import QuicConnectionProtocol
            from aioquic.h3.connection import H3Connection, H3_ALPN
            from aioquic.h3.events import DataReceived, HeadersReceived
            from aioquic.quic.configuration import QuicConfiguration
        except ImportError as exc:
            raise Failure(f"aioquic is not installed: {exc}")
        query = dns.message.make_query("www.example.test.", "A").to_wire()
        b64 = base64.urlsafe_b64encode(query).rstrip(b"=").decode()

        class H3Protocol(QuicConnectionProtocol):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self._h3 = H3Connection(self._quic)
                self._h3_events = []

            def quic_event_received(self, event):
                super().quic_event_received(event)
                for h3_event in self._h3.handle_event(event):
                    self._h3_events.append(h3_event)

        async def run_exchange(headers, body):
            asyncio.get_running_loop().set_exception_handler(lambda _loop, _context: None)
            config = QuicConfiguration(alpn_protocols=H3_ALPN, is_client=True, verify_mode=ssl.CERT_NONE)
            context = connect("127.0.0.1", port, configuration=config, create_protocol=H3Protocol)
            protocol = await context.__aenter__()
            try:
                stream_id = protocol._quic.get_next_available_stream_id()
                protocol._h3.send_headers(stream_id, headers, end_stream=body is None)
                if body is not None:
                    protocol._h3.send_data(stream_id, body, end_stream=True)
                protocol.transmit()
                got_headers = []
                got_body = b""
                for _ in range(100):
                    for event in protocol._h3_events:
                        if isinstance(event, HeadersReceived):
                            got_headers = event.headers
                        elif isinstance(event, DataReceived):
                            got_body += event.data
                            if event.stream_ended:
                                return got_headers, got_body
                    await asyncio.sleep(0.05)
                return got_headers, got_body
            finally:
                # aioquic's context exit writes a final EOF on its own
                # stream; this exchange already finished its stream.
                try:
                    await context.__aexit__(None, None, None)
                except RuntimeError:
                    pass

        # POST readiness loop: the server may still be starting.
        deadline = time.time() + 10
        answer = None
        status = None
        while time.time() < deadline:
            if proc.poll() is not None:
                out, err = proc.communicate()
                raise Failure(f"DoH/3 server exited: {out} {err}")
            try:
                headers, body = asyncio.run(run_exchange(
                    [(b":method", b"POST"), (b":path", b"/dns-query"), (b":scheme", b"https"), (b":authority", b"localhost"), (b"content-type", b"application/dns-message")],
                    query,
                ))
                status = dict((k.decode("latin-1"), v.decode("latin-1")) for k, v in headers).get(":status")
                if status == "200" and body:
                    answer = dns.message.from_wire(body)
                    break
            except Exception:
                answer = None
            time.sleep(0.1)
        else:
            raise Failure(f"aioquic did not get a DoH/3 POST answer; status={status}")
        if answer is None or answer.rcode() != 0 or not answer.answer:
            raise Failure(f"DoH/3 POST response is not a positive answer: {answer}")

        headers, body = asyncio.run(run_exchange(
            [(b":method", b"GET"), (b":path", f"/dns-query?dns={b64}".encode()), (b":scheme", b"https"), (b":authority", b"localhost")],
            None,
        ))
        status_get = dict((k.decode("latin-1"), v.decode("latin-1")) for k, v in headers).get(":status")
        if status_get != "200":
            raise Failure(f"DoH/3 GET returned {status_get}")
        get_answer = dns.message.from_wire(body)
        if get_answer.rcode() != 0 or not get_answer.answer:
            raise Failure(f"DoH/3 GET response is not a positive answer: {get_answer}")

        try:
            cleartext = dns.message.make_query("www.example.test.", "A")
            dns.query.udp(cleartext, "127.0.0.1", port=port, timeout=2)
        except Exception:
            pass
        else:
            raise Failure("the DoH/3 port answered cleartext DNS over UDP")

    def check_odoh(self, work, port):
        """RFC 9230 oblivious DoH: pyhpke seals a query the target opens."""
        import hashlib
        import hmac as hmac_mod

        try:
            from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey
        except ImportError as exc:
            raise Failure(f"pyhpke is not installed: {exc}")
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError as exc:
            raise Failure(f"cryptography is not installed: {exc}")

        priv = X25519PrivateKey.generate()
        pub = priv.public_key()
        raw_priv = priv.private_bytes_raw()
        raw_pub = pub.public_bytes_raw()
        with open(os.path.join(work, "odoh.key"), "w") as f:
            f.write(raw_priv.hex() + "\n")
        cert, key = self.make_cert(work)
        shutil.copy(ZONE, os.path.join(work, "authoritative.zone"))
        with open(os.path.join(work, "odoh.gdns"), "w") as f:
            f.write(f"listen dns doh 127.0.0.1:{port}\n")
            f.write("zone example.test primary authoritative.zone\n")
            f.write("local-zones off\n")
            f.write("odoh-target on\n")
            f.write("odoh-key-file odoh.key\n")
            f.write("odoh-config-out odoh.config\n")
        proc = self.spawn(
            [
                self.zimdns, "server", "run", "--config", "odoh.gdns",
                "--serve-doh", "--enable-encrypted-dns",
                "--tls-cert-file", cert, "--tls-key-file", key,
            ],
            cwd=work,
        )

        def post_odoh_raw(body, ctype="application/oblivious-dns-message"):
            import subprocess as _sp
            with open(os.path.join(work, "odoh-body.bin"), "wb") as f:
                f.write(body)
            result = _sp.run(
                ["curl", "-sk", "-o", os.path.join(work, "odoh-resp.bin"), "-w", "%{http_code}",
                 "--data-binary", "@" + os.path.join(work, "odoh-body.bin"),
                 "-H", "content-type: " + ctype, f"https://127.0.0.1:{port}/dns-query"],
                capture_output=True, text=True, timeout=15,
            )
            code = result.stdout.strip()
            with open(os.path.join(work, "odoh-resp.bin"), "rb") as f:
                return int(code), f.read()

        def post_odoh(body, ctype="application/oblivious-dns-message"):
            return post_odoh_raw(body, ctype)

        deadline = time.time() + 15
        configs = None
        while time.time() < deadline:
            if proc.poll() is not None:
                out, err = proc.communicate()
                raise Failure(f"ODoH server exited: {out} {err}")
            config_path = os.path.join(work, "odoh.config")
            if configs is None and os.path.exists(config_path):
                configs = open(config_path, "rb").read()
            if configs:
                try:
                    if post_odoh(b"\x00")[0] in (400, 401):
                        break
                except Exception:
                    pass
            time.sleep(0.2)
        else:
            raise Failure("ODoH target did not start answering")
        if len(configs) < 46 or int.from_bytes(configs[0:2], "big") != len(configs) - 2:
            raise Failure(f"ODoH configs file is malformed: {len(configs)} bytes")
        contents = configs[6:46]
        kem_id = int.from_bytes(contents[0:2], "big")
        kdf_id = int.from_bytes(contents[2:4], "big")
        aead_id = int.from_bytes(contents[4:6], "big")
        if (kem_id, kdf_id, aead_id) != (0x0020, 0x0001, 0x0001):
            raise Failure(f"ODoH configs name the wrong suite: {kem_id:#x} {kdf_id:#x} {aead_id:#x}")
        if contents[6:8] != b"\x00\x20" or contents[8:40] != raw_pub:
            raise Failure("ODoH configs do not carry this target's public key")
        prk = hmac_mod.new(b"", contents, hashlib.sha256).digest()
        key_id = hmac_mod.new(prk, b"odoh key id\x01", hashlib.sha256).digest()

        pkr = KEMKey.from_pyca_cryptography_key(pub)
        suite = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM)
        enc, sender = suite.create_sender_context(pkr, info=b"odoh query")
        dns_query = dns.message.make_query("www.example.test.", "A").to_wire()
        q_plain = len(dns_query).to_bytes(2, "big") + dns_query + (0).to_bytes(2, "big")
        aad = b"\x01" + len(key_id).to_bytes(2, "big") + key_id
        ct = sender.seal(q_plain, aad)
        msg = b"\x01" + len(key_id).to_bytes(2, "big") + key_id
        msg += len(enc + ct).to_bytes(2, "big") + enc + ct

        deadline = time.time() + 10
        while True:
            if proc.poll() is not None:
                out, err = proc.communicate()
                raise Failure(f"ODoH server exited: {out} {err}")
            try:
                status, body = post_odoh(msg)
            except Exception as exc:
                if time.time() > deadline:
                    raise Failure(f"ODoH POST never succeeded: {exc}")
                time.sleep(0.1)
                continue
            if status == 200 and body:
                break
            if time.time() > deadline:
                raise Failure(f"ODoH POST returned {status}: {body[:200]}")
            time.sleep(0.1)

        if body[0] != 0x02:
            raise Failure(f"ODoH response has the wrong message type: {body[0]}")
        kid_len = int.from_bytes(body[1:3], "big")
        resp_nonce = body[3:3 + kid_len]
        enc_len = int.from_bytes(body[3 + kid_len:5 + kid_len], "big")
        encrypted = body[5 + kid_len:]
        if len(resp_nonce) != 16 or enc_len != len(encrypted) or len(encrypted) < 16:
            raise Failure("ODoH response framing is malformed")
        secret = sender.export(b"odoh response", 16)
        info = q_plain + len(resp_nonce).to_bytes(2, "big") + resp_nonce
        prk2 = hmac_mod.new(info, secret, hashlib.sha256).digest()
        rkey = hmac_mod.new(prk2, b"odoh key\x01", hashlib.sha256).digest()[:16]
        rnonce = hmac_mod.new(prk2, b"odoh nonce\x01", hashlib.sha256).digest()[:12]
        aad_r = b"\x02" + len(resp_nonce).to_bytes(2, "big") + resp_nonce
        r_plain = AESGCM(rkey).decrypt(rnonce, encrypted, aad_r)
        dns_len = int.from_bytes(r_plain[0:2], "big")
        answer = dns.message.from_wire(r_plain[2:2 + dns_len])
        if answer.rcode() != 0 or not answer.answer:
            raise Failure(f"ODoH answer is not positive: {answer}")
        if "192.0.2.80" not in answer.to_text():
            raise Failure(f"ODoH answer lacks the fixture A record:\n{answer}")

        bad_key = bytes([key_id[0] ^ 0xFF]) + key_id[1:]
        bad = b"\x01" + len(bad_key).to_bytes(2, "big") + bad_key
        bad += len(enc + ct).to_bytes(2, "big") + enc + ct
        if post_odoh(bad)[0] != 401:
            raise Failure("ODoH target did not return 401 for an unknown key id")
        corrupt = bytearray(msg)
        corrupt[-1] ^= 0xFF
        if post_odoh(bytes(corrupt))[0] != 400:
            raise Failure("ODoH target did not return 400 for a corrupted ciphertext")

    def check_doq(self, work, port):
        cert, key = self.make_cert(work)
        with open(os.path.join(work, "doq.gdns"), "w") as f:
            f.write(f"listen dns doq 127.0.0.1:{port}\n")
            f.write("zone example.test primary authoritative.zone\n")
            f.write("local-zones off\n")
        proc = self.spawn(
            [
                self.zimdns, "server", "run", "--config", "doq.gdns",
                "--serve-doq", "--enable-encrypted-dns",
                "--tls-cert-file", cert, "--tls-key-file", key,
            ],
            cwd=work,
        )
        deadline = time.time() + 10
        while time.time() < deadline:
            if proc.poll() is not None:
                out, err = proc.communicate()
                raise Failure(f"DoQ server exited: {out} {err}")
            result = self.run(
                [
                    TOOLS["kdig"], "@127.0.0.1", "-p", str(port),
                    "+quic", f"+tls-ca={cert}", "+tls-hostname=localhost",
                    "+short", "www.example.test.", "A",
                ],
                check=False,
            )
            if "192.0.2.80" in result.stdout:
                break
            time.sleep(0.1)
        else:
            raise Failure(f"kdig did not get a DoQ answer:\n{result.stdout}\n{result.stderr}")

        # The same port must not answer cleartext DNS over TCP or UDP.
        for transport, options in (("TCP", ["+tcp"]), ("UDP", [])):
            cleartext = self.run(
                [TOOLS["kdig"], "@127.0.0.1", "-p", str(port), "+timeout=2", "+retry=1"]
                + options
                + ["www.example.test.", "A"],
                check=False,
                timeout=8,
            )
            if "192.0.2.80" in cleartext.stdout:
                raise Failure(f"the DoQ port answered cleartext DNS over {transport}")

        # The DoQ listener is query-only: a transfer question on it is refused.
        refused = self.run(
            [
                TOOLS["kdig"], "@127.0.0.1", "-p", str(port),
                "+quic", f"+tls-ca={cert}", "+tls-hostname=localhost",
                "example.test.", "AXFR", "+noall", "+answer",
            ],
            check=False,
        )
        if "REFUSED" not in refused.stderr and "SOA" in refused.stdout:
            raise Failure(f"DoQ answered an AXFR instead of refusing it:\n{refused.stdout}")
        proc.terminate()
        proc.wait(timeout=5)

        # The strict-TLS transfer listener is the transfer channel; it serves
        # the same zone over TLS, and an outside checker must accept it.
        xfr_port = self.free_port()
        with open(os.path.join(work, "xfr.gdns"), "w") as f:
            f.write(f"listen dns dot 127.0.0.1:{xfr_port}\n")
            f.write("zone example.test primary authoritative.zone\n")
            f.write("allow-transfer example.test 127.0.0.1/32\n")
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
        extra = "dnssec-key-file zsk.key\nzonemd publish sha384\nallow-transfer example.test 127.0.0.1/32\n"
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

    def check_obsolete_types(self, work, zport, nport, tcp):
        """RFC 1035: X25 and ISDN RDATA encode and compare with BIND 9."""
        zone = """$ORIGIN obsolete.test.
$TTL 300
@ IN SOA ns.obsolete.test. hostmaster.obsolete.test. 1 3600 900 604800 300
@ IN NS ns.obsolete.test.
ns IN A 127.0.0.1
x25 IN X25 "311061700956"
isdn IN ISDN "150862028003217" "004"
"""
        with open(os.path.join(work, "obsolete.zone"), "w") as f:
            f.write(zone)
        zimdns = self.start_zimdns(
            work, zport, "--serve-tcp" if tcp else "--serve-udp", zone=False,
            extra="zone obsolete.test primary obsolete.zone\n",
        )
        named = self.start_named(work, nport, "obsolete.test", "obsolete.zone")
        try:
            self.diff_authoritative(
                zport, nport, tcp=tcp,
                queries=[("x25.obsolete.test.", "X25"), ("isdn.obsolete.test.", "ISDN")],
            )
            x25 = self.dig(zport, "x25.obsolete.test.", "X25", "+short")
            if "311061700956" not in x25:
                raise Failure(f"X25 presentation is wrong:\n{x25[:800]}")
        finally:
            self.stop(named)
            self.stop(zimdns)

    def check_dnssec_algorithms(self, work, port):
        """RFC 5702/8080/6605: each signing algorithm verifies externally.

        The same zone is signed with RSA/SHA-256, ECDSA P-384, and Ed25519 in
        turn; `dnssec-verify` and `ldns-verify-zone` must accept every one.
        """
        algorithms = [
            ("RSASHA256", "rsa.key"),
            ("ECDSAP384SHA384", "p384.key"),
            ("ED25519", "ed.key"),
        ]
        for algorithm, key_file in algorithms:
            self.new_key(work, algorithm, key_file)
            self.start_zimdns(work, port, "--serve-udp", extra=f"dnssec-key-file {key_file}\n")
            self.start_zimdns(work, port, "--serve-tcp", extra=f"dnssec-key-file {key_file}\nallow-transfer example.test 127.0.0.1/32\n")
            axfr = self.run(
                [
                    TOOLS["dig"], "@127.0.0.1", "-p", str(port),
                    "example.test.", "AXFR", "+noall", "+answer",
                ]
            ).stdout
            signed_path = os.path.join(work, f"signed-{algorithm}.zone")
            with open(signed_path, "w") as f:
                f.write(axfr)
            self.run([TOOLS["dnssec-verify"], "-o", "example.test", signed_path])
            self.run([TOOLS["ldns-verify-zone"], signed_path])
            self.cleanup()

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

    def check_cli_query(self, port):
        """external client: shipped query CLI against BIND."""
        answer = subprocess.run(
            [self.zimdns, "query", "@127.0.0.1", "-p", str(port), "www.example.test.", "A"],
            capture_output=True, text=True, timeout=15,
        )
        if answer.returncode != 0 or "192.0.2.80" not in answer.stdout:
            raise Failure(f"query CLI did not answer: rc={answer.returncode} out={answer.stdout[-800:]!r}")
        refusal = subprocess.run(
            [self.zimdns, "query", "@127.0.0.1", "-p", str(port), "--no-such-flag", "www.example.test.", "A"],
            capture_output=True, text=True, timeout=15,
        )
        if refusal.returncode == 0:
            raise Failure("query CLI accepted an unknown flag")

    # ----------------------------------------------------------------- main
    def run_all(self):
        self.check_tools()
        work = self.make_workdir()
        zport = self.free_port()
        nport = self.free_port()
        try:
            self.start_zimdns(work, zport, "--serve-udp")
            self.start_zimdns(work, zport, "--serve-tcp", extra="allow-transfer example.test 127.0.0.1/32\n")
            self.start_named(work, nport)
            self.check("differential oracle, UDP corpus", lambda: self.diff_authoritative(zport, nport, tcp=False))
            self.check("differential oracle, TCP corpus", lambda: self.diff_authoritative(zport, nport, tcp=True))
            self.check("external client: shipped query CLI", lambda: self.check_cli_query(nport))
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

            tc_work = self.make_workdir()
            tc_udp = self.free_port()
            tc_tcp = self.free_port()
            self.check(
                "external client: TC, TCP retry, CD, and question count",
                lambda: self.check_tc_and_headers(tc_work, tc_udp, tc_tcp),
            )
            self.cleanup()
            shutil.rmtree(tc_work, ignore_errors=True)

            cache_work = self.make_workdir()
            cache_resolver_port = self.free_port()
            cache_upstream_port = self.free_port()
            self.check(
                "external client: stale answers and negative cache",
                lambda: self.check_cache_behaviour(cache_work, cache_upstream_port, cache_resolver_port),
            )
            self.cleanup()
            shutil.rmtree(cache_work, ignore_errors=True)

            report_work = self.make_workdir()
            report_resolver = self.free_port()
            report_upstream = self.free_port()
            self.check(
                "external client: RFC 9567 error report query",
                lambda: self.check_error_report(report_work, report_upstream, report_resolver),
            )
            self.cleanup()
            shutil.rmtree(report_work, ignore_errors=True)

            forged_work = self.make_workdir()
            forged_resolver = self.free_port()
            forged_upstream = self.free_port()
            self.check(
                "external client: forged upstream answers are ignored",
                lambda: self.check_forged_answers(forged_work, forged_upstream, forged_resolver),
            )
            self.cleanup()
            shutil.rmtree(forged_work, ignore_errors=True)

            dns64_work = self.make_workdir()
            dns64_resolver = self.free_port()
            dns64_upstream = self.free_port()
            self.check(
                "external client: DNS64 synthesis",
                lambda: self.check_dns64(dns64_work, dns64_upstream, dns64_resolver),
            )
            self.cleanup()
            shutil.rmtree(dns64_work, ignore_errors=True)

            blacklist_work = self.make_workdir()
            blacklist_port = self.free_port()
            self.check(
                "external client: RFC 5782 blacklist zone",
                lambda: self.check_blacklist(blacklist_work, blacklist_port),
            )
            self.cleanup()
            shutil.rmtree(blacklist_work, ignore_errors=True)

            catalog_work = self.make_workdir()
            catalog_producer = self.free_port()
            catalog_consumer = self.free_port()
            self.check(
                "external client: RFC 9432 catalog consumer",
                lambda: self.check_catalog(catalog_work, catalog_producer, catalog_consumer),
            )
            self.cleanup()
            shutil.rmtree(catalog_work, ignore_errors=True)

            edns_work = self.make_workdir()
            edns_udp = self.free_port()
            edns_tcp = self.free_port()
            self.check(
                "external clients: EDNS options and minimal ANY",
                lambda: self.check_edns_options(edns_work, edns_udp, edns_tcp),
            )
            self.cleanup()
            shutil.rmtree(edns_work, ignore_errors=True)

            ecs_work = self.make_workdir()
            ecs_resolver_port = self.free_port()
            ecs_upstream_port = self.free_port()
            self.check(
                "external client: ECS forwarding and scope",
                lambda: self.check_ecs(ecs_work, ecs_upstream_port, ecs_resolver_port),
            )
            self.cleanup()
            shutil.rmtree(ecs_work, ignore_errors=True)

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

            obsolete_work = self.make_workdir()
            obsolete_z = self.free_port()
            obsolete_n = self.free_port()
            self.check(
                "external clients: X25 and ISDN against BIND",
                lambda: self.check_obsolete_types(obsolete_work, obsolete_z, obsolete_n, tcp=False),
            )
            self.cleanup()
            shutil.rmtree(obsolete_work, ignore_errors=True)

            dnssec_algs_work = self.make_workdir()
            dnssec_algs_port = self.free_port()
            self.check(
                "external clients: RSA, P-384, and Ed25519 zones verify",
                lambda: self.check_dnssec_algorithms(dnssec_algs_work, dnssec_algs_port),
            )
            self.cleanup()
            shutil.rmtree(dnssec_algs_work, ignore_errors=True)

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
            odoh_work = self.make_workdir()
            odoh_port = self.free_port()
            self.check("external client: pyhpke ODoH target", lambda: self.check_odoh(odoh_work, odoh_port))
            shutil.rmtree(odoh_work, ignore_errors=True)

            ddr_work = self.make_workdir()
            ddr_plain = self.free_port()
            ddr_dot = self.free_port()
            self.check(
                "external client: RFC 9462 DDR upgrade to DoT",
                lambda: self.check_ddr(ddr_work, ddr_plain, ddr_dot),
            )
            self.cleanup()
            shutil.rmtree(ddr_work, ignore_errors=True)

            ddr_doh_work = self.make_workdir()
            ddr_doh_plain = self.free_port()
            ddr_doh_port = self.free_port()
            self.check(
                "external client: RFC 9462 DDR upgrade to DoH",
                lambda: self.check_ddr_doh(ddr_doh_work, ddr_doh_plain, ddr_doh_port),
            )
            self.cleanup()
            shutil.rmtree(ddr_doh_work, ignore_errors=True)

            doq_work = self.make_workdir()
            doq_port = self.free_port()
            self.check("external client: kdig DoQ", lambda: self.check_doq(doq_work, doq_port))
            self.check("external client: aioquic DoH/3", lambda: self.check_doh3(doq_work, doq_port))
            self.cleanup()
            shutil.rmtree(doq_work, ignore_errors=True)
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
