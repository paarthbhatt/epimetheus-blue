#!/usr/bin/env python3
"""Raw IPv4/UDP probes; invoked only by scripts/test-firewall-netns.sh."""

import errno
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time


class Failure(Exception):
    pass


class Skip(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Failure(message)


def run(*args, text=None):
    result = subprocess.run(args, input=text, text=True, capture_output=True)
    if result.returncode:
        detail = result.stderr.strip()
        if "Operation not permitted" in detail or "Permission denied" in detail:
            raise Skip(f"{args[0]} permission unavailable: {detail}")
        raise Failure(f"{' '.join(args)}: {detail}")
    return result.stdout


def checksum(data):
    data += b"\0" * (len(data) % 2)
    value = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while value >> 16:
        value = (value & 0xFFFF) + (value >> 16)
    return ~value & 0xFFFF


LOCAL, ALLOWED, OUTSIDE = "192.0.2.1", "192.0.2.2", "198.51.100.2"
PORT = 42424
LOCAL_MAC = bytes.fromhex("020000000001")
PEER_MAC = bytes.fromhex("020000000002")
DELETE = "delete table inet epimetheus_blue\n"


def frame(source, sport, dport, payload, sequence):
    src, dst = socket.inet_aton(source), socket.inet_aton(LOCAL)
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    pseudo = src + dst + struct.pack("!BBH", 0, 17, len(udp))
    udp = udp[:6] + struct.pack("!H", checksum(pseudo + udp) or 0xFFFF) + udp[8:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), sequence,
                     0, 64, 17, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return LOCAL_MAC + PEER_MAC + b"\x08\x00" + ip + udp


def capture(sock, matches):
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        sock.settimeout(max(0.001, deadline - time.monotonic()))
        try:
            packet = sock.recv(65535)
        except socket.timeout:
            break
        if matches(packet):
            return packet
    raise Failure("expected Ethernet packet did not reach the veth peer/interface")


class Probes:
    def __init__(self):
        self.sequence = 0
        self.peer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        self.peer.bind(("blue-peer", 0))
        self.ingress = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        self.ingress.bind(("blue-in", 0))

    def inbound(self, source, port, receives):
        self.sequence += 1  # Fresh conntrack tuple for every probe, including retries.
        sport = 40000 + self.sequence
        payload = f"blue-inbound-{self.sequence}".encode()
        packet = frame(source, sport, port, payload, self.sequence)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
            listener.bind((LOCAL, port))
            listener.settimeout(1.0 if receives else 0.25)
            require(self.peer.send(packet) == len(packet), "short Ethernet send")
            capture(self.ingress, lambda received: received == packet)
            try:
                data, address = listener.recvfrom(65535)
            except socket.timeout:
                require(not receives, f"UDP {source}:{sport} -> {port} was unexpectedly blocked")
            else:
                require(receives, f"UDP {source}:{sport} -> {port} was unexpectedly allowed")
                require(data == payload and address == (source, sport), "wrong inbound datagram")

    def matrix(self, receives):
        for source, port in [(ALLOWED, PORT), (ALLOWED, PORT + 1), (OUTSIDE, PORT)]:
            self.inbound(source, port, receives)

    def controls(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            listener.bind(("127.0.0.1", 0))
            listener.settimeout(1.0)
            sender.sendto(b"blue-loopback", listener.getsockname())
            require(listener.recv(128) == b"blue-loopback", "loopback failed")

        self.sequence += 1
        sport, remote_port = 45000 + self.sequence, 46000 + self.sequence
        payload = f"blue-outbound-{self.sequence}".encode()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.bind((LOCAL, sport))
            sender.settimeout(1.0)
            sender.sendto(payload, (ALLOWED, remote_port))

            def outbound(packet):
                if len(packet) < 42 or packet[12:14] != b"\x08\x00" or packet[23] != 17:
                    return False
                offset = 14 + (packet[14] & 15) * 4
                return (packet[26:34] == socket.inet_aton(LOCAL) + socket.inet_aton(ALLOWED)
                        and packet[offset:offset + 4] == struct.pack("!HH", sport, remote_port)
                        and packet[offset + 8:] == payload)

            capture(self.peer, outbound)  # Actual kernel output, not a local/loopback route.
            reply = frame(ALLOWED, remote_port, sport, payload, self.sequence)
            self.peer.send(reply)
            data, address = sender.recvfrom(65535)
            require(data == payload and address == (ALLOWED, remote_port),
                    "outbound established UDP reply failed")


def apply(policy, replace=False):
    batch = (DELETE if replace else "") + policy
    run("nft", "--check", "--file", "-", text=batch)
    run("nft", "--file", "-", text=batch)


def main():
    require(len(sys.argv) == 6, "invoke scripts/test-firewall-netns.sh")
    uid, parent_user, parent_net, public_path, exception_path = sys.argv[1:]
    user_ns = os.readlink("/proc/self/ns/user")
    net_ns = os.readlink("/proc/self/ns/net")
    require(user_ns != parent_user and net_ns != parent_net, "refusing the parent/host namespaces")
    require(os.getuid() == 0 and int(uid) > 0
            and Path("/proc/self/uid_map").read_text().split() == ["0", uid, "1"],
            "refusing anything except an unprivileged map-root-user namespace")
    print(f"ISOLATED: {parent_net} -> {net_ns}; mapped uid {uid}", flush=True)

    tables = json.loads(run("nft", "--json", "list", "tables"))["nftables"]
    require(not any("table" in item for item in tables), "new namespace has unexpected nft tables")
    public = Path(public_path).read_text()
    exception = Path(exception_path).read_text()
    for policy in (public, exception):
        require(policy.startswith("table inet epimetheus_blue {\n"), "unexpected policy table")
    run("ip", "link", "set", "lo", "up")
    run("ip", "link", "add", "blue-in", "type", "veth", "peer", "name", "blue-peer")
    for interface, mac in [("blue-in", "02:00:00:00:00:01"),
                           ("blue-peer", "02:00:00:00:00:02")]:
        run("ip", "link", "set", interface, "address", mac, "up")
    run("ip", "address", "add", f"{LOCAL}/24", "dev", "blue-in")
    run("ip", "route", "add", "198.51.100.0/24", "dev", "blue-in")
    run("ip", "neigh", "add", ALLOWED, "lladdr", "02:00:00:00:00:02",
        "nud", "permanent", "dev", "blue-in")
    probes = Probes()

    probes.matrix(True)
    print("PASS: no-rules baseline receives all 3 UDP probes", flush=True)
    apply(public)
    probes.matrix(False)
    probes.controls()
    print("PASS: Public drops all 3; loopback and outbound/established reply receive", flush=True)

    # Production rollback for an originally absent table is owned-table removal.
    run("nft", "--file", "-", text=DELETE)
    probes.matrix(True)
    print("PASS: rollback-to-absent restores all 3 baseline probes", flush=True)

    apply(public)
    snapshot = run("nft", "--stateless", "list", "table", "inet", "epimetheus_blue")
    apply(exception, replace=True)
    probes.inbound(ALLOWED, PORT, True)
    probes.inbound(ALLOWED, PORT + 1, False)
    probes.inbound(OUTSIDE, PORT, False)
    probes.controls()
    print("PASS: rendered UDP/CIDR exception receives; wrong port/CIDR drop; controls receive", flush=True)

    apply(snapshot, replace=True)
    probes.matrix(False)
    print("PASS: snapshot rollback restores Public denial", flush=True)
    run("nft", "--file", "-", text=DELETE)
    probes.matrix(True)
    tables = json.loads(run("nft", "--json", "list", "tables"))["nftables"]
    require(not any("table" in item for item in tables), "owned table remained after removal")
    print("PASS: removal restores all 3 baseline probes; namespace exits cleanly", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Skip as error:
        print(f"SKIP: {error}", file=sys.stderr)
        sys.exit(77)
    except OSError as error:
        if error.errno in (errno.EPERM, errno.EACCES):
            print(f"SKIP: namespace/raw-socket permission unavailable: {error}", file=sys.stderr)
            sys.exit(77)
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
    except (Failure, ValueError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
