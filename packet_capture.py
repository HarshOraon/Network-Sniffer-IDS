#!/usr/bin/env python3
"""
Packet Capture

A small network packet capture program for Python.

Features:
  - Captures packets with Scapy when available.
  - Falls back to raw sockets on Linux and Windows.
  - Prints compact packet summaries.
  - Optionally writes captured packets to a .pcap file.

Notes:
  - Packet capture usually requires Administrator/root privileges.
  - On Windows, install Npcap and Scapy for the best experience.
  - The raw Windows fallback captures IP packets, not full Ethernet frames.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import platform
import socket
import struct
import sys
import time
from dataclasses import dataclass
from typing import Callable, Optional


ETHERTYPES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x8100: "802.1Q",
    0x86DD: "IPv6",
}

IP_PROTOCOLS = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
}

TCP_FLAGS = [
    (0x80, "CWR"),
    (0x40, "ECE"),
    (0x20, "URG"),
    (0x10, "ACK"),
    (0x08, "PSH"),
    (0x04, "RST"),
    (0x02, "SYN"),
    (0x01, "FIN"),
]


@dataclass
class PacketSummary:
    timestamp: float
    length: int
    layer2: str = "-"
    network: str = "-"
    transport: str = "-"
    src: str = "-"
    dst: str = "-"
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    info: str = ""

    def endpoint_text(self) -> str:
        left = self.src
        right = self.dst
        if self.src_port is not None:
            left = f"{left}:{self.src_port}"
        if self.dst_port is not None:
            right = f"{right}:{self.dst_port}"
        return f"{left} -> {right}"

    def protocol_text(self) -> str:
        parts = [part for part in (self.layer2, self.network, self.transport) if part and part != "-"]
        return "/".join(parts) if parts else "-"

    def format(self, show_time: bool = True) -> str:
        stamp = ""
        if show_time:
            stamp = dt.datetime.fromtimestamp(self.timestamp).strftime("%H:%M:%S.%f")[:-3] + " "
        info = f" {self.info}" if self.info else ""
        return f"{stamp}{self.length:>6} bytes  {self.protocol_text():<16} {self.endpoint_text()}{info}"


class PcapWriter:
    """Minimal pcap writer for raw packet bytes."""

    # Common link-layer values:
    # 1 = Ethernet, 101 = raw IP.
    def __init__(self, path: str, linktype: int) -> None:
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        self.path = path
        self.file = open(path, "wb")
        self.file.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))

    def write(self, payload: bytes, timestamp: Optional[float] = None) -> None:
        ts = time.time() if timestamp is None else timestamp
        seconds = int(ts)
        micros = int((ts - seconds) * 1_000_000)
        self.file.write(struct.pack("<IIII", seconds, micros, len(payload), len(payload)))
        self.file.write(payload)

    def close(self) -> None:
        self.file.close()

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def mac_addr(data: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in data)


def ipv4_addr(data: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET, data)


def ipv6_addr(data: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET6, data)


def decode_packet(
    payload: bytes,
    timestamp: Optional[float] = None,
    linktype: int = 1,
    payload_preview: int = 0,
) -> PacketSummary:
    timestamp = time.time() if timestamp is None else timestamp
    if linktype == 1:
        return decode_ethernet(payload, timestamp, payload_preview)
    if linktype == 101:
        return decode_raw_ip(payload, timestamp, payload_preview)
    return PacketSummary(timestamp=timestamp, length=len(payload), layer2=f"linktype-{linktype}")


def decode_ethernet(frame: bytes, timestamp: float, payload_preview: int = 0) -> PacketSummary:
    summary = PacketSummary(timestamp=timestamp, length=len(frame), layer2="Ethernet")
    if len(frame) < 14:
        summary.info = "truncated Ethernet header"
        return summary

    dst_mac = mac_addr(frame[0:6])
    src_mac = mac_addr(frame[6:12])
    ethertype = struct.unpack("!H", frame[12:14])[0]
    offset = 14

    vlan_tags = []
    while ethertype in (0x8100, 0x88A8) and len(frame) >= offset + 4:
        tag_control = struct.unpack("!H", frame[offset : offset + 2])[0]
        vlan_tags.append(str(tag_control & 0x0FFF))
        ethertype = struct.unpack("!H", frame[offset + 2 : offset + 4])[0]
        offset += 4

    summary.network = ETHERTYPES.get(ethertype, f"0x{ethertype:04x}")
    if vlan_tags:
        summary.info = f"vlan={','.join(vlan_tags)}"

    if ethertype == 0x0800:
        return decode_ipv4(frame[offset:], timestamp, len(frame), layer2="Ethernet", payload_preview=payload_preview)
    if ethertype == 0x86DD:
        return decode_ipv6(frame[offset:], timestamp, len(frame), layer2="Ethernet", payload_preview=payload_preview)
    if ethertype == 0x0806:
        return decode_arp(frame[offset:], timestamp, len(frame), src_mac, dst_mac)

    summary.src = src_mac
    summary.dst = dst_mac
    if not summary.info:
        summary.info = "unsupported ethertype"
    return summary


def decode_raw_ip(packet: bytes, timestamp: float, payload_preview: int = 0) -> PacketSummary:
    if not packet:
        return PacketSummary(timestamp=timestamp, length=0, network="IP", info="empty packet")

    version = packet[0] >> 4
    if version == 4:
        return decode_ipv4(packet, timestamp, len(packet), layer2="RawIP", payload_preview=payload_preview)
    if version == 6:
        return decode_ipv6(packet, timestamp, len(packet), layer2="RawIP", payload_preview=payload_preview)
    return PacketSummary(timestamp=timestamp, length=len(packet), layer2="RawIP", info=f"unknown IP version {version}")


def decode_ipv4(
    packet: bytes,
    timestamp: float,
    frame_len: int,
    layer2: str,
    payload_preview: int = 0,
) -> PacketSummary:
    summary = PacketSummary(timestamp=timestamp, length=frame_len, layer2=layer2, network="IPv4")
    if len(packet) < 20:
        summary.info = "truncated IPv4 header"
        return summary

    version = packet[0] >> 4
    header_len = (packet[0] & 0x0F) * 4
    if version != 4 or header_len < 20:
        summary.info = "invalid IPv4 header"
        return summary
    if len(packet) < header_len:
        summary.info = "truncated IPv4 options"
        return summary

    total_len = struct.unpack("!H", packet[2:4])[0]
    proto_num = packet[9]
    summary.transport = IP_PROTOCOLS.get(proto_num, str(proto_num))
    summary.src = ipv4_addr(packet[12:16])
    summary.dst = ipv4_addr(packet[16:20])

    effective_len = min(total_len, len(packet)) if total_len else len(packet)
    segment = packet[header_len:effective_len]
    apply_transport_decode(summary, segment, proto_num, payload_preview)
    return summary


def decode_ipv6(
    packet: bytes,
    timestamp: float,
    frame_len: int,
    layer2: str,
    payload_preview: int = 0,
) -> PacketSummary:
    summary = PacketSummary(timestamp=timestamp, length=frame_len, layer2=layer2, network="IPv6")
    if len(packet) < 40:
        summary.info = "truncated IPv6 header"
        return summary

    version = packet[0] >> 4
    if version != 6:
        summary.info = "invalid IPv6 header"
        return summary

    payload_len = struct.unpack("!H", packet[4:6])[0]
    next_header = packet[6]
    summary.transport = IP_PROTOCOLS.get(next_header, str(next_header))
    summary.src = ipv6_addr(packet[8:24])
    summary.dst = ipv6_addr(packet[24:40])

    end = min(40 + payload_len, len(packet)) if payload_len else len(packet)
    segment = packet[40:end]
    apply_transport_decode(summary, segment, next_header, payload_preview)
    return summary


def decode_arp(packet: bytes, timestamp: float, frame_len: int, src_mac: str, dst_mac: str) -> PacketSummary:
    summary = PacketSummary(
        timestamp=timestamp,
        length=frame_len,
        layer2="Ethernet",
        network="ARP",
        src=src_mac,
        dst=dst_mac,
    )
    if len(packet) < 28:
        summary.info = "truncated ARP"
        return summary

    operation = struct.unpack("!H", packet[6:8])[0]
    sender_ip = ipv4_addr(packet[14:18])
    target_ip = ipv4_addr(packet[24:28])
    if operation == 1:
        summary.info = f"who-has {target_ip} tell {sender_ip}"
    elif operation == 2:
        summary.info = f"is-at {sender_ip}"
    else:
        summary.info = f"operation={operation} {sender_ip}->{target_ip}"
    return summary


def apply_transport_decode(
    summary: PacketSummary,
    segment: bytes,
    proto_num: int,
    payload_preview: int = 0,
) -> None:
    if proto_num == 6:
        decode_tcp(summary, segment, payload_preview)
    elif proto_num == 17:
        decode_udp(summary, segment, payload_preview)
    elif proto_num in (1, 58):
        decode_icmp(summary, segment)
    else:
        if segment:
            summary.info = f"payload={len(segment)} bytes"


def decode_tcp(summary: PacketSummary, segment: bytes, payload_preview: int = 0) -> None:
    if len(segment) < 20:
        summary.info = "truncated TCP header"
        return

    src_port, dst_port = struct.unpack("!HH", segment[0:4])
    data_offset = (segment[12] >> 4) * 4
    flags = segment[13]
    summary.src_port = src_port
    summary.dst_port = dst_port

    names = [name for value, name in TCP_FLAGS if flags & value]
    flag_text = ",".join(names) if names else "none"
    payload_len = max(0, len(segment) - data_offset)
    summary.info = f"flags={flag_text} payload={payload_len}"
    append_payload_preview(summary, segment[data_offset:], payload_preview)


def decode_udp(summary: PacketSummary, segment: bytes, payload_preview: int = 0) -> None:
    if len(segment) < 8:
        summary.info = "truncated UDP header"
        return

    src_port, dst_port, udp_len = struct.unpack("!HHH", segment[:6])
    summary.src_port = src_port
    summary.dst_port = dst_port
    payload_len = max(0, min(udp_len, len(segment)) - 8)
    summary.info = f"payload={payload_len}"
    append_payload_preview(summary, segment[8 : 8 + payload_len], payload_preview)


def decode_icmp(summary: PacketSummary, segment: bytes) -> None:
    if len(segment) < 2:
        summary.info = "truncated ICMP header"
        return
    summary.info = f"type={segment[0]} code={segment[1]}"


def append_payload_preview(summary: PacketSummary, payload: bytes, limit: int) -> None:
    if limit <= 0 or not payload:
        return
    preview = payload[:limit]
    safe = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in preview)
    suffix = "..." if len(payload) > limit else ""
    summary.info = f"{summary.info} preview={safe}{suffix}"


def print_banner(args: argparse.Namespace, backend: str) -> None:
    print("Packet Capture")
    print(f"backend: {backend}")
    if args.interface:
        print(f"interface: {args.interface}")
    if args.host:
        print(f"host: {args.host}")
    if args.filter:
        print(f"filter: {args.filter}")
    if args.output:
        print(f"pcap output: {args.output}")
    limits = []
    if args.count:
        limits.append(f"count={args.count}")
    if args.duration:
        limits.append(f"duration={args.duration}s")
    print("limits: " + (", ".join(limits) if limits else "none, press Ctrl+C to stop"))
    print("-" * 88)


def import_scapy():
    try:
        import scapy.all as scapy  # type: ignore
    except ImportError:
        return None
    return scapy


def list_scapy_interfaces() -> int:
    scapy = import_scapy()
    if scapy is None:
        print("Scapy is not installed. Install it with: python -m pip install scapy")
        return 1

    print("Available interfaces:")
    for iface in scapy.get_if_list():
        print(f"  {iface}")
    return 0


def capture_with_scapy(args: argparse.Namespace) -> int:
    scapy = import_scapy()
    if scapy is None:
        raise RuntimeError("Scapy is not installed")

    packet_count = 0
    start = time.monotonic()
    writer = PcapWriter(args.output, linktype=1) if args.output else None

    def handle_packet(packet) -> None:
        nonlocal packet_count
        packet_count += 1
        timestamp = float(getattr(packet, "time", time.time()))

        if packet.haslayer(scapy.Ether):
            raw = bytes(packet)
            linktype = 1
        elif packet.haslayer(scapy.IP):
            raw = bytes(packet[scapy.IP])
            linktype = 101
        elif packet.haslayer(scapy.IPv6):
            raw = bytes(packet[scapy.IPv6])
            linktype = 101
        else:
            raw = bytes(packet)
            linktype = 0

        summary = decode_packet(raw, timestamp=timestamp, linktype=linktype, payload_preview=args.payload_preview)
        print(summary.format(show_time=not args.no_time))

        if writer is not None:
            writer.write(raw, timestamp)

    print_banner(args, "scapy")
    try:
        try:
            scapy.sniff(
                iface=args.interface,
                count=args.count or 0,
                timeout=args.duration or None,
                filter=args.filter,
                prn=handle_packet,
                store=False,
                promisc=not args.no_promiscuous,
            )
        except Exception as exc:
            if "layer 2" not in str(exc).lower() and "winpcap" not in str(exc).lower():
                raise
            if writer is not None:
                writer.close()
            print("layer-2 capture is unavailable; retrying with Scapy layer-3 socket", file=sys.stderr)
            return capture_with_scapy_l3(args, scapy)
    finally:
        if writer is not None:
            try:
                writer.close()
            except ValueError:
                pass

    elapsed = time.monotonic() - start
    print("-" * 88)
    print(f"captured {packet_count} packet(s) in {elapsed:.2f}s")
    return 0


def capture_with_scapy_l3(args: argparse.Namespace, scapy) -> int:
    if args.filter:
        print("warning: --filter is only supported by layer-2 Scapy/libpcap capture", file=sys.stderr)

    packet_count = 0
    start = time.monotonic()
    writer = PcapWriter(args.output, linktype=101) if args.output else None
    l3_socket = scapy.conf.L3socket(iface=args.interface, promisc=not args.no_promiscuous)

    def handle_packet(packet) -> None:
        nonlocal packet_count
        packet_count += 1
        timestamp = float(getattr(packet, "time", time.time()))

        if packet.haslayer(scapy.IP):
            raw = bytes(packet[scapy.IP])
        elif packet.haslayer(scapy.IPv6):
            raw = bytes(packet[scapy.IPv6])
        else:
            raw = bytes(packet)

        summary = decode_packet(raw, timestamp=timestamp, linktype=101, payload_preview=args.payload_preview)
        print(summary.format(show_time=not args.no_time))
        if writer is not None:
            writer.write(raw, timestamp)

    print_banner(args, "scapy-l3")
    try:
        scapy.sniff(
            opened_socket=l3_socket,
            count=args.count or 0,
            timeout=args.duration or None,
            prn=handle_packet,
            store=False,
        )
    finally:
        l3_socket.close()
        if writer is not None:
            writer.close()

    elapsed = time.monotonic() - start
    print("-" * 88)
    print(f"captured {packet_count} packet(s) in {elapsed:.2f}s")
    return 0


def capture_with_raw_socket(args: argparse.Namespace) -> int:
    system = platform.system().lower()
    if system == "linux" and hasattr(socket, "AF_PACKET"):
        return capture_raw_linux(args)
    if system == "windows":
        return capture_raw_windows(args)

    raise RuntimeError(
        "raw socket fallback supports Linux and Windows only. "
        "Install Scapy/libpcap for this operating system."
    )


def capture_raw_linux(args: argparse.Namespace) -> int:
    if args.filter:
        print("warning: --filter is only supported by the Scapy backend", file=sys.stderr)

    packet_count = 0
    start_monotonic = time.monotonic()
    writer = PcapWriter(args.output, linktype=1) if args.output else None

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    if args.interface:
        sock.bind((args.interface, 0))
    sock.settimeout(0.5)

    print_banner(args, "raw-linux")
    try:
        while should_continue(args, packet_count, start_monotonic):
            try:
                frame, _addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            timestamp = time.time()
            packet_count += 1
            summary = decode_packet(frame, timestamp=timestamp, linktype=1, payload_preview=args.payload_preview)
            print(summary.format(show_time=not args.no_time))
            if writer is not None:
                writer.write(frame, timestamp)
    except KeyboardInterrupt:
        print("\nstopped by user")
    finally:
        sock.close()
        if writer is not None:
            writer.close()

    elapsed = time.monotonic() - start_monotonic
    print("-" * 88)
    print(f"captured {packet_count} packet(s) in {elapsed:.2f}s")
    if args.output and packet_count == 0:
        print(f"created empty pcap header at {args.output}")
    return 0


def capture_raw_windows(args: argparse.Namespace) -> int:
    if args.filter:
        print("warning: --filter is only supported by the Scapy backend", file=sys.stderr)
    if args.interface:
        print("warning: --interface is ignored by the Windows raw backend; use --host instead", file=sys.stderr)

    host = args.host or get_default_host_ip()
    if not host:
        raise RuntimeError("could not determine local host IP; pass one with --host 192.168.x.x")

    packet_count = 0
    start_monotonic = time.monotonic()
    writer = PcapWriter(args.output, linktype=101) if args.output else None

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sock.bind((host, 0))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    sock.settimeout(0.5)

    args.host = host
    print_banner(args, "raw-windows")
    try:
        while should_continue(args, packet_count, start_monotonic):
            try:
                packet, _addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            timestamp = time.time()
            packet_count += 1
            summary = decode_packet(packet, timestamp=timestamp, linktype=101, payload_preview=args.payload_preview)
            print(summary.format(show_time=not args.no_time))
            if writer is not None:
                writer.write(packet, timestamp)
    except KeyboardInterrupt:
        print("\nstopped by user")
    finally:
        try:
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        finally:
            sock.close()
        if writer is not None:
            writer.close()

    elapsed = time.monotonic() - start_monotonic
    print("-" * 88)
    print(f"captured {packet_count} packet(s) in {elapsed:.2f}s")
    return 0


def should_continue(args: argparse.Namespace, packet_count: int, start_monotonic: float) -> bool:
    if args.count and packet_count >= args.count:
        return False
    if args.duration and (time.monotonic() - start_monotonic) >= args.duration:
        return False
    return True


def get_default_host_ip() -> Optional[str]:
    candidates = []

    try:
        hostname = socket.gethostname()
        candidates.append(socket.gethostbyname(hostname))
    except OSError:
        pass

    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("8.8.8.8", 80))
        candidates.append(probe.getsockname()[0])
        probe.close()
    except OSError:
        pass

    for candidate in candidates:
        if candidate and not candidate.startswith("127."):
            return candidate
    return candidates[0] if candidates else None


def positive_int(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture network traffic packets and print decoded summaries.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-b",
        "--backend",
        choices=("auto", "scapy", "raw"),
        default="auto",
        help="capture backend to use",
    )
    parser.add_argument("-i", "--interface", help="network interface name")
    parser.add_argument(
        "--host",
        help="local IPv4 address to bind for Windows raw socket capture",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=positive_int,
        default=0,
        help="number of packets to capture; 0 means unlimited",
    )
    parser.add_argument(
        "-d",
        "--duration",
        type=positive_int,
        default=0,
        help="capture duration in seconds; 0 means unlimited",
    )
    parser.add_argument(
        "-f",
        "--filter",
        help="BPF capture filter, such as 'tcp port 443' or 'host 192.168.1.10' (Scapy backend only)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="write captured packets to this .pcap file",
    )
    parser.add_argument(
        "--payload-preview",
        type=positive_int,
        default=0,
        help="print the first N printable payload bytes in each summary",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="list interfaces using Scapy, then exit",
    )
    parser.add_argument(
        "--no-promiscuous",
        action="store_true",
        help="disable promiscuous mode for the Scapy backend",
    )
    parser.add_argument(
        "--no-time",
        action="store_true",
        help="hide timestamps in packet output",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_interfaces:
        return list_scapy_interfaces()

    try:
        if args.backend == "scapy":
            return capture_with_scapy(args)
        if args.backend == "raw":
            return capture_with_raw_socket(args)

        try:
            return capture_with_scapy(args)
        except RuntimeError as exc:
            if "Scapy is not installed" not in str(exc):
                raise
            print("Scapy is not installed; falling back to raw sockets.", file=sys.stderr)
            return capture_with_raw_socket(args)
    except PermissionError:
        print(
            "error: permission denied. Run this program as Administrator/root, "
            "or use Scapy with Npcap/libpcap installed.",
            file=sys.stderr,
        )
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
