"""
Utility for parsing Cisco BGP MSGDUMP logs and transforming them into
standard Wireshark PCAP.

Example:

```
❯ python msgdmp-to-pcap.py "FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 0041 0104
 5BA0 00B4 0303 0303 2402 0601
 0400 0100 8002 0601 0400 0100 0102 0280 0002 0202 0002 0246 0002 0641 0400
 068D B8"

============================================================
PCAP CREATED SUCCESSFULLY
============================================================
Full path       : /Users/foo/bgp_dump.pcap
File size       : 159 bytes
Ethernet frame  : 119 bytes
BGP payload     : 65 bytes
BGP message     : OPEN (type 1)
BGP length      : 65 bytes
============================================================
```
"""

import struct
import socket
import os
import sys
from pathlib import Path
from dataclasses import dataclass
from enum import IntFlag

MESSAGE_TYPES: dict[int, str] = {
    1: "OPEN",
    2: "UPDATE",
    3: "NOTIFICATION",
    4: "KEEPALIVE",
    5: "ROUTE-REFRESH",
}


def bgp_message_type(msg_type: int) -> str:
    return MESSAGE_TYPES.get(msg_type, "UNKNOWN")


class TCPFlag(IntFlag):
    """8-bit TCP flag."""

    FIN = 1
    SYN = 2
    RST = 4
    PSH = 8
    ACK = 16
    URG = 32
    ECE = 64
    CWR = 128


@dataclass
class TCPOptions:
    """Fields of the TCP header."""

    src_port: int
    dst_port: int
    seq: int
    ack: int
    offset_flags: int
    window: int
    checksum: int
    urgent: int


@dataclass
class IPOptions:
    """Fields of the IPv4 header."""

    src_ip: str
    dst_ip: str
    ttl: int
    protocol: int
    version_ihl: bytes
    tos: int
    identification: bytes
    flags_fragment: bytes
    ip_packet_total_len: int
    checksum: int


@dataclass
class EthernetOptions:
    """Fields of the Ethernet header."""

    dst_mac: bytes
    src_mac: bytes
    ether_type: bytes


@dataclass
class PacketOptions:
    tcp: TCPOptions
    ip: IPOptions
    ethernet: EthernetOptions


def checksum(data: bytes) -> int:
    """Calculates the Internet checksum based on RFC1071.

    The checksum is needed for the IP and TCP (as well as UDP) headers.
    """
    # The checksum operates on 16-bit words (2 bytes) so we need an even number
    # of bytes. If the data has an odd number of bytes, we add one zero byte to
    # make it even.
    if len(data) % 2:
        data += b"\x00"

    # Checksum accumulator starts at zero.
    total: int = 0
    # Each iteration processes one 16-bit word i.e., 2 bytes
    for i in range(0, len(data), 2):
        # Converting two 8-bit bytes into one 16-bit number.
        # Example: 0x12 0x34 -> becomes: 0x1234
        #
        # We want 0x12 (00010010) to become the upper 8 bits of a 16-bit number
        # so we shift it left `0x12 << 8` to create `00010010 00000000`. Then
        # `0x34` (00110100) should occupy the lower 8 bits so we leave it alone
        # to get `00000000 00110100` and then we do a bitwise OR.
        #
        #   00010010 00000000         0x1200
        # | 00000000 00110100       | 0x0034
        # -------------------  ==>  --------
        #   00010010 00110100         0x1234
        #
        # We can use addition and get the same result but the operation is
        # conceptually combining bit fields, rather than mathematically adding
        # numbers. Addition happens to work because there is no overlap between
        # the bits.
        word = (data[i] << 8) | data[i + 1]

        # We add the word to the cumulated checksum total. But when adding the
        # 16-bit word to the accumulated checksum total, the result can exceed
        # 16 bits. However, the checksum algorithm uses 16 bits arithmetic so we
        # handle the carry over using "end-around carry".
        # For example if accumulated total is `0xFFFF` and the bitwise op above
        # created a word that is `0x0001`, the new accumulated total will be:
        #
        #      0xFFFF            1111 1111 1111 1111
        #  +   0x0001         +  0000 0000 0000 0001
        #  ----------  ==>    ----------------------
        #    0x1 0000          1 0000 0000 0000 0000
        #
        # This total is now 17 bits so we need to handle that carry over.
        total += word

        # In the operation below the `total & 0xffff` is done to keep only the
        # lower 16 bits of the total since for a 16 bit field when all 16 bits
        # are set the value is FFFF. For example, if cumulative total becomes
        # `0x12345` after the above addition that number is now 17 bits.
        # In order to keep the lower 16 bits we do `0x12345 & 0xFFFF` such that:
        #
        #     0001 0010 0011 0100 0101
        #  &  0000 1111 1111 1111 1111
        #  ----------------------------
        #     0000 0010 0011 0100 0101 --> 0x2345
        #
        # The second part `0x12345 >> 16` gives: `0001` this is the carry over
        # bit discared by the operation `0x12345 & 0xFFFF`, so we add it back:
        #
        #     0010 0011 0100 0101            0x2345
        #  +  0000 0000 0000 0001        +   0x0001
        #  ----------------------  ==>   -----------
        #     0010 0011 0100 0110            0x2346
        #
        # Essentially the operation folds anything above 16 bits back into the
        # 16 bits.
        total = (total & 0xFFFF) + (total >> 16)

    # The final step of the Internet checksum calculation:
    # Flip every bit of the 16-bit accumulated value, then keep only the lower
    # 16 bits. That is we do a One's complement of the final 16-bit value.
    return (~total) & 0xFFFF


def bgp_message(bgp_hex: str) -> bytes:
    """Generate BGP message from hex string.

    BGP message general format:

    ```
    0                          16            24           32
    ├──────────────────────────┴─────────────┴────────────┤
    │ Marker                                              │
    ├─────────────────────────────────────────────────────┤
    │ Marker                                              │
    ├─────────────────────────────────────────────────────┤
    │ Marker                                              │
    ├─────────────────────────────────────────────────────┤
    │ Marker                                              │
    ├──────────────────────────┬─────────────┬────────────┤
    │ Length                   │ Type        │ Message    │
    ├──────────────────────────┴─────────────┴────────────┤
    │ ~Message                                            │
    └─────────────────────────────────────────────────────┘
    ```
    """

    # Removing whitespace and newlines from the dump.
    bgp_hex = "".join(bgp_hex.split())
    message: bytes = bytes.fromhex(bgp_hex)

    # A BGP message has:
    #   16 bytes: Marker
    #    2 bytes: Length
    #    1 byte : Type
    minimum_bgp_length = 19
    assert (
        len(message) >= minimum_bgp_length
    ), f"BGP message is too short: {len(message)} bytes"

    """
    From BGP message standard format, see example below:

    ```
    Border Gateway Protocol - KEEPALIVE Message
    Marker: ffffffffffffffffffffffffffffffff
    Length: 19
    Type: KEEPALIVE Message (4)
    ```

    The first 16 bytes (0 to 15th byte) of a BGP message are the marker. Thus
    the 16th and 17th bytes are the 2 bytes for the Length field. And, the 18th
    byte is the message type.
    """
    marker = message[:16]
    assert marker == b"\xff" * 16, "Invalid BGP marker"

    length = int.from_bytes(message[16:18], "big")
    # Validate that the actual message length matches the length
    # declared inside the BGP message.
    assert len(message) == length, (
        f"Unexpected BGP payload length: {len(message)} "
        f"(BGP header declares {length})"
    )

    message_type = message[18]
    assert (
        message_type in MESSAGE_TYPES
    ), f"Unknown BGP message type: {message_type}"

    return message


def tcp_offset_flags(*flags: TCPFlag, data_offset: int = 5) -> int:
    """Builds the 16-bit TCP Data Offset/Reserved/Flags field.

    Field format:
    ```
    ┌─────────────┬──────────┬────────────────┐
    │ Data Offset │ Reserved │     Flags      │
    │   4 bits    │  4 bits  │     8 bits     │
    └─────────────┴──────────┴────────────────┘
    ```

    Parameters:
        data_offset: TCP header length's measured in 32-bit words (4 bytes).
            Therefore 20-byte TCP header with no options is represented as 5
        flag_names: TCP flags to enable.
            Accepted names FIN, SYN, RST, PSH, ACK, URG, ECE, CWR.
    """

    tcp_flags = 0
    for flag in flags:
        # Each TCP flag occupies a different bit. The selected flag values
        # are combined using bitwise OR (|), which turns on the bits for all
        # requested flags without changing the other flags.
        tcp_flags = tcp_flags | flag.value

    # The data offset is shifted into the upper 4 bits and combined with
    # the flags and we return the resulting 16-bit field as an integer.
    return (data_offset << 12) | tcp_flags


def tcp_header(
    tcp_options: TCPOptions, src_ip: str, dst_ip: str, payload: bytes
) -> bytes:
    """Creates the TCP header.

    The TCP header format is:

    ```
    0       4        8              16                             32
    ├───────┴────────┴──────────────┼──────────────────────────────┤
    │Source Port                    │Destination Port              │
    ├───────────────────────────────┴──────────────────────────────┤
    │Sequence Number                                               │
    ├──────────────────────────────────────────────────────────────┤
    │Acknowledgment Number                                         │
    ├───────┬────────┬──────────────┬──────────────────────────────┤
    │Data   │Reserved│Flags         │Window Size                   │
    │Offset │        │              │                              │
    ├───────┴────────┴──────────────┼──────────────────────────────┤
    │Checksum                       │Urgent Pointer                │
    ├───────────────────────────────┴──────────────────────────────┤
    │Options                                                       │
    └──────────────────────────────────────────────────────────────┘
    ```
    """

    def tcp_pseudo_header(src_ip: str, dst_ip: str, tcp_length: int) -> bytes:
        """Creates a TCP pseudo header.

        A TCP pseudo-header is a temporary piece of information used only when
        calculating the TCP checksum.

        TCP pseudo header format:

        ```
        0              8               16                       32
        ├──────────────┴───────────────┴────────────────────────┤
        │ Source IP address                                     │
        ├───────────────────────────────────────────────────────┤
        │ Destination IP address                                │
        ├──────────────┬───────────────┬────────────────────────┤
        │ Reserved     │ Protocol      │TCP length              │
        └──────────────┴───────────────┴────────────────────────┘
        ```
        """
        # Struct format string.
        # ! = Network byte order (big-endian)
        # H = unsigned short (2 bytes)
        # B = 1-byte unsigned integer
        return (
            socket.inet_aton(src_ip)
            + socket.inet_aton(dst_ip)
            + struct.pack(
                "!BBH",
                0,  # Reserved = 0
                6,  # Protocol = TCP (6)
                tcp_length,
            )
        )

    # Initializing a TCP header with checksum set to zero.
    tcp_options.checksum = 0
    # struct.pack() format string:
    #  ! = Network byte order (big-endian)
    #  H = unsigned short (2 bytes)
    #  I = unsigned integer (4 bytes)
    #  B = 1-byte unsigned integer
    #
    tcp_header = bytearray(
        struct.pack(
            "!HHIIHHHH",
            tcp_options.src_port,
            tcp_options.dst_port,
            tcp_options.seq,
            tcp_options.ack,
            tcp_options.offset_flags,
            tcp_options.window,
            tcp_options.checksum,
            tcp_options.urgent,
        )
    )
    # Checksum occupies bytes 16-17 of the TCP header.
    tcp_header[16:18] = struct.pack(
        "!H",
        # Calculating the TCP checksum.
        # TCP cheksum covers: pseudo-header + TCP header + payload
        checksum(
            tcp_pseudo_header(src_ip, dst_ip, len(tcp_header) + len(payload))
            + tcp_header
            + payload
        ),
    )
    return bytes(tcp_header)


def ip_header(options: IPOptions) -> bytes:
    """Creates the IPv4 header.

    The IPv4 header format is:

    ```
    0       4       8               16     19                      32
    ├───────┼───────┼───────────────┼──────┴───────────────────────┤
    │Version│IHL    │Type of Service│Total Length                  │
    ├───────┴───────┴───────────────┼──────┬───────────────────────┤
    │Identification                 │Flags │Fragment Offset        │
    ├───────────────┬───────────────┼──────┴───────────────────────┤
    │Time to Live   │Protocol       │Header Checksum               │
    ├───────────────┴───────────────┴──────────────────────────────┤
    │Source IP Address                                             │
    ├──────────────────────────────────────────────────────────────┤
    │Destination IP Address                                        │
    ├──────────────────────────────────────────────────────────────┤
    │Options                                                       │
    └──────────────────────────────────────────────────────────────┘
    ```
    """

    # We initially put zero in the checksum field. Why?
    # Because we need to calculate the checksum based on the complete IP header
    # but we don't have the header before creating it. So we initialise it at 0
    options.checksum = 0

    # struct.pack() format string:
    #  ! = Network byte order (big-endian)
    #  H = unsigned short (2 bytes)
    #  I = unsigned integer (4 bytes)
    #  B = 1-byte unsigned integer
    #  1s = exactly 1 bytes
    #  2s = exactly 2 bytes
    #  4s = exactly 4 bytes
    header = bytearray(
        struct.pack(
            "!1sBH2s2sBBH4s4s",
            options.version_ihl,  # 1s = exactly 1 bytes
            options.tos,  # B = 1-byte unsigned integer
            options.ip_packet_total_len,  # H = unsigned short (2 bytes)
            options.identification,  # 2s = exactly 2 bytes
            options.flags_fragment,  # 2s = exactly 2 bytes
            options.ttl,  # B = 1-byte unsigned integer
            options.protocol,  # B = 1-byte unsigned integer
            options.checksum,  # H = unsigned short (2 bytes)
            socket.inet_aton(options.src_ip),  # 4s = exactly 4 bytes
            socket.inet_aton(options.dst_ip),  # 4s = exactly 4 bytes
        )
    )
    # Checksum occupies bytes 10-11 of the TCP header.
    header[10:12] = struct.pack(
        "!H",
        # IP checksum covers only the IP header.
        checksum(bytes(header)),
    )
    return bytes(header)


def ethernet_header(options: EthernetOptions) -> bytes:
    """Creates the L2 ethernet header.

    L2 frame format:

    ```
    0                            16                             32
    ├────────────────────────────┴──────────────────────────────┤
    │ Destination MAC Address                                   │
    ├────────────────────────────┬──────────────────────────────┤
    │ ~Destination MAC Address   │ Source MAC Address           │
    ├────────────────────────────┴──────────────────────────────┤
    │ ~Source MAC Address                                       │
    ├────────────────────────────┬──────────────────────────────┤
    │ EtherType                  │ Payload                      │
    ├────────────────────────────┴──────────────────────────────┤
    │ ~Payload                                                  │
    ├───────────────────────────────────────────────────────────┤
    │ Frame Check Sequence (FCS)                                │
    └───────────────────────────────────────────────────────────┘
    ```

    Ethernet frame starts with:
        Destination MAC address = 6 bytes
        Source MAC address      = 6 bytes
        EtherType               = 2 bytes
    """

    return options.dst_mac + options.src_mac + options.ether_type


def generate_bgp_packet(bgp_message: bytes, options: PacketOptions) -> bytes:
    """Generates a BGP packet."""

    # IPv4 packet total length includes:
    #
    #    IP header = 20 bytes
    #    TCP header = 20 bytes
    #    BGP payload = N bytes
    #
    #    Total: 20 + 20 + N = 40 + N bytes
    #
    packet_total_len: int = 20 + 20 + len(bgp_message)
    options.ip.ip_packet_total_len = packet_total_len

    return (
        ethernet_header(options.ethernet)
        + ip_header(options.ip)
        + tcp_header(
            options.tcp, options.ip.src_ip, options.ip.dst_ip, bgp_message
        )
        + bgp_message
    )


def write_pcap(packet: bytes, filename: Path) -> None:
    """Creates and saves a Wireshark compatible `.pcap` file."""

    with filename.open("wb") as f:
        # Every classic PCAP file starts with a global header 24 bytes.
        #
        # This tells Wireshark things such as:
        #   - PCAP format
        #   - Version
        #   - Capture length
        #   - Link-layer type
        #
        # PCAP headers are written little-endian.
        # Struct format string:
        #   < = little-endian
        #   H = unsigned short (2 bytes)
        #   I = unsigned integer (4 bytes)
        _ = f.write(
            struct.pack(
                "<IHHIIII",
                0xA1B2C3D4,  # PCAP magic number to identify the file as a PCAP
                2,  # PCAP major version
                4,  # PCAP minor version
                0,  # Timezone correction
                0,  # Timestamp accuracy
                65535,  # Maximum captured packet size
                1,  # Link-layer type:  1 = Ethernet
            )
        )
        # Every packet in a PCAP has a packet record header.
        #
        # It contains:
        #   - timestamp seconds
        #   - timestamp microseconds
        #   - captured length
        #   - original length
        #
        # We don't know the original timestamp so using zero for this packet.
        timestamp_seconds = 0
        # Microseconds portion of timestamp.
        timestamp_microseconds = 0

        # Struct format string:
        #   < = little-endian
        #   I = unsigned integer (4 bytes)
        _ = f.write(
            struct.pack(
                "<IIII",
                timestamp_seconds,
                timestamp_microseconds,
                len(packet),
                len(packet),
            )
        )
        # Ethernet frame containing:
        #   - Ethernet header
        #   - IPv4 header
        #   - TCP header
        #   - BGP message
        _ = f.write(packet)


def generate_pcap(bgp_hex: str, options: PacketOptions) -> None:
    filename = Path.home() / "bgp_dump.pcap"
    write_pcap(
        packet := generate_bgp_packet(
            (message := bgp_message(bgp_hex)), options
        ),
        filename,
    )
    print()
    print("=" * 60)
    print("PCAP CREATED SUCCESSFULLY")
    print("=" * 60)

    print(f"Full path       : {filename.as_posix()}")
    print(f"File size       : {os.path.getsize(filename.as_posix())} bytes")
    # Size of the Ethernet packet we constructed.
    print(f"Ethernet frame  : {len(packet)} bytes")
    # The original BGP payload size.
    print(f"BGP payload     : {len(message)} bytes")
    # Byte 18 is the BGP message type.
    print(
        f"BGP message     : {bgp_message_type(int(message[18]))} (type {message[18]})"
    )
    # Bytes 16 and 17 are BGP Length field but we need to convert the two-byte
    # from hexadecimal bytes into an integer. E.g., 00 41 -> 65
    print(f"BGP length      : {int.from_bytes(message[16:18], 'big')} bytes")
    print("=" * 60)


defaultTCPOptions = TCPOptions(
    src_port=179,  # Making src the BGP server.
    dst_port=12345,  # Synthetic ephemeral port for the client.
    seq=1000,  # Synthetic sequence number.
    ack=2000,  # Synthetic ack number.
    offset_flags=tcp_offset_flags(TCPFlag.PSH, TCPFlag.ACK),
    window=65535,  # Max value of the 16 bits field.
    checksum=0,  # Initial checksum value.
    urgent=0,  # Urgent pointer not being used.
)

defaultIPOptions = IPOptions(
    # We don't know the real source and destination IPs from the Cisco dump so
    # we use some syntetic addresses.
    src_ip="0.0.0.0",
    dst_ip="0.0.0.0",
    ttl=64,
    protocol=6,  # TCP number
    # IPv4 header is normally 20 bytes when there are no options.
    #
    #  IP version = 4
    #  IP Header length = 20 bytes
    #
    # The length (IHL) is measured in 32-bit (4 bytes) words so 20 bytes is 5
    # because 20/4 = 5. Therefore:
    #
    #  IPv4 Version Field = 4 (4 bits)
    #  Internet Header Length Field = 5 (4 bits)
    #
    # These 2 values form 1 byte.
    version_ihl=b"\x45",
    # We don't know the original value so we use zero.
    tos=0,
    # Synthetic IP identification value.
    identification=b"\x12\x34",
    # IPv4 flags and fragment offset take 2 bytes.
    # 0x4000 means: Don't Fragment (DF), the offset is 0.
    flags_fragment=b"\x40\x00",
    ip_packet_total_len=0,  # Packet length will be calcuated later.
    checksum=0,  # Initial checksum value.
)

defaultEtherOptions = EthernetOptions(
    # We don't have the real MAC addresses because the Cisco MSGDUMP only
    # contains the BGP payload.
    dst_mac=b"\x00\x11\x22\x33\x44\x55",
    src_mac=b"\x00\xaa\xbb\xcc\xdd\xee",
    # The EtherType for IPV4 is 0x0800
    ether_type=b"\x08\x00",
)


def main(args: list[str]) -> None:
    PROGRAM_NAME = "msgdmp-to-pcap"
    if len(sys.argv) < 2:
        print(
            f"""Usage:
  {PROGRAM_NAME} $BGP_HEX

Example:
  {PROGRAM_NAME} "FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 0013 0400"
"""
        )
        sys.exit(1)

    return generate_pcap(
        "".join(args[1:]),
        PacketOptions(
            tcp=defaultTCPOptions,
            ip=defaultIPOptions,
            ethernet=defaultEtherOptions,
        ),
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv))
