/**
 * Utility for parsing Cisco MSGDUMP BGP logs and transforming them into
 * standard Wireshark PCAP structures.
 *
 * @example:
 * 
 *   ❯ bun run msgdmp-to-pcap.ts "FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 0118
 *   0200 0000 FD40 0101 0040 0206 0202 0D1C 316E 4003 04C3 10A1 6180 0404 0000
 *   0000 4005 0400 0000 3CC0 081C 0D1C 0002 0D1C 0016 0D1C 0056 0D1C
 *   01F7 0D1C 029A 0D1C 0813 FDE8 FDDE F063 0BB8 0000 0000 0000 0000 0000 0000
 *   0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
 *   0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
 *   0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
 *   0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
 *   0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
 *   0000 0000 0000 0000
 *   0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 185D AF90"
 *
 *   ============================================================
 *   PCAP CREATED SUCCESSFULLY
 *   ============================================================
 *   Full path       : /Users/bar/bgp_dump.pcap
 *   File size       : 374 bytes
 *   Ethernet frame  : 334 bytes
 *   BGP payload     : 280 bytes
 *   BGP message     : UPDATE (type 2)
 *   BGP length      : 280 bytes
 *   ============================================================
 *
 */

import { Buffer } from "node:buffer";


const MESSAGE_TYPES: Record<number, string> = {
    1: "OPEN",
    2: "UPDATE",
    3: "NOTIFICATION",
    4: "KEEPALIVE",
    5: "ROUTE-REFRESH",
};

/**
 * Get the BGP message type name.
 */
function bgpMessageType(msgType: number): string {
    return MESSAGE_TYPES[msgType] ?? "UNKNOWN";
}


enum TCPFlag {
    FIN = 1,
    SYN = 2,
    RST = 4,
    PSH = 8,
    ACK = 16,
    URG = 32,
    ECE = 64,
    CWR = 128,
}

interface TCPOptions {
    srcPort: number;
    dstPort: number;
    seq: number;
    ack: number;
    offsetFlags: number;
    window: number;
    checksum: number;
    urgent: number;
}

interface IPOptions {
    versionIHL: number;
    tos: number;
    ipPacketTotalLength: number;
    identification: number;
    flagsFragment: number;
    ttl: number;
    protocol: number;
    checksum: number;
    srcIP: string;
    dstIP: string;
}

interface EthernetOptions {
    dstMac: Buffer;
    srcMac: Buffer;
    etherType: number;
}



/**
 * Calculates the Internet checksum based on RFC 1071.
 */
function checksum(data: Buffer): number {
    // The checksum operates on 16-bit words (2 bytes) so we need an even number
    // of bytes. If the data has an odd number of bytes, we add one zero byte to
    // make it even.
    if (data.length % 2 !== 0) {
        data = Buffer.concat([
            data,
            Buffer.from([0x00]),
        ]);
    }

    let total = 0;
    for (let i = 0; i < data.length; i += 2) {
        const word = (data[i] << 8) | data[i + 1];
        total += word;
        total = (total & 0xffff) + (total >>> 16);
    }
    return (~total) & 0xffff;
}


/**
 * Converts an IPv4 address to four bytes.
 *
 * Example: `192.0.2.1`  becomes: `c0 00 02 01`
 */
function ipv4ToBuffer(ip: string): Buffer {
    const parts = ip.split(".").map(Number);
    if (
        parts.length !== 4 ||
        parts.some(part => !Number.isInteger(part) || part < 0 || part > 255)
    ) {
        throw new Error(`Invalid IPv4 address: ${ip}`);
    }
    return Buffer.from(parts);
}


/**
 * Converts hexadecimal text to bytes.
 */
function hexToBuffer(hex: string): Buffer {
    // Whitespace and newlines are ignored.
    hex = hex.replace(/\s+/g, "");

    if (hex.length % 2 !== 0) {
        throw new Error("Hex string contains an odd number of characters");
    }

    if (!/^[0-9a-fA-F]*$/.test(hex)) {
        throw new Error(
            "Invalid hexadecimal string"
        );
    }

    return Buffer.from(hex, "hex");
}


/**
 * Validate and return a BGP message.
 * 
 * BGP Message format:
 * ```
 *   0                          16            24           32
 *   ├──────────────────────────┴─────────────┴────────────┤
 *   │ Marker                                              │
 *   ├─────────────────────────────────────────────────────┤
 *   │ Marker                                              │
 *   ├─────────────────────────────────────────────────────┤
 *   │ Marker                                              │
 *   ├─────────────────────────────────────────────────────┤
 *   │ Marker                                              │
 *   ├──────────────────────────┬─────────────┬────────────┤
 *   │ Length                   │ Type        │ Message    │
 *   ├──────────────────────────┴─────────────┴────────────┤
 *   │ ~Message                                            │
 *   └─────────────────────────────────────────────────────┘
 *```
 */
function bgpMessage(bgpHex: string): Buffer {
    const message = hexToBuffer(bgpHex);
    /*
     * Marker = 16 bytes
     * Length = 2 bytes
     * Type   = 1 byte
     * 
     * BGP Message minimum length = 19 bytes.
     */
    if (message.length < 19) {
        throw new Error(`BGP message is too short: ${message.length} bytes`);
    }
    // First 16 bytes must be FF for the marker.
    const marker = message.subarray(0, 16);
    const expectedMarker = Buffer.alloc(16, 0xff);
    if (!marker.equals(expectedMarker)) {
        throw new Error("Invalid BGP marker");
    }
    // The 16th and 17th bytes are the 2 bytes for the Length field.
    // BGP length is big-endian.
    const length = message.readUInt16BE(16);
    if (message.length !== length) {
        throw new Error(
            `Unexpected BGP payload length: ${message.length} ` +
            `(BGP header declares ${length})`
        );
    }
    // 18th bytes is the message type
    const messageType = message[18];
    if (!(messageType in MESSAGE_TYPES)) {
        throw new Error(
            `Unknown BGP message type: ${messageType}`
        );
    }

    return message;
}


/**
 * Build TCP Data Offset and Flags field.
 *  ```
 *  ┌─────────────┬──────────┬────────────────┐
 *  │ Data Offset │ Reserved │     Flags      │
 *  │   4 bits    │  4 bits  │     8 bits     │
 *  └─────────────┴──────────┴────────────────┘
 *  ```
 * 
 * TCP header length is measured in 32-bit words (4 bytes).
 * Therefore 20-byte TCP header with no options is represented as 5
 * because 20/4 is 5.
 *
 */
function tcpOffsetFlags(flags: TCPFlag[], dataOffset: number): number {
    let tcpFlags = 0;

    for (const flag of flags) {
        tcpFlags |= flag;
    }

    return (dataOffset << 12) | tcpFlags;
}



/**
 * Creates the IPv4 TCP pseudo-header.
 *
 * Pseudo header format:
 * 
 *  ```
 *  0              8               16                       3
 *  ├──────────────┴───────────────┴────────────────────────┤
 *  │ Source IP address                                     │
 *  ├───────────────────────────────────────────────────────┤
 *  │ Destination IP address                                │
 *  ├──────────────┬───────────────┬────────────────────────┤
 *  │ Reserved     │ Protocol      │TCP length              │
 *  └──────────────┴───────────────┴────────────────────────┘
 *  ```
 * Total = 12 bytes.
 */
function tcpPseudoHeader(srcIP: string, dstIP: string, tcpLength: number): Buffer {
    // the header is 12 bytes long
    const pseudoHeader = Buffer.alloc(12);

    ipv4ToBuffer(srcIP).copy(pseudoHeader, 0);
    ipv4ToBuffer(dstIP).copy(pseudoHeader, 4);
    pseudoHeader[8] = 0;
    pseudoHeader[9] = 6; // TCP protocol number
    pseudoHeader.writeUInt16BE(tcpLength, 10);

    return pseudoHeader;
}


/**
 * Creates the TCP header.
 * 
 * TCP header format:
 * 
 *  ```
 *  0       4        8              16                             32
 *  ├───────┴────────┴──────────────┼──────────────────────────────┤
 *  │Source Port                    │Destination Port              │
 *  ├───────────────────────────────┴──────────────────────────────┤
 *  │Sequence Number                                               │
 *  ├──────────────────────────────────────────────────────────────┤
 *  │Acknowledgment Number                                         │
 *  ├───────┬────────┬──────────────┬──────────────────────────────┤
 *  │Data   │Reserved│Flags         │Window Size                   │
 *  │Offset │        │              │                              │
 *  ├───────┴────────┴──────────────┼──────────────────────────────┤
 *  │Checksum                       │Urgent Pointer                │
 *  ├───────────────────────────────┴──────────────────────────────┤
 *  │Options                                                       │
 *  └──────────────────────────────────────────────────────────────┘
 *  ```
 * 
 */
function tcpHeader(
    srcIP: string,
    dstIP: string,
    opts: TCPOptions,
    payload: Buffer): Buffer {
    /*
     * TCP header bytes:
     *
     * Source port       2
     * Destination port  2
     * Sequence number   4
     * ACK number        4
     * Offset/flags      2
     * Window            2
     * Checksum          2
     * Urgent pointer    2
     *
     * Total = 20 bytes
     */

    const header = Buffer.alloc(20);
    let pos = 0; // bytes position

    header.writeUInt16BE(opts.srcPort, pos);
    pos += 2;

    header.writeUInt16BE(opts.dstPort, pos);
    pos += 2;

    header.writeUInt32BE(opts.seq, pos);
    pos += 4;

    header.writeUInt32BE(opts.ack, pos);
    pos += 4;

    header.writeUInt16BE(opts.offsetFlags, pos);
    pos += 2;

    header.writeUInt16BE(opts.window, pos);
    pos += 2;

    // Checksum is initially be zero.
    header.writeUInt16BE(0, pos);
    pos += 2;
    header.writeUInt16BE(opts.urgent, pos);


    const checksumValue = checksum(
        Buffer.concat([
            tcpPseudoHeader(srcIP, dstIP, header.length + payload.length),
            header,
            payload,
        ])
    )
    // Inserting the checksum at the 16th byte
    header.writeUInt16BE(checksumValue, 16);

    return header;
}


/**
 * Creates the IPv4 header.
 *
 * IPv4 Header format:
 * 
 *  ```
 *  0       4       8               16     19                      32
 *  ├───────┼───────┼───────────────┼──────┴───────────────────────┤
 *  │Version│IHL    │Type of Service│Total Length                  │
 *  ├───────┴───────┴───────────────┼──────┬───────────────────────┤
 *  │Identification                 │Flags │Fragment Offset        │
 *  ├───────────────┬───────────────┼──────┴───────────────────────┤
 *  │Time to Live   │Protocol       │Header Checksum               │
 *  ├───────────────┴───────────────┴──────────────────────────────┤
 *  │Source IP Address                                             │
 *  ├──────────────────────────────────────────────────────────────┤
 *  │Destination IP Address                                        │
 *  ├──────────────────────────────────────────────────────────────┤
 *  │Options                                                       │
 *  └──────────────────────────────────────────────────────────────┘
 *  ```
 *
 *
 */
function ipHeader(options: IPOptions): Buffer {
    /*
     * IPv4 header without options = 20 bytes.
     */
    const header = Buffer.alloc(20);
    let offset = 0;

    // Version + IHL.
    header[offset] = options.versionIHL;
    offset += 1;

    // TOS.
    header[offset] = options.tos;
    offset += 1;

    // Total length.
    header.writeUInt16BE(options.ipPacketTotalLength, offset);
    offset += 2;

    // Identification.
    header.writeUInt16BE(options.identification, offset);
    offset += 2;

    // Flags + fragment offset.
    header.writeUInt16BE(options.flagsFragment, offset);
    offset += 2;

    // TTL.
    header[offset] = options.ttl;
    offset += 1;

    // Protocol.
    header[offset] = options.protocol;
    offset += 1;

    // Checksum initially zero.
    header.writeUInt16BE(0, offset);
    offset += 2;

    // Source address.
    ipv4ToBuffer(options.srcIP).copy(header, offset);
    offset += 4;

    // Destination address.
    ipv4ToBuffer(options.dstIP).copy(header, offset);

    // Calculate checksum over the complete IPv4 header with checksum currently
    // zero.
    const ipChecksum = checksum(header);

    // Insert checksum on the 10th byte
    header.writeUInt16BE(ipChecksum, 10);

    return header;
}


/**
 * Create Ethernet II header.
 * 
 *
 *    ```
 *    0                            16                             3
 *    ├────────────────────────────┴──────────────────────────────┤
 *    │ Destination MAC Address                                   │
 *    ├────────────────────────────┬──────────────────────────────┤
 *    │ ~Destination MAC Address   │ Source MAC Address           │
 *    ├────────────────────────────┴──────────────────────────────┤
 *    │ ~Source MAC Address                                       │
 *    ├────────────────────────────┬──────────────────────────────┘
 *    │ EtherType                  │
 *    └────────────────────────────┘
 *   ```
 * 
 */
function ethernetHeader(options: EthernetOptions): Buffer {
    const header = Buffer.alloc(14);

    options.dstMac.copy(header, 0);
    options.srcMac.copy(header, 6);
    header.writeUInt16BE(options.etherType, 12);

    return header;
}


interface PacketOptions {
    tcp: TCPOptions;
    ip: IPOptions;
    ethernet: EthernetOptions;
}

/**
 * Creates complete Ethernet + IPv4 + TCP + BGP packet.
 */
function generateBGPPacket(bgpPayload: Buffer, params: PacketOptions): Buffer {



    /*
     * IPv4 Total Length includes:
     *
     * IPv4 header
     * TCP header
     * BGP payload
     */
    const ipHeaderLength = 20;
    const tcpHeaderLength = 20;
    params.ip.ipPacketTotalLength = ipHeaderLength + tcpHeaderLength + bgpPayload.length;

    return Buffer.concat([
        ethernetHeader(params.ethernet),
        ipHeader(params.ip),
        tcpHeader(params.ip.srcIP, params.ip.dstIP, params.tcp, bgpPayload),
        bgpPayload,
    ]);
}


/**
 * Creates a PCAP file.
 */
async function writePcap(packet: Buffer, filename: string): Promise<void> {
    /*
     * Every classic PCAP file starts with a global header.
     * This tells Wireshark things such as:
     *
     *   Magic             4
     *   Version major     2
     *   Version minor     2
     *   Thiszone          4
     *   Sigfigs           4
     *   Snaplen           4
     *   Network           4
     *
     *   Total = 24 bytes
     *
     */
    const globalHeader = Buffer.alloc(24);
    let pos = 0;
    // PCAP magic number to identify the file as a PCAP
    globalHeader.writeUInt32LE(0xA1B2C3D4, pos);
    pos += 4;
    // PCAP major version
    globalHeader.writeUInt16LE(2, pos);
    pos += 2;
    // PCAP minor version
    globalHeader.writeUInt16LE(4, pos);
    pos += 2;
    // Timezone correction.
    globalHeader.writeInt32LE(0, pos);
    pos += 4;
    // Timestamp accuracy.
    globalHeader.writeUInt32LE(0, pos);
    pos += 4;
    // Snaplen.
    globalHeader.writeUInt32LE(65535, pos);
    pos += 4;
    // Link-layer type: 1 = Ethernet.
    globalHeader.writeUInt32LE(1, pos);

    /*
     * PCAP packet header:
     *
     * Timestamp seconds       4
     * Timestamp microseconds  4
     * Captured length         4
     * Original length         4
     *
     * Total = 16 bytes.
     */
    const packetHeader = Buffer.alloc(16);

    pos = 0;

    // Timestamp seconds.
    packetHeader.writeUInt32LE(0, pos);
    pos += 4;
    // Timestamp microseconds.
    packetHeader.writeUInt32LE(0, pos);
    pos += 4;
    // Captured length.
    packetHeader.writeUInt32LE(packet.length, pos);
    pos += 4;
    // Original length.
    packetHeader.writeUInt32LE(packet.length, pos);

    const pcap =
        Buffer.concat([
            globalHeader,
            packetHeader,
            packet,
        ]);

    await Bun.write(filename, pcap);
}




/**
 * Get the user's home directory.
 */
function homeDirectory(): string {
    // Linux and macOS
    if (Bun.env.HOME) { return Bun.env.HOME }
    // Windows
    if (Bun.env.USERPROFILE) { return Bun.env.USERPROFILE }
    throw new Error(
        "Could not determine home directory"
    );
}


/**
 * Main program.
 */
async function generatePcap(bgpHex: string, params: PacketOptions): Promise<void> {
    const filename = `${homeDirectory()}/bgp_dump.pcap`;
    const message = bgpMessage(bgpHex);
    const packet = generateBGPPacket(message, params);

    await writePcap(packet, filename);

    const file = Bun.file(filename);
    console.log();
    console.log("=".repeat(60));
    console.log("PCAP CREATED SUCCESSFULLY");
    console.log("=".repeat(60));

    console.log(`Full path       : ${filename}`);
    console.log(`File size       : ${file.size} bytes`);
    console.log(`Ethernet frame  : ${packet.length} bytes`);
    console.log(`BGP payload     : ${message.length} bytes`);
    console.log(`BGP message     : ${bgpMessageType(message[18])} (type ${message[18]})`);
    console.log(`BGP length      : ${message.readUInt16BE(16)} bytes`);

    console.log("=".repeat(60));
}


/**
 * CLI entry point.
 */
const args = process.argv.slice(2);
const PROGAM_NAME = "msgdmp-to-pcap"
if (args.length === 0) {
    console.error(
        `Usage:
  ${PROGAM_NAME} $BGP_HEX

Example:
  ${PROGAM_NAME} "FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 0013 0400"
`);
    process.exit(1);
}

await generatePcap(args.join(""), {
    ip: {
        srcIP: "0.0.0.0",
        dstIP: "0.0.0.0",
        ttl: 64,
        protocol: 6,
        versionIHL: 0x45,
        tos: 0,
        identification: 0x1234,
        flagsFragment: 0x4000,
        ipPacketTotalLength: 0,
        checksum: 0
    },
    tcp: {
        srcPort: 179,
        dstPort: 12345,
        seq: 1000,
        ack: 2000,
        window: 65535,
        offsetFlags: tcpOffsetFlags([TCPFlag.PSH, TCPFlag.ACK], 5),
        checksum: 0,
        urgent: 0
    },
    ethernet: {
        dstMac: Buffer.from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        srcMac: Buffer.from([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
        etherType: 0x0800
    },
});
