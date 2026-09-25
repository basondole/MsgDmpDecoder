/*
 * Utility for parsing Cisco BGP MSGDUMP logs and transforming them into
 * standard Wireshark PCAP.
 *
 * Example:
 *
 * ```
 * ❯ java msgdmp-to-pcap.java "FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 0041 0104
 *  5BA0 00B4 0303 0303 2402 0601
 *  0400 0100 8002 0601 0400 0100 0102 0280 0002 0202 0002 0246 0002 0641 0400
 *  068D B8"
 *
 * ============================================================
 * PCAP CREATED SUCCESSFULLY
 * ============================================================
 * Full path       : /Users/foo/bgp_dump.pcap
 * File size       : 159 bytes
 * Ethernet frame  : 119 bytes
 * BGP payload     : 65 bytes
 * BGP message     : OPEN (type 1)
 * BGP length      : 65 bytes
 * ============================================================
 * ```
 */

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

public class MsgdmpToPcap {

    static final Map<Integer, String> MESSAGE_TYPES = Map.of(
            1, "OPEN",
            2, "UPDATE",
            3, "NOTIFICATION",
            4, "KEEPALIVE",
            5, "ROUTE-REFRESH");

    static String bgpMessageType(int msgType) {
        return MESSAGE_TYPES.getOrDefault(msgType, "UNKNOWN");
    }

    /**
     * 8-bit TCP flag.
     */
    enum TCPFlag {
        FIN(1),
        SYN(2),
        RST(4),
        PSH(8),
        ACK(16),
        URG(32),
        ECE(64),
        CWR(128);

        final int value;

        TCPFlag(int value) {
            this.value = value;
        }
    }

    /**
     * Fields of the TCP header.
     */
    static class TCPOptions {
        int srcPort;
        int dstPort;
        long seq;
        long ack;
        int offsetFlags;
        int window;
        int checksum;
        int urgent;
    }

    /**
     * Fields of the IPv4 header.
     */
    static class IPOptions {
        byte[] versionIhl;
        int tos;
        int ipPacketTotalLen;
        byte[] identification;
        byte[] flagsFragment;
        int ttl;
        int protocol;
        int checksum;
        InetAddress srcIp;
        InetAddress dstIp;
    }

    /**
     * Fields of the IPv4 header.
     */
    static class EthernetOptions {
        byte[] dstMac;
        byte[] srcMac;
        byte[] etherType;
    }

    static class PacketOptions {
        TCPOptions tcp;
        IPOptions ip;
        EthernetOptions ethernet;

        PacketOptions(
                TCPOptions tcp,
                IPOptions ip,
                EthernetOptions ethernet) {
            this.tcp = tcp;
            this.ip = ip;
            this.ethernet = ethernet;
        }
    }

    /**
     * Calculates the Internet checksum based on RFC1071.
     *
     * The checksum is needed for the IP and TCP headers.
     */
    static int checksum(byte[] data) {
        // The checksum operates on 16-bit words (2 bytes) so we need an even number
        // of bytes. If the data has an odd number of bytes, we add one zero byte to
        // make it even.
        if (data.length % 2 != 0) {
            byte[] padded = new byte[data.length + 1];
            System.arraycopy(data, 0, padded, 0, data.length);
            data = padded;
        }

        // Checksum accumulator starts at zero.
        int total = 0;

        // Each iteration processes one 16-bit word i.e., 2 bytes
        for (int i = 0; i < data.length; i += 2) {
            // Converting two 8-bit bytes into one 16-bit number.
            // Example: 0x12 0x34 -> becomes: 0x1234
            int word = ((data[i] & 0xff) << 8) | (data[i + 1] & 0xff);

            total += word;
            // We added the word to the cumulated checksum total. But when adding the
            // 16-bit word to the accumulated checksum total, the result can exceed
            // 16 bits. However, the checksum algorithm uses 16 bits arithmetic.
            // so fold anything above 16 bits back into the 16 bits.
            total = (total & 0xFFFF) + (total >>> 16);
        }

        // The final step of the Internet checksum calculation:
        // Flip every bit of the 16-bit accumulated value, then keep only the lower
        // 16 bits. That is we do a One's complement of the final 16-bit value.
        return (~total) & 0xFFFF;
    }

    /**
     * Generate BGP message from hex string.
     *
     * BGP message general format:
     *
     * <pre>
     * 0                          16            24           32
     * ├──────────────────────────┴─────────────┴────────────┤
     * │ Marker                                              │
     * ├─────────────────────────────────────────────────────┤
     * │ Marker                                              │
     * ├─────────────────────────────────────────────────────┤
     * │ Marker                                              │
     * ├─────────────────────────────────────────────────────┤
     * │ Marker                                              │
     * ├──────────────────────────┬─────────────┬────────────┤
     * │ Length                   │ Type        │ Message    │
     * ├──────────────────────────┴─────────────┴────────────┤
     * │ ~Message                                            │
     * └─────────────────────────────────────────────────────┘
     * </pre>
     */
    static byte[] bgpMessage(String bgpHex) {
        // Removing whitespace and newlines from the dump.
        bgpHex = bgpHex.replaceAll("\\s+", "");

        if (bgpHex.length() % 2 != 0) {
            throw new IllegalArgumentException(
                    "Hex string must contain an even number of characters");
        }
        // Each bytes 2 hex numbers
        byte[] message = new byte[bgpHex.length() / 2];

        for (int i = 0; i < bgpHex.length(); i += 2) {
            try {
                message[i / 2] = (byte) Integer.parseInt(bgpHex.substring(i, i + 2), 16);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid hexadecimal byte", e);
            }
        }
        // A BGP message has:
        // Marker : 16 bytes
        // Length : 2 bytes
        // Type : 1 byte
        int minimumBgpLength = 19;
        if (message.length < minimumBgpLength) {
            throw new IllegalArgumentException("BGP message is too short: " + message.length + " bytes");
        }

        /*
         * From BGP message standard format, see example below:
         *
         * ```
         * Border Gateway Protocol - KEEPALIVE Message
         * Marker: ffffffffffffffffffffffffffffffff
         * Length: 19
         * Type: KEEPALIVE Message (4)
         * ```
         *
         * The first 16 bytes (0 to 15th byte) of a BGP message are the marker.
         * The 16th and 17th bytes are the 2 bytes for the Length field.
         * The 18th byte is the message type.
         */

        byte[] marker = new byte[16];
        System.arraycopy(message, 0, marker, 0, 16);

        for (byte b : marker) {
            if ((b & 0xff) != 0xff) {
                throw new IllegalArgumentException("Invalid BGP marker");
            }
        }

        int length = ((message[16] & 0xff) << 8) | (message[17] & 0xff);
        // Validate that the actual message length matches the length declared inside
        // the BGP message.
        if (message.length != length) {
            throw new IllegalArgumentException(
                    "Unexpected BGP payload length: " + message.length + " (BGP header declares " + length + ")");
        }

        int messageType = message[18] & 0xff;
        if (!MESSAGE_TYPES.containsKey(messageType)) {
            throw new IllegalArgumentException("Unknown BGP message type: " + messageType);
        }

        return message;
    }

    /**
     * Builds the 16-bit TCP Data Offset/Reserved/Flags field.
     *
     * Field format:
     * 
     * <pre>
     * ┌─────────────┬──────────┬────────────────┐
     * │ Data Offset │ Reserved │ Flags          │
     * │ 4 bits      │ 4 bits   │ 8 bits         │
     * └─────────────┴──────────┴────────────────┘
     * </pre>
     *
     * @param dataOffset TCP header length's measured in 32-bit words (4 bytes).
     *                   Therefore 20-byte TCP header with no options is represented
     *                   as 5
     * @param flags      TCP flags to enable.
     *                   Accepted names FIN, SYN, RST, PSH, ACK, URG, ECE, CWR.
     */
    static int tcpOffsetFlags(int dataOffset, TCPFlag... flags) {

        int tcpFlags = 0;

        for (TCPFlag flag : flags) {
            // Each TCP flag occupies a different bit. The selected flag values
            // are combined using bitwise OR (|), which turns on the bits for all
            // requested flags without changing the other flags.
            tcpFlags = tcpFlags | flag.value;
        }

        // The data offset is shifted into the upper 4 bits and combined with
        // the flags and we return the resulting 16-bit field as an integer.
        return (dataOffset << 12) | tcpFlags;
    }

    /**
     * Creates a TCP pseudo header.
     *
     * A TCP pseudo-header is a temporary piece of information used only when
     * calculating
     * the TCP checksum.
     *
     * <pre>
     *  
     * 0              8               16                       32
     * ├──────────────┴───────────────┴────────────────────────┤
     * │ Source IP address                                     │
     * ├───────────────────────────────────────────────────────┤
     * │ Destination IP address                                │
     * ├──────────────┬───────────────┬────────────────────────┤
     * │ Reserved     │ Protocol      │TCP length              │
     * └──────────────┴───────────────┴────────────────────────┘
     * </pre>
     */
    static byte[] tcpPseudoHeader(InetAddress srcIp, InetAddress dstIp, int tcpLength) {
        // 12 bytes pseudoheader
        ByteArrayOutputStream header = new ByteArrayOutputStream(12);

        header.writeBytes(srcIp.getAddress());
        header.writeBytes(dstIp.getAddress());
        header.write(0); // Reserved = 0
        header.write(6); // Protocol = TCP (6)
        // TCP length field is 16 bitsso we make the nnumber occupy those
        header.write((byte) (tcpLength >> 8)); // the upper 8 bits first
        header.write((byte) tcpLength); // the lower 8 bits

        return header.toByteArray();
    }

    /**
     * Creates the TCP header.
     *
     * <pre>
     * 0       4        8              16                             32
     * ├───────┴────────┴──────────────┼──────────────────────────────┤
     * │Source Port                    │Destination Port              │
     * ├───────────────────────────────┴──────────────────────────────┤
     * │Sequence Number                                               │
     * ├──────────────────────────────────────────────────────────────┤
     * │Acknowledgment Number                                         │
     * ├───────┬────────┬──────────────┬──────────────────────────────┤
     * │Data   │Reserved│Flags         │Window Size                   │
     * │Offset │        │              │                              │  
     * ├───────┴────────┴──────────────┼──────────────────────────────┤
     * │Checksum                       │Urgent Pointer                │
     * ├───────────────────────────────┴──────────────────────────────┤
     * │Options                                                       │
     * └──────────────────────────────────────────────────────────────┘
     * </pre>
     */
    static byte[] tcpHeader(TCPOptions tcpOptions, InetAddress srcIp, InetAddress dstIp, byte[] payload) {

        // Initializing a TCP header with checksum set to zero.
        tcpOptions.checksum = 0;
        // 20 bytes TCP header.
        ByteBuffer buffer = ByteBuffer.allocate(20);
        buffer.order(ByteOrder.BIG_ENDIAN);

        buffer.putShort((short) tcpOptions.srcPort);
        buffer.putShort((short) tcpOptions.dstPort);
        buffer.putInt((int) tcpOptions.seq);
        buffer.putInt((int) tcpOptions.ack);
        buffer.putShort((short) tcpOptions.offsetFlags);
        buffer.putShort((short) tcpOptions.window);
        buffer.putShort((short) tcpOptions.checksum);
        buffer.putShort((short) tcpOptions.urgent);

        byte[] tcpHeader = buffer.array();

        byte[] pseudoHeader = tcpPseudoHeader(srcIp, dstIp, tcpHeader.length + payload.length);

        byte[] checksumData = new byte[pseudoHeader.length + tcpHeader.length + payload.length];
        System.arraycopy(pseudoHeader, 0, checksumData, 0, pseudoHeader.length);
        System.arraycopy(tcpHeader, 0, checksumData, pseudoHeader.length, tcpHeader.length);
        System.arraycopy(payload, 0, checksumData, pseudoHeader.length + tcpHeader.length, payload.length);

        // TCP cheksum covers: pseudo-header + TCP header + payload
        int calculatedChecksum = checksum(checksumData);
        // Checksum occupies bytes 16-17 of the TCP header.
        tcpHeader[16] = (byte) (calculatedChecksum >> 8);
        tcpHeader[17] = (byte) calculatedChecksum;

        return tcpHeader;
    }

    /**
     * Creates the IPv4 header.
     *
     * <pre>
     * 0       4       8               16     19                      32
     * ├───────┼───────┼───────────────┼──────┴───────────────────────┤
     * │Version│IHL    │Type of Service│Total Length                  │
     * ├───────┴───────┴───────────────┼──────┬───────────────────────┤
     * │Identification                 │Flags │Fragment Offset        │
     * ├───────────────┬───────────────┼──────┴───────────────────────┤
     * │Time to Live   │Protocol       │Header Checksum               │
     * ├───────────────┴───────────────┴──────────────────────────────┤
     * │Source IP Address                                             │
     * ├──────────────────────────────────────────────────────────────┤
     * │Destination IP Address                                        │
     * ├──────────────────────────────────────────────────────────────┤
     * │Options                                                       │
     * └──────────────────────────────────────────────────────────────┘
     * </pre>
     */
    static byte[] ipHeader(IPOptions options) {

        // Initializing a TCP header with checksum set to zero.
        options.checksum = 0;

        // 20 bytes IPv4 header
        ByteBuffer header = ByteBuffer.allocate(20);
        header.order(ByteOrder.BIG_ENDIAN);

        header.put(options.versionIhl);
        header.put((byte) options.tos);
        header.putShort((short) options.ipPacketTotalLen);
        header.put(options.identification);
        header.put(options.flagsFragment);
        header.put((byte) options.ttl);
        header.put((byte) options.protocol);
        header.putShort((short) options.checksum);
        header.put(options.srcIp.getAddress());
        header.put(options.dstIp.getAddress());

        // Calculating checksum over the IP header. IP checksum covers only the IP
        // header.
        short checksum = (short) checksum(header.array());
        // Inserting the checksum on the 10th byte, it will take 2 bytes.
        header.putShort(10, checksum);

        return header.array();
    }

    /**
     * Creates the L2 ethernet header.
     *
     * <pre>
     * 0                            16                            32
     * ├────────────────────────────┴──────────────────────────────┤
     * │ Destination MAC Address                                   │
     * ├────────────────────────────┬──────────────────────────────┤
     * │ ~Destination MAC Address   │ Source MAC Address           │
     * ├────────────────────────────┴──────────────────────────────┤
     * │ ~Source MAC Address                                       │
     * ├────────────────────────────┬──────────────────────────────┤
     * │ EtherType                  │ Payload                      │
     * ├────────────────────────────┴──────────────────────────────┤
     * │ ~Payload                                                  │
     * ├───────────────────────────────────────────────────────────┤
     * │ Frame Check Sequence (FCS)                                │
     * └───────────────────────────────────────────────────────────┘
     * </pre>
     *
     */
    static byte[] ethernetHeader(EthernetOptions options) {
        // 14 bytes Etherent header
        ByteArrayOutputStream result = new ByteArrayOutputStream(14);

        result.writeBytes(options.dstMac);
        result.writeBytes(options.srcMac);
        result.writeBytes(options.etherType);

        return result.toByteArray();
    }

    /**
     * Generates a BGP packet.
     */
    static byte[] generateBgpPacket(byte[] bgpMessage, PacketOptions options) {

        // IPv4 packet total length includes:
        //
        // IP header = 20 bytes
        // TCP header = 20 bytes
        // BGP payload = N bytes
        //
        // Total: 20 + 20 + N = 40 + N bytes
        //
        options.ip.ipPacketTotalLen = 20 + 20 + bgpMessage.length;

        byte[] ethernet = ethernetHeader(options.ethernet);
        byte[] ip = ipHeader(options.ip);
        byte[] tcp = tcpHeader(options.tcp, options.ip.srcIp, options.ip.dstIp, bgpMessage);

        ByteArrayOutputStream packet = new ByteArrayOutputStream(
                ethernet.length + ip.length + tcp.length + bgpMessage.length);

        packet.writeBytes(ethernet);
        packet.writeBytes(ip);
        packet.writeBytes(tcp);
        packet.writeBytes(bgpMessage);

        return packet.toByteArray();
    }

    /**
     * Creates and saves a Wireshark-compatible classic `.pcap` file.
     *
     * PCap Structure:
     *
     *	FILE
     *	│
     *	├── Global Header
     *	│   ├── Magic Number
     *	│   ├── Version
     *	│   ├── Snapshot Length
     *	│   └── Link-layer Type
     *	│
     *	├── Packet Record Header
     *	│   ├── Timestamp
     *	│   ├── Captured Length
     *	│   └── Original Length
     *	│
     *	└── Captured Packet
     */
    static void writePcap(byte[] packet, Path filename) throws IOException {

        // Every classic PCAP file starts with a global header 24 bytes.
        //
        ByteBuffer globalHeader = ByteBuffer.allocate(24);
        // PCAP headers are written little-endian.
        globalHeader.order(ByteOrder.LITTLE_ENDIAN);
        globalHeader.putInt(0xA1B2C3D4); // PCAP magic number to identify the file as a PCAP
        globalHeader.putShort((short) 2); // PCAP major version
        globalHeader.putShort((short) 4); // PCAP minor version
        globalHeader.putInt(0); // Timezone correction
        globalHeader.putInt(0); // Timestamp accuracy
        globalHeader.putInt(65535); // Maximum captured packet size
        globalHeader.putInt(1); // Link-layer type: 1 = Ethernet

        // Every packet in a PCAP has a packet record header.
        //
        ByteBuffer packetHeader = ByteBuffer.allocate(16);
        packetHeader.order(ByteOrder.LITTLE_ENDIAN);
        // We don't know the original timestamp so using zero for this packet.
        int timestampSeconds = 0;
        // Microseconds portion of timestamp.
        int timestampMicroseconds = 0;
        packetHeader.putInt(timestampSeconds);
        packetHeader.putInt(timestampMicroseconds);
        packetHeader.putInt(packet.length);
        packetHeader.putInt(packet.length);

        // Writing the the file. This contains:
        // Wireshark file metadata
        // Wireshark packet record metadata
        // Ethernet frame:
        //   - Ethernet header
        //   - IPv4 header
        //   - TCP header
        //   - BGP message
        try (var f = Files.newOutputStream(filename)) {
            f.write(globalHeader.array());
            f.write(packetHeader.array());
            f.write(packet);
        }
    }

    static void generatePcap(String bgpHex, PacketOptions options) throws IOException {

        Path filename = Paths.get(System.getProperty("user.home"), "bgp_dump.pcap");

        byte[] message = bgpMessage(bgpHex);
        byte[] packet = generateBgpPacket(message, options);

        writePcap(packet, filename);

        System.out.println();
        System.out.println("=".repeat(60));
        System.out.println("PCAP CREATED SUCCESSFULLY");
        System.out.println("=".repeat(60));

        System.out.printf("Full path       : %s%n", filename.toAbsolutePath());
        System.out.printf("File size       : %d bytes%n", Files.size(filename));
        System.out.printf("Ethernet frame  : %d bytes%n", packet.length);
        System.out.printf("BGP payload     : %d bytes%n", message.length);

        // Doing `& 0xff` when indexing `message` because bytes are signed in java.
        // The `& 0xff` clears the upper bits that will be filled due to sign extension
        // when converting signed bytes to int.
        int type = message[18] & 0xff; // Byte 18 is the BGP message type.
        System.out.printf("BGP message     : %s (type %d)%n", bgpMessageType(type), type);
        // Bytes 16 and 17 are BGP Length field but we need to convert the two-byte
        // from hexadecimal bytes into an integer. E.g., 00 41 -> 65
        System.out.printf("BGP length      : %d bytes%n", ((message[16] & 0xff) << 8) | (message[17] & 0xff));

        System.out.println("=".repeat(60));
    }

    static TCPOptions defaultTCPOptions() {
        TCPOptions options = new TCPOptions();

        options.srcPort = 179;
        options.dstPort = 12345;
        options.seq = 1000;
        options.ack = 2000;
        options.offsetFlags = tcpOffsetFlags(5, TCPFlag.PSH, TCPFlag.ACK);
        options.window = 65535;
        options.checksum = 0;
        options.urgent = 0;

        return options;
    }

    static IPOptions defaultIPOptions() {
        IPOptions options = new IPOptions();

        // We don't know the real source and destination IPs from the Cisco dump so
        // we use some syntetic addresses.
        try {
            options.srcIp = InetAddress.getByName("0.0.0.0");
            options.dstIp = InetAddress.getByName("0.0.0.0");
        } catch (UnknownHostException e) {
            throw new RuntimeException("Invalid IP address", e);
        }

        options.ttl = 64;
        options.protocol = 6; // TCP number

        // IPv4 header is normally 20 bytes when there are no options.
        //
        // IP version = 4
        // IP Header length = 20 bytes
        //
        // The length (IHL) is measured in 32-bit (4 bytes) words so 20 bytes is 5
        // because 20/4 = 5. Therefore:
        //
        // IPv4 Version Field = 4 (4 bits)
        // Internet Header Length Field = 5 (4 bits)
        //
        // These 2 values form 1 byte.
        options.versionIhl = new byte[] { 0x45 };

        // We don't know the original value, it is normally CS6 but we can use zero.
        options.tos = 0;

        // Synthetic IP identification value.
        options.identification = new byte[] { 0x12, 0x34 };

        // IPv4 flags and fragment offset take 2 bytes.
        // 0x4000 means: Don't Fragment (DF), the offset is 0.
        options.flagsFragment = new byte[] { 0x40, 0x00 };

        options.ipPacketTotalLen = 0; // Packet length will be calcuated later.
        options.checksum = 0; // Initial checksum value.

        return options;
    }

    static EthernetOptions defaultEthernetOptions() {
        EthernetOptions options = new EthernetOptions();
        // We don't have the real MAC addresses from the Cisco MSGDUMP
        options.dstMac = new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
        options.srcMac = new byte[] { 0x00, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd, (byte) 0xee };
        // The EtherType for IPv4 is 0x0800
        options.etherType = new byte[] { 0x08, 0x00 };

        return options;
    }

    public static void main(String[] args) throws Exception {

        final String PROGRAM_NAME = "msgdmp-to-pcap";

        if (args.length < 1) {
            System.out.printf(
                    "Usage:%n" +
                            "  %s $BGP_HEX%n%n" +
                            "Example:%n" +
                            "  %s \"FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF  FFFF FFFF FFFF FFFF  0013 0400\"%n",
                    PROGRAM_NAME,
                    PROGRAM_NAME);
            System.exit(1);
        }

        StringBuilder bgpHex = new StringBuilder();

        for (String arg : args) {
            bgpHex.append(arg);
        }

        generatePcap(
                bgpHex.toString(),
                new PacketOptions(
                        defaultTCPOptions(),
                        defaultIPOptions(),
                        defaultEthernetOptions()));
    }
}
