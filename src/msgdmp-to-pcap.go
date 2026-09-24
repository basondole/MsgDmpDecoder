// Utility for parsing Cisco BGP MSGDUMP logs and transforming them into
// standard Wireshark PCAP.
//
// Example:
// ```
// ❯ go run msgdmp-to-pcap.go "FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 0118
// 0200 0000 FD40 0101 0040 0206 0202 0D1C 316E 4003 04C3 10A1 6180 0404 0000
// 0000 4005 0400 0000 3CC0 081C 0D1C 0002 0D1C 0016 0D1C 0056 0D1C
// 01F7 0D1C 029A 0D1C 0813 FDE8 FDDE F063 0BB8 0000 0000 0000 0000 0000 0000
// 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
// 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
// 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
// 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
// 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
// 0000 0000 0000 0000
// 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 185D AF90"
//
// ============================================================
// PCAP CREATED SUCCESSFULLY
// ============================================================
// Full path       : /Users/bar/bgp_dump.pcap
// File size       : 374 bytes
// Ethernet frame  : 334 bytes
// BGP payload     : 280 bytes
// BGP message     : UPDATE (type 2)
// BGP length      : 280 bytes
// ============================================================
// ```

package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// BGP message types
var messageTypes = map[byte]string{
	1: "OPEN",
	2: "UPDATE",
	3: "NOTIFICATION",
	4: "KEEPALIVE",
	5: "ROUTE-REFRESH",
}

// tcpFlag is an 8-bit TCP flag
type tcpFlag uint8

const (
	FIN tcpFlag = 1 << iota // 1
	SYN                     // 2
	RST                     // 4
	PSH                     // 8
	ACK                     // 16
	URG                     // 32
	ECE                     // 64
	CWR                     // 128
)

// Fields of the TCP header.
type TCPOptions struct {
	srcPort     uint16
	dstPort     uint16
	seq         uint32
	ack         uint32
	offsetFlags uint16
	window      uint16
	checksum    uint16
	urgent      uint16
}

// Fields of the IPv4 header.
type IPOptions struct {
	versionIHL       uint8
	tos              uint8
	ipPacketTotalLen uint16
	identification   uint16
	flagsFragment    uint16
	ttl              uint8
	protocol         uint8
	checksum         uint16
	srcIP            string
	dstIP            string
}

// Fields of the Ethernet header.
type EthernetOptions struct {
	dstMAC    [6]byte
	srcMAC    [6]byte
	etherType uint16
}

type PacketOptions struct {
	tcp      TCPOptions
	ip       IPOptions
	etherent EthernetOptions
}

// checksum calculates the Internet checksum as described by RFC 1071.
func checksum(data []byte) uint16 {

	var total uint32
	for i := 0; i+1 < len(data); i += 2 {
		// Converting two 8-bit bytes into one 16-bit number.
		// Example: 0x12 0x34 -> becomes: 0x1234
		word := uint16(data[i])<<8 | uint16(data[i+1])
		// Internet checksum works on 16-bit words but when you add two 16-bit
		// numbers the result can overflow to 17 bits so we use 32 int to
		// accomodate that.
		total += uint32(word)
		// End-around carry to fold the result back to 16 bits
		total = (total & 0xffff) + (total >> 16)
	}
	// The checksum operates on 16-bit words (2 bytes) so we need an even number
	// of bytes. If the data has an odd number of bytes, there'd be one byte
	// left over, treat it as the high byte of a 16-bit word and pad the low
	// byte with 0.
	if len(data)%2 != 0 {
		total += uint32(data[len(data)-1]) << 8
		total = (total & 0xffff) + (total >> 16)
	}
	// One's complement.
	return ^uint16(total)
}

// bgpMessage converts the hexadecimal BGP dump into bytes.
//
// BGP message general format:
//
//	0                          16            24           3
//	├──────────────────────────┴─────────────┴────────────┤
//	│ Marker                                              │
//	├─────────────────────────────────────────────────────┤
//	│ Marker                                              │
//	├─────────────────────────────────────────────────────┤
//	│ Marker                                              │
//	├─────────────────────────────────────────────────────┤
//	│ Marker                                              │
//	├──────────────────────────┬─────────────┬────────────┤
//	│ Length                   │ Type        │ Message    │
//	├──────────────────────────┴─────────────┴────────────┤
//	│ ~Message                                            │
//	└─────────────────────────────────────────────────────┘
//
// Example:
//
//	Border Gateway Protocol - KEEPALIVE Message
//	Marker: ffffffffffffffffffffffffffffffff
//	Length: 19
//	Type: KEEPALIVE Message (4)
func bgpMessage(bgpHex string) ([]byte, error) {
	// Remove whitespace/newlines from the dump.
	bgpHex = strings.Join(strings.Fields(bgpHex), "")
	message, err := hex.DecodeString(bgpHex)
	if err != nil {
		return nil, fmt.Errorf("invalid BGP hex: %w", err)
	}
	// A BGP message has:
	//  - Marker : 16 bytes
	//  - Length : 2 bytes
	//  - Type   : 1 byte
	//
	// So, minimum BGP message size: Marker 16 + Length 2 + Type 1 = 19 bytes.
	if len(message) < 19 {
		return nil, fmt.Errorf("BGP message is too short: %d bytes", len(message))
	}
	// First 16 bytes must be FF for the marker.
	for _, b := range message[:16] {
		if b != 0xff {
			return nil, fmt.Errorf("invalid BGP marker")
		}
	}
	// BGP Length is a 16-bit big-endian value.
	// The 16th and 17th bytes are the 2 bytes for the Length field.
	length := binary.BigEndian.Uint16(message[16:18])
	if len(message) != int(length) {
		return nil, fmt.Errorf(
			"unexpected BGP payload length: %d bytes (BGP header declares %d)",
			len(message), length,
		)
	}
	// The 18th byte is the message type.
	messageType := message[18]
	if _, ok := messageTypes[messageType]; !ok {
		return nil, fmt.Errorf("unknown BGP message type: %d", messageType)
	}

	return message, nil
}

// tcpOffsetFlags creates the TCP Data Offset + Reserved + Flags field.
//
//	┌─────────────┬──────────┬────────────────┐
//	│ Data Offset │ Reserved │     Flags      │
//	│   4 bits    │  4 bits  │     8 bits     │
//	└─────────────┴──────────┴────────────────┘
//
// dataOffset is the TCP header length measured in 32-bit words (4 bytes).
// Therefore for a 20-byte TCP header with no options the offset is 5.
//
// flags contains the TCP flags to enable.
// Accepted names FIN, SYN, RST, PSH, ACK, URG, ECE, CWR.
func tcpOffsetFlags(flags []tcpFlag, dataOffset uint8) uint16 {
	var tcpFlags uint8
	for _, flag := range flags {
		// Each TCP flag occupies a different bit. The selected flag values
		// are combined using bitwise OR (|), which turns on the bits for all
		// requested flags without changing the other flags.
		tcpFlags |= uint8(flag)
	}

	return (uint16(dataOffset) << 12) | uint16(tcpFlags)
}

// tcpPseudoHeader creates the IPv4 TCP pseudo-header.
//
// A TCP pseudo-header is a temporary piece of information used only when
// calculating the TCP checksum.
//
//	0              8               16                       3
//	├──────────────┴───────────────┴────────────────────────┤
//	│ Source IP address                                     │
//	├───────────────────────────────────────────────────────┤
//	│ Destination IP address                                │
//	├──────────────┬───────────────┬────────────────────────┤
//	│ Reserved     │ Protocol      │TCP length              │
//	└──────────────┴───────────────┴────────────────────────┘
//
// Total = 12 bytes.
func tcpPseudoHeader(srcIP, dstIP string, tcpLength int) ([]byte, error) {

	src := net.ParseIP(srcIP).To4()
	dst := net.ParseIP(dstIP).To4()
	if src == nil {
		return nil, fmt.Errorf("invalid source IPv4 address: %s", srcIP)
	}
	if dst == nil {
		return nil, fmt.Errorf("invalid destination IPv4 address: %s", dstIP)
	}

	header := make([]byte, 12) // the header is 12 bytes long

	copy(header[0:4], src)
	copy(header[4:8], dst)
	header[8] = 0                                                // Reserved = 0
	header[9] = 6                                                // Protocol  number for TCP
	binary.BigEndian.PutUint16(header[10:12], uint16(tcpLength)) // TCP length

	return header, nil
}

// tcpHeader creates the TCP header and calculates its checksum.
//
// TCP header format:
//
//	0       4        8              16                             3
//	├───────┴────────┴──────────────┼──────────────────────────────┤
//	│Source Port                    │Destination Port              │
//	├───────────────────────────────┴──────────────────────────────┤
//	│Sequence Number                                               │
//	├──────────────────────────────────────────────────────────────┤
//	│Acknowledgment Number                                         │
//	├───────┬────────┬──────────────┬──────────────────────────────┤
//	│Data   │Reserved│Flags         │Window Size                   │
//	│Offset │        │              │                              │
//	├───────┴────────┴──────────────┼──────────────────────────────┤
//	│Checksum                       │Urgent Pointer                │
//	├───────────────────────────────┴──────────────────────────────┤
//	│Options                                                       │
//	└──────────────────────────────────────────────────────────────┘
func tcpHeader(opts TCPOptions, srcIP, dstIP string, payload []byte) ([]byte, error) {

	// TCP header without options is 20 bytes.
	header := make([]byte, 20)
	// Initial checksum must be set to zero
	opts.checksum = 0

	binary.BigEndian.PutUint16(header[0:2], opts.srcPort)
	binary.BigEndian.PutUint16(header[2:4], opts.dstPort)
	binary.BigEndian.PutUint32(header[4:8], opts.seq)
	binary.BigEndian.PutUint32(header[8:12], opts.ack)
	binary.BigEndian.PutUint16(header[12:14], opts.offsetFlags)
	binary.BigEndian.PutUint16(header[14:16], opts.window)
	binary.BigEndian.PutUint16(header[16:18], opts.checksum)
	binary.BigEndian.PutUint16(header[18:20], opts.urgent)

	pseudoHeader, err := tcpPseudoHeader(srcIP, dstIP, len(header)+len(payload))
	if err != nil {
		return nil, err
	}

	// The TCP checksum covers:
	//  - Pseudo-header
	//  - TCP header
	//  - TCP payload
	//
	checksumData := make([]byte, 0, len(pseudoHeader)+len(header)+len(payload))
	checksumData = append(checksumData, pseudoHeader...)
	checksumData = append(checksumData, header...)
	checksumData = append(checksumData, payload...)

	// Checksum takes the 16th and 17th bytes
	binary.BigEndian.PutUint16(header[16:18], checksum(checksumData))

	return header, nil
}

// ipHeader creates the IPv4 header and calculates its checksum.
//
// IPv4 header format:
//
//	0       4       8               16     19                      3
//	├───────┼───────┼───────────────┼──────┴───────────────────────┤
//	│Version│IHL    │Type of Service│Total Length                  │
//	├───────┴───────┴───────────────┼──────┬───────────────────────┤
//	│Identification                 │Flags │Fragment Offset        │
//	├───────────────┬───────────────┼──────┴───────────────────────┤
//	│Time to Live   │Protocol       │Header Checksum               │
//	├───────────────┴───────────────┴──────────────────────────────┤
//	│Source IP Address                                             │
//	├──────────────────────────────────────────────────────────────┤
//	│Destination IP Address                                        │
//	├──────────────────────────────────────────────────────────────┤
//	│Options                                                       │
//	└──────────────────────────────────────────────────────────────┘
func ipHeader(fields IPOptions) ([]byte, error) {

	src := net.ParseIP(fields.srcIP).To4()
	dst := net.ParseIP(fields.dstIP).To4()

	if src == nil {
		return nil, fmt.Errorf("invalid source IPv4 address: %s", fields.srcIP)
	}
	if dst == nil {
		return nil, fmt.Errorf("invalid destination IPv4 address: %s", fields.dstIP)
	}

	// IPv4 header without options = 20 bytes.
	header := make([]byte, 20)

	header[0] = fields.versionIHL
	header[1] = fields.tos

	binary.BigEndian.PutUint16(header[2:4], fields.ipPacketTotalLen)
	binary.BigEndian.PutUint16(header[4:6], fields.identification)
	binary.BigEndian.PutUint16(header[6:8], fields.flagsFragment)

	header[8] = fields.ttl
	header[9] = fields.protocol

	// Checksum initially zero.
	binary.BigEndian.PutUint16(header[10:12], 0)

	copy(header[12:16], src)
	copy(header[16:20], dst)
	// IP checksum covers only the IP header.
	ipChecksum := checksum(header)
	// Backfill the checksum in the 10th and 11th bytes.
	binary.BigEndian.PutUint16(header[10:12], ipChecksum)

	return header, nil
}

// ethernetHeader creates the Ethernet II header.
//
// L2 frame format:
//
//	0                            16                             3
//	├────────────────────────────┴──────────────────────────────┤
//	│ Destination MAC Address                                   │
//	├────────────────────────────┬──────────────────────────────┤
//	│ ~Destination MAC Address   │ Source MAC Address           │
//	├────────────────────────────┴──────────────────────────────┤
//	│ ~Source MAC Address                                       │
//	├────────────────────────────┬──────────────────────────────┘
//	│ EtherType                  │
//	└────────────────────────────┘
func ethernetHeader(fields EthernetOptions) []byte {
	// Ethernet frame starts with:
	//   Destination MAC address = 6 bytes
	//   Source MAC address      = 6 bytes
	//   EtherType               = 2 bytes
	//
	// Total is: 14 bytes
	//
	header := make([]byte, 14)

	copy(header[0:6], fields.dstMAC[:])
	copy(header[6:12], fields.srcMAC[:])
	binary.BigEndian.PutUint16(header[12:14], fields.etherType)

	return header
}

// generateBGPPacket geerates a BGP packet.
func generateBGPPacket(bgpMessage []byte, opts PacketOptions) ([]byte, error) {

	// IPv4 packet total length includes:
	//  - IP header   = 20 bytes
	//  - TCP header  = 20 bytes
	//  - BGP payload =  N bytes
	//
	// Total: 20 + 20 + N = 40 + N bytes
	//
	packetTotalLength := 20 + 20 + len(bgpMessage)
	opts.ip.ipPacketTotalLen = uint16(packetTotalLength)

	ethernet := ethernetHeader(opts.etherent)

	ip, err := ipHeader(opts.ip)
	if err != nil {
		return nil, err
	}

	tcp, err := tcpHeader(opts.tcp, opts.ip.srcIP, opts.ip.dstIP, bgpMessage)
	if err != nil {
		return nil, err
	}

	packet := make([]byte, 0, len(ethernet)+len(ip)+len(tcp)+len(bgpMessage))
	packet = append(packet, ethernet...)
	packet = append(packet, ip...)
	packet = append(packet, tcp...)
	packet = append(packet, bgpMessage...)

	return packet, nil
}

// writePCAP creates and saves a Wireshark compatible `.pcap` file.
//
// PCap Structure:
//
//	FILE
//	│
//	├── Global Header
//	│   ├── Magic Number
//	│   ├── Version
//	│   ├── Snapshot Length
//	│   └── Link-layer Type
//	│
//	├── Packet Record Header
//	│   ├── Timestamp
//	│   ├── Captured Length
//	│   └── Original Length
//	│
//	└── Captured Packet
func writePCAP(packet []byte, filename string) error {

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	// Every classic PCAP file starts with a global header.
	//
	globalHeader := make([]byte, 24)
	// PCAP magic number to identify the file as a PCAP
	binary.LittleEndian.PutUint32(globalHeader[0:4], 0xA1B2C3D4)
	// PCAP major version
	binary.LittleEndian.PutUint16(globalHeader[4:6], 2)
	// PCAP minor version
	binary.LittleEndian.PutUint16(globalHeader[6:8], 4)
	// Timezone correction = 0
	binary.LittleEndian.PutUint32(globalHeader[8:12], 0)
	// Timestamp accuracy = 0
	binary.LittleEndian.PutUint32(globalHeader[12:16], 0)
	// Maximum capture length
	binary.LittleEndian.PutUint32(globalHeader[16:20], 65535)
	// Link-layer type: 1 = Ethernet
	binary.LittleEndian.PutUint32(globalHeader[20:24], 1)

	if _, err := f.Write(globalHeader); err != nil {
		return err
	}

	// Packet record header.
	//
	packetHeader := make([]byte, 16)
	// Timestamp seconds = 0.
	binary.LittleEndian.PutUint32(packetHeader[0:4], 0)
	// Timestamp microseconds = 0.
	binary.LittleEndian.PutUint32(packetHeader[4:8], 0)
	// Number of bytes actually stored
	binary.LittleEndian.PutUint32(packetHeader[8:12], uint32(len(packet)))
	// Original packet size
	binary.LittleEndian.PutUint32(packetHeader[12:16], uint32(len(packet)))

	if _, err := f.Write(packetHeader); err != nil {
		return err
	}

	// The actual Ethernet frame contains:
	//   - Ethernet header
	//   - IPv4 header
	//   - TCP header
	//   - BGP message
	if _, err := f.Write(packet); err != nil {
		return err
	}

	return nil
}

// generatePCAP generates a pcap file.
func generatePCAP(bgpHex string, opts PacketOptions) error {

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("could not determine home directory: %w", err)
	}
	filename := filepath.Join(homeDir, "bgp_dump.pcap")

	message, err := bgpMessage(bgpHex)
	if err != nil {
		return err
	}

	packet, err := generateBGPPacket(message, opts)
	if err != nil {
		return err
	}

	if err := writePCAP(packet, filename); err != nil {
		return err
	}

	messageType := message[18]
	bgpLength := binary.BigEndian.Uint16(message[16:18])

	info, err := os.Stat(filename)
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("PCAP CREATED SUCCESSFULLY")
	fmt.Println(strings.Repeat("=", 60))

	fmt.Printf("Full path       : %s\n", filename)
	fmt.Printf("File size       : %d bytes\n", info.Size())
	fmt.Printf("Ethernet frame  : %d bytes\n", len(packet))
	fmt.Printf("BGP payload     : %d bytes\n", len(message))
	fmt.Printf("BGP message     : %s (type %d)\n", messageTypes[messageType], messageType)
	fmt.Printf("BGP length      : %d bytes\n", bgpLength)

	fmt.Println(strings.Repeat("=", 60))

	return nil
}

// defaultTCPOptions provides default values for TCP Header fields.
func defaultTCPOptions() TCPOptions {
	return TCPOptions{
		srcPort:     179,   // Making src the BGP server
		dstPort:     12345, // Synthetic ephemeral port for the client
		seq:         1000,  // Synthetic sequence number
		ack:         2000,  // Synthetic ack number
		offsetFlags: tcpOffsetFlags([]tcpFlag{PSH, ACK}, 5),
		window:      65535, // Max value of the 16 bis field.
		checksum:    0,     // Initial checksum, we'll calculate it later.
		urgent:      0,     // Urgent pointer not being used.
	}
}

// defaultIPOptions provides default values for IPv4 Header fields.
func defaultIPOptions() IPOptions {
	return IPOptions{
		// The length (IHL) is measured in 32-bit (4 bytes) words so 20
		// bytes is represented as 5. Because 20/4 = 5. Therefore:
		//
		//  IPv4 Version Field = 4 (4 bits)
		//  Internet Header Length Field = 5 (4 bits)
		//
		// These 2 values form 1 byte.
		versionIHL: 0x45,
		// We don't know the original value, normally it would be NC or CS6
		// but we use zero for now.
		tos:              0,
		ipPacketTotalLen: 0,      // Packet length will be calcuated later.
		identification:   0x1234, // Synthetic IP identification value
		// IPv4 flags and fragment offset consume 2 bytes.
		// 0x4000 means: Don't Fragment (DF) and the offset is 0.
		flagsFragment: 0x4000,
		ttl:           64,
		protocol:      6, // TCP protocol number
		checksum:      0, // We initially put zero into the checksum field.
		// We don't know the real source and destination IPs from the Cisco
		// dump so we use some syntetic addresses.
		srcIP: "0.0.0.0",
		dstIP: "0.0.0.0",
	}
}

// defaultEthernetOptions provides default values for Etherent Header fields.
func defaultEthernetOptions() EthernetOptions {
	return EthernetOptions{
		// We don't have the real MAC addresses.
		dstMAC:    [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		srcMAC:    [6]byte{0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee},
		etherType: 0x0800, // The EtherType for IPV4 is 0x0800

	}
}

// defaultPacketOptions provides default values for packet fields.
func defaultPacketOptions() PacketOptions {
	return PacketOptions{
		tcp:      defaultTCPOptions(),
		ip:       defaultIPOptions(),
		etherent: defaultEthernetOptions(),
	}
}

// Entry point
func main() {
	const programName = "msgdmp-to-pcap"
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr,
			`Usage:
  %s $BGP_HEX

Example:
  %s "FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 0013 0400"

`, programName, programName)

		os.Exit(1)
	}
	bgpHex := strings.Join(os.Args[1:], "")
	if err := generatePCAP(bgpHex, defaultPacketOptions()); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

}
