//! Utility for parsing Cisco BGP MSGDUMP logs and transforming them into
//! standard Wireshark PCAP.
//!
//! ## Example:
//! ```
//! ❯ cargo install rust-script
//! ❯ rust-script msgdmp-to-pcap.rs "FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF
//!  0041 0104 5BA0 00B4 0303 0303 2402 0601
//!  0400 0100 8002 0601 0400 0100 0102 0280
//!  0002 0202 0002 0246 0002 0641 0400 068D
//!  B8"
//!
//! ============================================================
//! PCAP CREATED SUCCESSFULLY
//! ============================================================
//! Full path       : /Users/foo/bgp_dump.pcap
//! File size       : 159 bytes
//! Ethernet frame  : 119 bytes
//! BGP payload     : 65 bytes
//! BGP message     : OPEN (type 1)
//! BGP length      : 65 bytes
//! ============================================================
//! ```

use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::PathBuf;

const MESSAGE_TYPES: [(u8, &str); 5] = [
    (1, "OPEN"),
    (2, "UPDATE"),
    (3, "NOTIFICATION"),
    (4, "KEEPALIVE"),
    (5, "ROUTE-REFRESH"),
];

fn bgp_message_type(msg_type: u8) -> &'static str {
    MESSAGE_TYPES
        .iter()
        .find(|(kind, _)| *kind == msg_type)
        .map(|(_, name)| *name)
        .unwrap_or("UNKNOWN")
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
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

/// Fields of the TCP header.
struct TCPOptions {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    offset_flags: u16,
    window: u16,
    checksum: u16,
    urgent: u16,
}

/// Fields of the IPv4 Header.
#[derive(Clone)]
struct IPOptions {
    version_ihl: u8,
    tos: u8,
    ip_packet_total_len: u16,
    identification: u16,
    flags_fragment: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
}
/// Ethernet Header fields.
struct EthernetOptions {
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    ether_type: u16,
}

struct PacketOptions {
    tcp: TCPOptions,
    ip: IPOptions,
    ethernet: EthernetOptions,
}

/// Calculates the Internet checksum based on RFC1071.
///
/// The checksum is needed for the IP and TCP headers.
fn checksum(data: &[u8]) -> u16 {
    let mut data = data.to_vec();
    // The checksum operates on 16-bit words (2 bytes) so we need an even number
    // of bytes. If the data has an odd number of bytes pad it to make it even.
    if data.len() % 2 != 0 {
        data.push(0);
    }
    // Checksum accumulator starts at zero.
    // This is a 16 bit value but can temporary spill over during calculation
    // so setting it as 32 bits to account for any carry over.
    let mut total: u32 = 0;

    // Each iteration processes one 16-bit word i.e., 2 bytes.
    for i in (0..data.len()).step_by(2) {
        // Converting two 8-bit bytes into one 16-bit number.
        // Example: 0x12 0x34 -> becomes: 0x1234
        let word = (u16::from(data[i]) << 8) | u16::from(data[i + 1]);

        total += u32::from(word);

        // We added the word to the cumulated checksum total. But when adding the
        // 16-bit word to the accumulated checksum total, the result can exceed
        // 16 bits. So fold anything above 16 bits back into the 16 bits.
        total = (total & 0xFFFF) + (total >> 16);
    }

    // The final step of the Internet checksum calculation:
    // One's complement of the final 16-bit value.
    !total as u16
}

/// Generates BGP message from hex string.
///
/// BGP message general format:
///
/// ```
/// 0                          16            24           32
/// ├──────────────────────────┴─────────────┴────────────┤
/// │ Marker                                              │
/// ├─────────────────────────────────────────────────────┤
/// │ Marker                                              │
/// ├─────────────────────────────────────────────────────┤
/// │ Marker                                              │
/// ├─────────────────────────────────────────────────────┤
/// │ Marker                                              │
/// ├──────────────────────────┬─────────────┬────────────┤
/// │ Length                   │ Type        │ Message    │
/// ├──────────────────────────┴─────────────┴────────────┤
/// │ ~Message                                            │
/// └─────────────────────────────────────────────────────┘
/// ```
fn bgp_message(bgp_hex: &str) -> Vec<u8> {
    // Removing whitespace and newlines from the dump.
    let bgp_hex: String = bgp_hex.chars().filter(|c| !c.is_whitespace()).collect();

    assert!(
        bgp_hex.len() % 2 == 0,
        "Hex string must contain an even number of characters"
    );
    // Every two hex characters represent one byte.
    let mut message = Vec::with_capacity(bgp_hex.len() / 2);

    for i in (0..bgp_hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&bgp_hex[i..i + 2], 16)
            .unwrap_or_else(|_| panic!("Invalid hexadecimal byte"));
        message.push(byte);
    }
    // A BGP message has:
    //  - Marker : 16 bytes
    //  - Length : 2 bytes
    //  - Type   : 1 byte
    let minimum_bgp_length = 19;
    assert!(
        message.len() >= minimum_bgp_length,
        "BGP message is too short: {} bytes",
        message.len()
    );

    /*
    From BGP message standard format, example below:

    ```
    Border Gateway Protocol - KEEPALIVE Message
    Marker: ffffffffffffffffffffffffffffffff
    Length: 19
    Type: KEEPALIVE Message (4)
    ```

    The first 16 bytes (0 to 15th byte) of a BGP message are the marker. Thus
    the 16th and 17th bytes are the 2 bytes for the Length field. And, the 18th
    byte is the message type.
    */
    let marker = &message[..16];
    assert_eq!(marker, &[0xff; 16], "Invalid BGP marker");

    let length = u16::from_be_bytes([message[16], message[17]]) as usize;
    // Validate that the actual message length matches the length declared
    // inside the BGP message.
    assert_eq!(
        message.len(),
        length,
        "Unexpected BGP payload length: {} (BGP header declares {})",
        message.len(),
        length
    );

    let message_type = message[18];
    assert!(
        MESSAGE_TYPES.iter().any(|(kind, _)| *kind == message_type),
        "Unknown BGP message type: {}",
        message_type
    );

    message
}

/// Builds the 16-bit TCP Data Offset/Reserved/Flags field.
///
/// ```
/// ┌─────────────┬──────────┬────────────────┐
/// │ Data Offset │ Reserved │     Flags      │
/// │   4 bits    │  4 bits  │     8 bits     │
/// └─────────────┴──────────┴────────────────┘
/// ```
/// # Parameters
/// * `data_offset` - TCP header length's measured in 32-bit words (4 bytes).
///       Therefore 20-byte TCP header with no options is represented as 5
/// * `flags` - TCP flags to enable.
///
fn tcp_offset_flags(
    /* TCP flags to enable accepted values: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR */
    flags: &[TCPFlag],
    data_offset: u8,
) -> u16 {
    let mut tcp_flags = 0u8;
    for &flag in flags {
        // Each TCP flag occupies a different bit. The selected flag values
        // are combined using bitwise OR (|), which turns on the bits for all
        // requested flags without changing the other flags.
        tcp_flags = tcp_flags | flag as u8;
    }

    // The data offset is shifted into the upper 4 bits and combined with
    // the flags and we return the resulting 16-bit field as an integer.
    (u16::from(data_offset) << 12) | (tcp_flags as u16)
}

/// Createss a TCP pseudo header.
///
/// A TCP pseudo-header is a temporary piece of information used only when
/// calculating the TCP checksum.
///
/// TCP pseudo header format:
///
/// ```
/// 0              8               16                       32
/// ├──────────────┴───────────────┴────────────────────────┤
/// │ Source IP address                                     │
/// ├───────────────────────────────────────────────────────┤
/// │ Destination IP address                                │
/// ├──────────────┬───────────────┬────────────────────────┤
/// │ Reserved     │ Protocol      │TCP length              │
/// └──────────────┴───────────────┴────────────────────────┘
/// ```
fn tcp_pseudo_header(src_ip: &Ipv4Addr, dst_ip: &Ipv4Addr, tcp_length: u16) -> Vec<u8> {
    let mut result = Vec::with_capacity(12); // Pseudo header is 12 bytes

    result.extend_from_slice(&src_ip.octets());
    result.extend_from_slice(&dst_ip.octets());
    result.push(0); // Reserved = 0
    result.push(6); // Protocol = TCP (6)
    result.extend_from_slice(&tcp_length.to_be_bytes());

    result
}

/// Creates the TCP header.
///
/// TCP header format:
/// ```
/// 0       4        8              16                             32
/// ├───────┴────────┴──────────────┼──────────────────────────────┤
/// │Source Port                    │Destination Port              │
/// ├───────────────────────────────┴──────────────────────────────┤
/// │Sequence Number                                               │
/// ├──────────────────────────────────────────────────────────────┤
/// │Acknowledgment Number                                         │
/// ├───────┬────────┬──────────────┬──────────────────────────────┤
/// │Data   │Reserved│Flags         │Window Size                   │
/// │Offset │        │              │                              │
/// ├───────┴────────┴──────────────┼──────────────────────────────┤
/// │Checksum                       │Urgent Pointer                │
/// ├───────────────────────────────┴──────────────────────────────┤
/// │Options                                                       │
/// └──────────────────────────────────────────────────────────────┘
/// ```
fn tcp_header(
    options: &mut TCPOptions,
    src_ip: Ipv4Addr,
    dst_ip: &Ipv4Addr,
    payload: &[u8],
) -> Vec<u8> {
    // 20 bytes TCP header
    let mut tcp_header = Vec::with_capacity(20);
    options.checksum = 0u16;

    tcp_header.extend_from_slice(&options.src_port.to_be_bytes());
    tcp_header.extend_from_slice(&options.dst_port.to_be_bytes());
    tcp_header.extend_from_slice(&options.seq.to_be_bytes());
    tcp_header.extend_from_slice(&options.ack.to_be_bytes());
    tcp_header.extend_from_slice(&options.offset_flags.to_be_bytes());
    tcp_header.extend_from_slice(&options.window.to_be_bytes());
    tcp_header.extend_from_slice(&options.checksum.to_be_bytes());
    tcp_header.extend_from_slice(&options.urgent.to_be_bytes());

    // Data for calculating the checksum. TCP cheksum covers:
    //  - Pseudo-header
    //  - TCP header
    //  - Payload
    let mut checksum_data =
        tcp_pseudo_header(&src_ip, &dst_ip, (tcp_header.len() + payload.len()) as u16);
    checksum_data.extend_from_slice(&tcp_header);
    checksum_data.extend_from_slice(payload);

    // Checksum occupies bytes 16 and 17 of the TCP header.
    tcp_header[16..18].copy_from_slice(&checksum(&checksum_data).to_be_bytes());

    tcp_header
}

/// Creates the IPv4 header.
///
/// ```
/// 0       4       8               16     19                      32
/// ├───────┼───────┼───────────────┼──────┴───────────────────────┤
/// │Version│IHL    │Type of Service│Total Length                  │
/// ├───────┴───────┴───────────────┼──────┬───────────────────────┤
/// │Identification                 │Flags │Fragment Offset        │
/// ├───────────────┬───────────────┼──────┴───────────────────────┤
/// │Time to Live   │Protocol       │Header Checksum               │
/// ├───────────────┴───────────────┴──────────────────────────────┤
/// │Source IP Address                                             │
/// ├──────────────────────────────────────────────────────────────┤
/// │Destination IP Address                                        │
/// ├──────────────────────────────────────────────────────────────┤
/// │Options                                                       │
/// └──────────────────────────────────────────────────────────────┘
/// ```
fn ip_header(fields: &IPOptions) -> Vec<u8> {
    let mut result = Vec::with_capacity(20);

    result.push(fields.version_ihl);
    result.push(fields.tos);
    result.extend_from_slice(&fields.ip_packet_total_len.to_be_bytes());
    result.extend_from_slice(&fields.identification.to_be_bytes());
    result.extend_from_slice(&fields.flags_fragment.to_be_bytes());
    result.push(fields.ttl);
    result.push(fields.protocol);
    // Calculating checksum over the temporary IP header.
    // IP checksum covers only the IP header.
    result.extend_from_slice(&checksum(&pseudo_ip_header(fields)).to_be_bytes());
    result.extend_from_slice(&fields.src_ip.octets());
    result.extend_from_slice(&fields.dst_ip.octets());

    result
}

/// Temporary IP header used to calculate the checksum.
fn pseudo_ip_header(fields: &IPOptions) -> Vec<u8> {
    let mut fields = fields.clone();
    // We initially put zero in the checksum field. Why?
    // Because we need to calculate the checksum based on the complete IP
    // header but we don't have the header before creating it. So we use this
    // pseudo header to calculate the checksum.
    fields.checksum = 0u16;

    let mut result = Vec::with_capacity(20);

    result.push(fields.version_ihl);
    result.push(fields.tos);
    result.extend_from_slice(&fields.ip_packet_total_len.to_be_bytes());
    result.extend_from_slice(&fields.identification.to_be_bytes());
    result.extend_from_slice(&fields.flags_fragment.to_be_bytes());
    result.push(fields.ttl);
    result.push(fields.protocol);
    result.extend_from_slice(&fields.checksum.to_be_bytes());
    result.extend_from_slice(&fields.src_ip.octets());
    result.extend_from_slice(&fields.dst_ip.octets());

    result
}

/// Creating the L2 ethernet header.
///
/// L2 frame format:
///
/// ```
/// 0                            16                             32
/// ├────────────────────────────┴──────────────────────────────┤
/// │ Destination MAC Address                                   │
/// ├────────────────────────────┬──────────────────────────────┤
/// │ ~Destination MAC Address   │ Source MAC Address           │
/// ├────────────────────────────┴──────────────────────────────┤
/// │ ~Source MAC Address                                       │
/// ├────────────────────────────┬──────────────────────────────┤
/// │ EtherType                  │ Payload                      │
/// ├────────────────────────────┴──────────────────────────────┤
/// │ ~Payload                                                  │
/// ├───────────────────────────────────────────────────────────┤
/// │ Frame Check Sequence (FCS)                                │
/// └───────────────────────────────────────────────────────────┘
/// ```
fn l2_header(options: &EthernetOptions) -> Vec<u8> {
    // Ethernet frame starts with:
    //   Destination MAC address = 6 bytes
    //   Source MAC address      = 6 bytes
    //   EtherType               = 2 bytes
    //
    // Total is: 14 bytes
    //
    let mut result = Vec::with_capacity(14);

    result.extend_from_slice(&options.dst_mac);
    result.extend_from_slice(&options.src_mac);
    result.extend_from_slice(&options.ether_type.to_be_bytes());

    result
}

/// Generates a BGP packet.
fn generate_bgp_packet(bgp_message: &[u8], options: &mut PacketOptions) -> Vec<u8> {
    // IPv4 packet total length includes:
    //  - IP header   = 20 bytes
    //  - TCP header  = 20 bytes
    //  - BGP payload =  N bytes
    //
    // Total: 20 + 20 + N = 40 + N bytes
    //
    let packet_total_len = 20 + 20 + bgp_message.len();
    options.ip.ip_packet_total_len = packet_total_len as u16;

    let mut packet = l2_header(&options.ethernet);
    packet.extend_from_slice(&ip_header(&options.ip));
    packet.extend_from_slice(&tcp_header(
        &mut options.tcp,
        options.ip.src_ip,
        &options.ip.dst_ip,
        bgp_message,
    ));
    packet.extend_from_slice(bgp_message);

    packet
}

/// Creates and saves a Wireshark compatible `.pcap` file.
///
/// PCap file structure:
///
/// ```
///	FILE
///	│
///	├── Global Header
///	│   ├── Magic number
///	│   ├── Version
///	│   ├── Snapshot Length
///	│   └── Link-layer Type
///	│
///	├── Packet Record Header
///	│   ├── Timestamp
///	│   ├── Captured Length
///	│   └── Original Length
///	│
///	└── Captured Packet
/// ```
fn write_pcap(packet: &[u8], filename: &PathBuf) {
    let mut f = File::create(filename).expect("Unable to create PCAP file");
    // Every classic PCAP file starts with a 24 bytes global header.
    //
    let mut global_header = Vec::with_capacity(24);
    // PCAP magic number to identify the file as a PCAP
    global_header.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes());
    // PCAP major version
    global_header.extend_from_slice(&2u16.to_le_bytes());
    // PCAP minor version
    global_header.extend_from_slice(&4u16.to_le_bytes());
    // Timezone correction
    global_header.extend_from_slice(&0u32.to_le_bytes());
    // Timestamp accuracy
    global_header.extend_from_slice(&0u32.to_le_bytes());
    // Maximum captured packet size
    global_header.extend_from_slice(&65535u32.to_le_bytes());
    // Link-layer type:  1 = Ethernet
    global_header.extend_from_slice(&1u32.to_le_bytes());

    f.write_all(&global_header)
        .expect("Unable to write PCAP global header");

    // We don't know the original timestamp so using zero for this packet.
    let timestamp_seconds = 0u32;
    // Microseconds portion of timestamp.
    let timestamp_microseconds = 0u32;

    // Every packet in a PCAP has a packet record header.
    //
    let packet_header = [
        timestamp_seconds.to_le_bytes(),
        timestamp_microseconds.to_le_bytes(),
        (packet.len() as u32).to_le_bytes(), // Number of bytes actually stored
        (packet.len() as u32).to_le_bytes(), // Original packet size
    ]
    .concat();

    f.write_all(&packet_header)
        .expect("Unable to write PCAP packet header");

    // Write the actual Ethernet frame. This contains:
    //  - Ethernet header
    //  - IPv4 header
    //  - TCP header
    //  - BGP message
    f.write_all(packet).expect("Unable to write Ethernet frame");
}

fn generate_pcap(bgp_hex: &str, mut options: PacketOptions) {
    let filename = env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("bgp_dump.pcap");

    let message = bgp_message(bgp_hex);
    let packet = generate_bgp_packet(&message, &mut options);

    write_pcap(&packet, &filename);

    println!();
    println!("{}", "=".repeat(60));
    println!("PCAP CREATED SUCCESSFULLY");
    println!("{}", "=".repeat(60));

    println!("Full path       : {}", filename.display());
    println!(
        "File size       : {} bytes",
        fs::metadata(&filename)
            .expect("Unable to read file metadata")
            .len()
    );
    // Size of the Ethernet packet we constructed.
    println!("Ethernet frame  : {} bytes", packet.len());
    // The original BGP payload size.
    println!("BGP payload     : {} bytes", message.len());
    // Byte 18 is the BGP message type.
    println!(
        "BGP message     : {} (type {})",
        bgp_message_type(message[18]),
        message[18]
    );
    // Bytes 16 and 17 are BGP Length field but we need to convert the two-byte
    // from hexadecimal bytes into an integer. E.g., 00 41 -> 65
    println!(
        "BGP length      : {} bytes",
        u16::from_be_bytes([message[16], message[17]])
    );

    println!("{}", "=".repeat(60));
}

// Default values for TCP Header fields.
impl Default for TCPOptions {
    fn default() -> Self {
        Self {
            // Making src the BGP server
            src_port: 179,
            // Synthetic ephemeral port for the client
            dst_port: 12345,
            // Synthetic sequence number
            seq: 1000,
            // Synthetic ack number
            ack: 2000,
            offset_flags: tcp_offset_flags(&[TCPFlag::PSH, TCPFlag::ACK], 5),
            // Max value of the 16 bis field.
            window: 65535,
            // We initially put zero into the checksum field, we'll calculate it later.
            checksum: 0u16,
            // Urgent pointer not being used.
            urgent: 0u16,
        }
    }
}

// Default values for IPv4 Header fields.
impl Default for IPOptions {
    fn default() -> Self {
        Self {
            // We don't know the real source and destination IPs from the Cisco
            // dump so we use some syntetic addresses.
            src_ip: Ipv4Addr::new(0, 0, 0, 0),
            dst_ip: Ipv4Addr::new(0, 0, 0, 0),
            // The length (IHL) is measured in 32-bit (4 bytes) words so 20
            // bytes is represented as 5. Because 20/4 = 5. Therefore:
            //
            //  IPv4 Version Field = 4 (4 bits)
            //  Internet Header Length Field = 5 (4 bits)
            //
            // These 2 values form 1 byte.
            version_ihl: 0x45,
            // We don't know the original value, normally it would be NC or CS6
            // but we use zero for now.
            tos: 0,
            ip_packet_total_len: 0,
            ttl: 64,
            // TCP protocol number
            protocol: 6,
            // Synthetic IP identification value
            identification: 0x1234,
            // IPv4 flags and fragment offset consume 2 bytes.
            // 0x4000 means: Don't Fragment (DF) and the offset is 0.
            flags_fragment: 0x4000,
            // We initially put zero into the checksum field.
            checksum: 0u16,
        }
    }
}

// Default values for Ethernet header.
impl Default for EthernetOptions {
    fn default() -> Self {
        Self {
            // We don't have the real MAC addresses because the Cisco MSGDUMP
            // only contains the BGP payload.
            dst_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            src_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
            // The EtherType for IPV4 is 0x0800
            ether_type: 0x0800,
        }
    }
}

fn main() {
    const PROGRAM_NAME: &str = "msgdmp-to-pcap";
    let args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() {
        println!(
            r#"Usage:
  {PROGRAM_NAME} $BGP_HEX

Example:
  {PROGRAM_NAME} "FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 0013 0400"
"#
        );
        std::process::exit(1);
    }

    generate_pcap(
        &args.join(""),
        // TODO: Accept custom packet fields passed as flags via CLI arguments.
        PacketOptions {
            tcp: TCPOptions::default(),
            ip: IPOptions::default(),
            ethernet: EthernetOptions::default(),
        },
    );
}
