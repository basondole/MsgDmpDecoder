/*
 * Utility for parsing Cisco BGP MSGDUMP logs and transforming them into
 * standard Wireshark PCAP.
 *
 * Example:
 *   ❯ # Needs compiling before running
 *   ❯ cc -std=c11 -Wall -Wextra -O2 msgdmp-to-pcap.c -o msgdmp-to-pcap
 *   ❯ ./msgdmp-to-pcap "FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF
 *    0041 0104 5BA0 00B4 0303 0303 2402 0601
 *    0400 0100 8002 0601 0400 0100 0102 0280
 *    0002 0202 0002 0246 0002 0641 0400 068D
 *    B8"
 *
 *   ============================================================
 *   PCAP CREATED SUCCESSFULLY
 *   ============================================================
 *   Full path       : /home/foo/bgp_dump.pcap
 *   File size       : 159 bytes
 *   Ethernet frame  : 119 bytes
 *   BGP payload     : 65 bytes
 *   BGP message     : OPEN (type 1)
 *   BGP length      : 65 bytes
 *   ============================================================
 */

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <io.h>
#define close _close
#else
#include <unistd.h>
#endif

typedef struct {
  uint8_t type;
  const char *name;
} MessageType;

static const MessageType MESSAGE_TYPES[] = {
    {1, "OPEN"},      {2, "UPDATE"},        {3, "NOTIFICATION"},
    {4, "KEEPALIVE"}, {5, "ROUTE-REFRESH"},
};

#define MESSAGE_TYPE_COUNT (sizeof(MESSAGE_TYPES) / sizeof(MESSAGE_TYPES[0]))

static const char *bgp_message_type(uint8_t msg_type) {
  size_t i;

  for (i = 0; i < MESSAGE_TYPE_COUNT; i++) {
    if (MESSAGE_TYPES[i].type == msg_type)
      return MESSAGE_TYPES[i].name;
  }

  return "UNKNOWN";
}

// TCP Flags
typedef enum {
  TCP_FIN = 1,
  TCP_SYN = 2,
  TCP_RST = 4,
  TCP_PSH = 8,
  TCP_ACK = 16,
  TCP_URG = 32,
  TCP_ECE = 64,
  TCP_CWR = 128
} TCPFlag;

// TCP Header fields
typedef struct {
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t seq;
  uint32_t ack;
  uint16_t offset_flags;
  uint16_t window;
  uint16_t checksum;
  uint16_t urgent;
} TCPOptions;

// IPv4 Header fields
typedef struct {
  uint8_t version_ihl;
  uint8_t tos;
  uint16_t ip_packet_total_len;
  uint16_t identification;
  uint16_t flags_fragment;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum;
  struct in_addr src_ip;
  struct in_addr dst_ip;
} IPOptions;

// Ethernet Header fields
typedef struct {
  uint8_t dst_mac[6];
  uint8_t src_mac[6];
  uint16_t ether_type;
} EthernetOptions;

typedef struct {
  IPOptions ip;
  TCPOptions tcp;
  EthernetOptions ethernet;
} PacketOptions;

/*
 * Converts a single hexadecimal character to its numeric value.
 *
 * Examples:
 *
 *     '0' -> 0
 *     '9' -> 9
 *     'A' -> 10
 *     'F' -> 15
 */
static int hex_value(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';

  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;

  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;

  return -1;
}

/*
 * Gets a big-endian 16-bit integer from a byte buffer.
 */
static uint16_t get_be16(const uint8_t *data) {
  return ((uint16_t)data[0] << 8) | (uint16_t)data[1];
}

/*
 * Inserts a 16-bit integer in big-endian order into a byte buffer.
 */
static void put_u16_be(uint8_t *p, uint16_t value) {
  p[0] = (uint8_t)(value >> 8);
  p[1] = (uint8_t)(value);
}

/*
 * Inserts a 32-bit integer in big-endian order into a byte buffer.
 */
static void put_u32_be(uint8_t *p, uint32_t value) {
  p[0] = (uint8_t)(value >> 24);
  p[1] = (uint8_t)(value >> 16);
  p[2] = (uint8_t)(value >> 8);
  p[3] = (uint8_t)(value);
}

/*
 * Inserts a 16-bit integer in little-endian order into a byte buffer.
 *
 * PCAP headers are written little-endian.
 */
static void put_u16_le(uint8_t *p, uint16_t value) {
  p[0] = (uint8_t)(value);
  p[1] = (uint8_t)(value >> 8);
}

/*
 * Inserts a 32-bit integer in little-endian order into a byte buffer.
 */
static void put_u32_le(uint8_t *p, uint32_t value) {
  p[0] = (uint8_t)(value);
  p[1] = (uint8_t)(value >> 8);
  p[2] = (uint8_t)(value >> 16);
  p[3] = (uint8_t)(value >> 24);
}

/**
 * Calculates the Internet checksum based on RFC1071.
 *
 * The checksum is needed for the BGP IP and TCP headers.
 *
 * The checksum operates on 16-bit words (2 bytes), so an odd-length
 * buffer is padded with one zero byte.
 */
static uint16_t checksum(const uint8_t *data, size_t length) {
  uint32_t total = 0;
  size_t i;

  // Each iteration processes one 16-bit word, i.e. 2 bytes.
  for (i = 0; i + 1 < length; i += 2) {
    /*
     * Converting two 8-bit bytes into one 16-bit number.
     * Example: 0x12 0x34 -> becomes: 0x1234
     */
    uint16_t word = ((uint16_t)data[i] << 8) | (uint16_t)data[i + 1];
    total += word;
    /*
     * Internet checksum works on 16-bit words but when you add two 16-bit
     * numbers the result can overflow to 17 bits.
     * End-around carry to fold the result back into 16 bits.
     */
    total = (total & 0xffff) + (total >> 16);
  }

  /*
   * Bitwise & to check the last bit is 1 which means odd value of the legth.
   * If the buffer contains an odd number of bytes, pad the final
   * byte with zero in the least-significant position.
   */
  if (length & 1) {
    uint16_t word = (uint16_t)(data[length - 1] << 8);
    total += word;
    total = (total & 0xffff) + (total >> 16);
  }

  // The final step is the one's complement of the accumulated value.
  return (uint16_t)~total;
}

/**
 * Generates BGP message from a hex string.
 *
 * @param bgp_hex Null-terminated hexadecimal input. Hexadecimal digits
 *                must be contiguous in pairs.
 *
 * BGP message general format:
 *
 *     0                          16            24           32
 *     ├──────────────────────────┴─────────────┴────────────┤
 *     │ Marker                                              │
 *     ├─────────────────────────────────────────────────────┤
 *     │ Marker                                              │
 *     ├─────────────────────────────────────────────────────┤
 *     │ Marker                                              │
 *     ├─────────────────────────────────────────────────────┤
 *     │ Marker                                              │
 *     ├──────────────────────────┬─────────────┬────────────┤
 *     │ Length                   │ Type        │ Message    │
 *     ├──────────────────────────┴─────────────┴────────────┤
 *     │ ~Message                                            │
 *     └─────────────────────────────────────────────────────┘
 */
static uint8_t *bgp_message(const char *bgp_hex, size_t *message_length) {
  size_t hex_length = 0;

  // Ignore non-whitespace characters.
  for (const char *p = bgp_hex; *p; p++) {
    if (!isspace((unsigned char)*p))
      hex_length++;
  }

  if (hex_length % 2 != 0) {
    fprintf(stderr, "Error: Hex string must contain an even number "
                    "of characters\n");
    return NULL;
  }

  // Every two hexadecimal characters represent one byte.
  size_t msg_length = hex_length / 2;
  uint8_t *message = malloc(msg_length);

  if (message == NULL) {
    perror("malloc");
    return NULL;
  }

  // Convert the hexadecimal string into bytes.
  {
    size_t hex_pos = 0;
    size_t byte_pos = 0;
    // Not end of string
    while (bgp_hex[hex_pos] != '\0') {
      int first_hex;
      int second_hex;

      if (isspace((unsigned char)bgp_hex[hex_pos])) {
        hex_pos++;
        continue;
      }

      first_hex = hex_value(bgp_hex[hex_pos]);
      second_hex = hex_value(bgp_hex[hex_pos + 1]);
      if (first_hex < 0 || second_hex < 0) {
        fprintf(stderr, "Error: Invalid hexadecimal byte\n");
        free(message);
        return NULL;
      }

      message[byte_pos++] = (uint8_t)((first_hex << 4) | second_hex);

      hex_pos += 2;
    }
  }

  /*
   * A BGP message has:
   *
   *   Marker : 16 bytes
   *   Length : 2 bytes
   *   Type   : 1 byte
   *
   * Therefore the minimum BGP message size is 19 bytes.
   */
  if (msg_length < 19) {
    fprintf(stderr, "Error: BGP message is too short: %zu bytes\n", msg_length);
    free(message);
    return NULL;
  }

  // The first 16 bytes of a BGP message are the marker should be all 0xff.
  for (size_t i = 0; i < 16; i++) {
    if (message[i] != 0xff) {
      fprintf(stderr, "Error: Invalid BGP marker\n");
      free(message);
      return NULL;
    }
  }

  // Bytes 16 and 17 contain the BGP Length field.
  {
    uint16_t declared_length = ((uint16_t)message[16] << 8) | message[17];
    if (msg_length != declared_length) {
      fprintf(stderr,
              "Error: Unexpected BGP payload length: %zu "
              "(BGP header declares %u)\n",
              msg_length, declared_length);
      free(message);
      return NULL;
    }
  }

  // Byte 18 is the message type,
  {
    uint8_t message_type = message[18];
    int known = 0;

    for (size_t i = 0; i < MESSAGE_TYPE_COUNT; i++) {
      if (MESSAGE_TYPES[i].type == message_type) {
        known = 1;
        break;
      }
    }
    if (!known) {
      fprintf(stderr, "Error: Unknown BGP message type: %u\n", message_type);
      free(message);
      return NULL;
    }
  }

  *message_length = msg_length;
  return message;
}

/**
 * Builds the 16-bit TCP Data Offset/Reserved/Flags field.
 *
 *     ┌─────────────┬──────────┬────────────────┐
 *     │ Data Offset │ Reserved │     Flags      │
 *     │   4 bits    │  4 bits  │     8 bits     │
 *     └─────────────┴──────────┴────────────────┘
 *
 * @param data_offset TCP header length measured in 32-bit words. Therefore for
 *                    a 20-byte TCP header with no options the offset is 5.
 *                    Because `20 / 4 = 5`
 *
 */
static uint16_t tcp_offset_flags(uint8_t flags, uint8_t data_offset) {
  /*
   * The data offset is shifted into the upper four bits and
   * combined with the TCP flags.
   */
  return ((uint16_t)data_offset << 12) | (uint16_t)flags;
}

/*
 * Creates a TCP pseudo header.
 *
 * A TCP pseudo-header is temporary information used only when calculating
 * the TCP checksum.
 *
 * TCP pseudo-header format:
 *
 *     0              8               16                       32
 *     ├──────────────┴───────────────┴────────────────────────┤
 *     │ Source IP address                                     │
 *     ├───────────────────────────────────────────────────────┤
 *     │ Destination IP address                                │
 *     ├──────────────┬───────────────┬────────────────────────┤
 *     │ Reserved     │ Protocol      │ TCP length             │
 *     └──────────────┴───────────────┴────────────────────────┘
 *
 * Total size = 12 bytes.
 */
static void tcp_pseudo_header(uint8_t *result, const struct in_addr *src_ip,
                              const struct in_addr *dst_ip,
                              uint16_t tcp_length) {

  memcpy(result, &src_ip->s_addr, 4);
  memcpy(result + 4, &dst_ip->s_addr, 4);

  result[8] = 0; // Reserved = 0.
  result[9] = 6; // Protocol = TCP (6).
  put_u16_be(&result[10], tcp_length);
}

#define TCP_HEADER_LENGTH 20
/*
 * Creates the TCP header.
 *
 * TCP header format:
 *
 *     0       4        8             16                            32
 *     ├───────┴────────┴─────────────┼─────────────────────────────┤
 *     │ Source Port                  │ Destination Port            │
 *     ├──────────────────────────────┴─────────────────────────────┤
 *     │ Sequence Number                                            │
 *     ├────────────────────────────────────────────────────────────┤
 *     │ Acknowledgment Number                                      │
 *     ├───────┬────────┬─────────────┬─────────────────────────────┤
 *     │Data   │Reserved│ Flags       │ Window Size                 │
 *     │Offset │        │             │                             │
 *     ├───────┴────────┴─────────────┼─────────────────────────────┤
 *     │ Checksum                     │ Urgent Pointer              │
 *     ├──────────────────────────────┴─────────────────────────────┤
 *     │Options                                                     │
 *     └────────────────────────────────────────────────────────────┘
 *
 * This implementation uses a 20-byte TCP header with no options.
 */
static void tcp_header(uint8_t *tcp_header, TCPOptions *options,
                       const struct in_addr *src_ip,
                       const struct in_addr *dst_ip, const uint8_t *payload,
                       size_t payload_length) {

  uint8_t pseudo_header[12]; // 12 bytes
  uint8_t *checksum_data;
  size_t checksum_data_length;
  // uint16_t tcp_length;
  uint16_t tcp_checksum;

  options->checksum = 0;
  put_u16_be(&tcp_header[0], options->src_port);
  put_u16_be(&tcp_header[2], options->dst_port);
  put_u32_be(&tcp_header[4], options->seq);
  put_u32_be(&tcp_header[8], options->ack);
  put_u16_be(&tcp_header[12], options->offset_flags);
  put_u16_be(&tcp_header[14], options->window);
  put_u16_be(&tcp_header[16], options->checksum);
  put_u16_be(&tcp_header[18], options->urgent);

  tcp_pseudo_header(pseudo_header, src_ip, dst_ip,
                    (TCP_HEADER_LENGTH + payload_length));

  checksum_data_length =
      sizeof(pseudo_header) + TCP_HEADER_LENGTH + payload_length;

  checksum_data = malloc(checksum_data_length);
  if (checksum_data == NULL) {
    perror("malloc");
    exit(EXIT_FAILURE);
  }
  /*
   * TCP checksum covers:
   *   - Pseudo-header
   *   - TCP header
   *   - Payload
   */
  memcpy(&checksum_data[0], pseudo_header, sizeof(pseudo_header));
  memcpy(&checksum_data[sizeof(pseudo_header)], tcp_header, TCP_HEADER_LENGTH);
  memcpy(&checksum_data[sizeof(pseudo_header) + TCP_HEADER_LENGTH], payload,
         payload_length);

  tcp_checksum = checksum(checksum_data, checksum_data_length);
  free(checksum_data);

  // Checksum occupies bytes 16 and 17 of the TCP header.
  put_u16_be(&tcp_header[16], tcp_checksum);
}

#define IPV4_HEADER_LENGTH 20
/*
 * Creates the IPv4 header.
 *
 * IPv4 header format:
 *
 *     0       4       8               16     19                      32
 *     ├───────┼───────┼───────────────┼──────┴───────────────────────┤
 *     │Version│IHL    │Type of Service│ Total Length                 │
 *     ├───────┴───────┴───────────────┼──────┬───────────────────────┤
 *     │Identification                 │Flags │Fragment Offset        │
 *     ├───────────────┬───────────────┼──────┴───────────────────────┤
 *     │Time to Live   │ Protocol      │ Header Checksum              │
 *     ├───────────────┴───────────────┴──────────────────────────────┤
 *     │Source IP Address                                             │
 *     ├──────────────────────────────────────────────────────────────┤
 *     │Destination IP Address                                        │
 *     ├──────────────────────────────────────────────────────────────┤
 *     │Options                                                       │
 *     └──────────────────────────────────────────────────────────────┘
 *
 * This implementation uses a 20-byte IP header with no options.
 */
static void ip_header(uint8_t *result, const IPOptions *fields) {
  uint8_t ip_header[20];
  uint16_t ip_checksum;

  ip_header[0] = fields->version_ihl;
  ip_header[1] = fields->tos;
  put_u16_be(&ip_header[2], fields->ip_packet_total_len);
  put_u16_be(&ip_header[4], fields->identification);
  put_u16_be(&ip_header[6], fields->flags_fragment);
  ip_header[8] = fields->ttl;
  ip_header[9] = fields->protocol;
  // Checksum field is zero while calculating the checksum.
  put_u16_be(&ip_header[10], 0);
  put_u32_be(&ip_header[12], fields->src_ip.s_addr);
  put_u32_be(&ip_header[16], fields->dst_ip.s_addr);
  /*
   * Calculating the IPv4 header checksum and backfilling it.
   * The IPv4 checksum covers only the IPv4 header.
   */
  ip_checksum = checksum(ip_header, IPV4_HEADER_LENGTH);
  put_u16_be(&ip_header[10], ip_checksum);

  memcpy(result, ip_header, IPV4_HEADER_LENGTH);
}

#define ETHERNET_HEADER_LENGTH 14
/*
 * Creates the Ethernet header.
 *
 * Ethernet frame starts with:
 *
 *     Destination MAC address = 6 bytes
 *     Source MAC address      = 6 bytes
 *     EtherType               = 2 bytes
 *
 * Total = 14 bytes.
 */
static void ethernet_header(uint8_t *result, const EthernetOptions *options) {
  memcpy(&result[0], options->dst_mac, 6);
  memcpy(&result[6], options->src_mac, 6);
  put_u16_be(&result[12], options->ether_type);
}

/*
 * Generates a BGP packet.
 *
 * Packet layout:
 *
 *     Ethernet header = 14 bytes
 *     IPv4 header     = 20 bytes
 *     TCP header      = 20 bytes
 *     BGP payload     = N bytes
 *
 * Therefore:
 *
 *     Ethernet frame = 54 + N bytes
 *     IP packet      = 40 + N bytes
 */
static uint8_t *generate_bgp_packet(const uint8_t *bgp_message,
                                    size_t bgp_message_length,
                                    PacketOptions *options,
                                    size_t *packet_length) {
  uint8_t *packet;
  uint8_t ip_header_data[IPV4_HEADER_LENGTH];
  uint8_t tcp_header_data[TCP_HEADER_LENGTH];

  /*
   * IPv4 packet total length includes:
   *
   *   IP header   = 20 bytes
   *   TCP header  = 20 bytes
   *   BGP payload = N bytes
   *
   * Total = 40 + N bytes.
   */
  size_t ip_packet_length =
      IPV4_HEADER_LENGTH + TCP_HEADER_LENGTH + bgp_message_length;
  options->ip.ip_packet_total_len = (uint16_t)ip_packet_length;

  // Full length Ethernet frame.
  *packet_length = ETHERNET_HEADER_LENGTH + ip_packet_length;
  packet = malloc(*packet_length);
  if (packet == NULL) {
    perror("malloc");
    return NULL;
  }

  ethernet_header(packet, &options->ethernet);
  ip_header(ip_header_data, &options->ip);
  tcp_header(tcp_header_data, &options->tcp, &options->ip.dst_ip,
             &options->ip.src_ip, bgp_message, bgp_message_length);

  memcpy(&packet[ETHERNET_HEADER_LENGTH], ip_header_data, IPV4_HEADER_LENGTH);
  memcpy(&packet[ETHERNET_HEADER_LENGTH + IPV4_HEADER_LENGTH], tcp_header_data,
         TCP_HEADER_LENGTH);
  memcpy(
      &packet[ETHERNET_HEADER_LENGTH + IPV4_HEADER_LENGTH + TCP_HEADER_LENGTH],
      bgp_message, bgp_message_length);

  return packet;
}

#define FILE_METADATA_LENGTH 24
#define PRECORD_METADATA_LENGTH 16
/*
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
static int write_pcap(const uint8_t *packet, size_t packet_length,
                      const char *filename) {
  FILE *f;
  uint8_t global_header[FILE_METADATA_LENGTH];

  f = fopen(filename, "wb");

  if (f == NULL) {
    fprintf(stderr, "Unable to create PCAP file '%s': %s\n", filename,
            strerror(errno));
    return -1;
  }
  // Every classic PCAP file starts with a 24-byte global header.
  //
  // PCAP magic number to identify the file as a PCAP
  put_u32_le(&global_header[0], 0xA1B2C3D4);
  // PCAP major version.
  put_u16_le(&global_header[4], 2);
  // PCAP minor version.
  put_u16_le(&global_header[6], 4);
  // Timezone correction.
  put_u32_le(&global_header[8], 0);
  // Timestamp accuracy.
  put_u32_le(&global_header[12], 0);
  // Maximum captured packet size.
  put_u32_le(&global_header[16], 65535);
  // Link-layer type:  1 = Ethernet
  put_u32_le(&global_header[20], 1);

  if (fwrite(global_header, 1, FILE_METADATA_LENGTH, f) !=
      FILE_METADATA_LENGTH) {
    fprintf(stderr, "Unable to write PCAP global header\n");
    fclose(f);
    return -1;
  }

  // Every packet in a PCAP has a 16-bit packet record header.
  //
  uint8_t packet_header[PRECORD_METADATA_LENGTH];
  // We don't know the original timestamp, so use zero.
  put_u32_le(&packet_header[0], 0);
  // Microseconds portion of timestamp.
  put_u32_le(&packet_header[4], 0);
  put_u32_le(&packet_header[8], (uint32_t)packet_length);
  put_u32_le(&packet_header[12], (uint32_t)packet_length);

  if (fwrite(packet_header, 1, PRECORD_METADATA_LENGTH, f) !=
      PRECORD_METADATA_LENGTH) {
    fprintf(stderr, "Unable to write PCAP packet header\n");
    fclose(f);
    return -1;
  }

  /*
   * Write the actual Ethernet frame.
   *
   * This contains:
   *
   *   - Ethernet header
   *   - IPv4 header
   *   - TCP header
   *   - BGP message
   */
  if (fwrite(packet, 1, packet_length, f) != packet_length) {
    fprintf(stderr, "Unable to write Ethernet frame\n");
    fclose(f);
    return -1;
  }

  fclose(f);

  return 0;
}

/*
 * Sets default packet options
 */
static void default_packet_options(PacketOptions *options) {
  // TCP
  options->tcp.src_port = 179;
  options->tcp.dst_port = 12345;
  options->tcp.seq = 1000;
  options->tcp.ack = 2000;
  options->tcp.offset_flags = tcp_offset_flags(TCP_PSH | TCP_ACK, 5);
  options->tcp.window = 65535;
  options->tcp.checksum = 0;
  options->tcp.urgent = 0;

  // IP
  options->ip.src_ip.s_addr = htonl(0x00000000);
  options->ip.dst_ip.s_addr = htonl(0x00000000);
  options->ip.version_ihl = 0x45;
  options->ip.tos = 0;
  options->ip.ip_packet_total_len = 0;
  options->ip.identification = 0x1234;
  options->ip.flags_fragment = 0x4000;
  options->ip.ttl = 64;
  options->ip.protocol = 6;
  options->ip.checksum = 0;

  // Ethernet
  {
    const uint8_t dst_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    const uint8_t src_mac[6] = {0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};

    memcpy(options->ethernet.dst_mac, dst_mac, 6);
    memcpy(options->ethernet.src_mac, src_mac, 6);
  }
  options->ethernet.ether_type = 0x0800;
}

static int generate_pcap(const char *bgp_hex,
                         const PacketOptions *default_options) {
  char filename[4096];
  const char *home;
  uint8_t *message;
  uint8_t *packet;
  size_t message_length;
  size_t packet_length;
  PacketOptions options;
  struct stat file_stat;

  /*
   * Making a copy because generate_bgp_packet modifies the IP
   * packet length and TCP checksum.
   */
  options = *default_options;

  /*
   * Writes to:
   *
   *     $HOME/bgp_dump.pcap
   *
   * If HOME isn't set, it writes to:
   *
   *     ./bgp_dump.pcap
   */
  home = getenv("HOME");

  if (home != NULL) {
    snprintf(filename, sizeof(filename), "%s/bgp_dump.pcap", home);
  } else {
    snprintf(filename, sizeof(filename), "./bgp_dump.pcap");
  }

  message = bgp_message(bgp_hex, &message_length);

  if (message == NULL)
    return EXIT_FAILURE;

  packet =
      generate_bgp_packet(message, message_length, &options, &packet_length);

  if (packet == NULL) {
    free(message);
    return EXIT_FAILURE;
  }

  if (write_pcap(packet, packet_length, filename) != 0) {
    free(packet);
    free(message);
    return EXIT_FAILURE;
  }

  /*
   * Read the resulting file size.
   */
  if (stat(filename, &file_stat) != 0) {
    fprintf(stderr, "Unable to read file metadata: %s\n", strerror(errno));

    free(packet);
    free(message);

    return EXIT_FAILURE;
  }

  printf("\n");
  printf("============================================================\n");
  printf("PCAP CREATED SUCCESSFULLY\n");
  printf("============================================================\n");

  printf("Full path       : %s\n", filename);
  printf("File size       : %lld bytes\n", (long long)file_stat.st_size);
  printf("Ethernet frame  : %zu bytes\n", packet_length);
  printf("BGP payload     : %zu bytes\n", message_length);
  printf("BGP message     : %s (type %u)\n", bgp_message_type(message[18]),
         message[18]);

  printf("BGP length      : %u bytes\n", get_be16(&message[16]));

  printf("============================================================\n");
  free(packet);
  free(message);

  return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
  const char *program_name = "msgdmp-to-pcap";

  if (argc < 2) {
    printf("Usage:\n"
           "  %s $BGP_HEX\n"
           "\n"
           "Example:\n"
           "  %s \"FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF "
           "FFFF FFFF FFFF FFFF 0013 0400\"\n",
           program_name, program_name);

    return EXIT_FAILURE;
  }

  {
    size_t total_length = 0;
    size_t i;
    char *bgp_hex;
    size_t position = 0;

    for (i = 1; i < (size_t)argc; i++)
      total_length += strlen(argv[i]);

    bgp_hex = malloc(total_length + 1);

    if (bgp_hex == NULL) {
      perror("malloc");
      return EXIT_FAILURE;
    }

    // Build one continuous hexadecimal string from all command-line arguments.
    for (i = 1; i < (size_t)argc; i++) {
      size_t length = strlen(argv[i]);
      memcpy(bgp_hex + position, argv[i], length);
      position += length;
    }
    // Put the null character at the end, '\0' is the  string terminator.
    bgp_hex[position] = '\0';

    PacketOptions options;
    default_packet_options(&options);

    {
      int result = generate_pcap(bgp_hex, &options);
      free(bgp_hex);

      return result;
    }
  }
}
