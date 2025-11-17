# 🌐 NetForge - Custom TCP/IP Protocol Stack

**Developed by Yx0R**

![NetForge Banner](https://img.shields.io/badge/NetForge-TCP%2FIP%20Stack-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey)

## 🎯 Overview

**NetForge** is a complete, from-scratch implementation of the TCP/IP protocol stack that creates **real network packets** detectable by professional tools like Wireshark. Unlike theoretical implementations, NetForge sends actual Ethernet frames over the network interface, providing hands-on understanding of networking fundamentals.

### 🌟 Key Features
- ✅ **Real Packet Generation** - Not simulations, actual network traffic
- ✅ **Wireshark Compatible** - Professional network analysis
- ✅ **Four-Layer Implementation** - Complete TCP/IP model
- ✅ **Multiple Protocols** - ICMP, TCP, UDP, HTTP, Raw Ethernet
- ✅ **Educational Focus** - Clear code with extensive documentation
- ✅ **From Scratch** - No high-level networking libraries

---

## 📖 The Journey: From Concept to Implementation

### 🧠 The Vision

The project began with a simple question: **"How does internet communication REALLY work at the packet level?"** Most educational projects stop at simulation, but we wanted to create something that interacts with the actual network hardware.

### 🏗️ Architectural Philosophy

We followed the **4-layer TCP/IP model** but with a practical twist:

```
📱 Application Layer  → User data and high-level protocols
🚚 Transport Layer   → End-to-end communication (TCP/UDP)  
🌍 Internet Layer    → Logical addressing and routing (IP)
🔗 Link Layer       → Physical network interface (Ethernet)
```

### 🔄 Development Evolution

1. **Phase 1: Understanding** - Studied RFCs and protocol specifications
2. **Phase 2: Python Simulation** - Built educational models to understand flow
3. **Phase 3: C Implementation** - Created raw socket-based real implementation
4. **Phase 4: Polish** - Added robust error handling and beautiful UI

---

## 🏗️ Technical Architecture

### 📁 Project Structure
```
netforge/
├── src/
│   ├── main.c              # Application entry point & CLI
│   ├── protocols.h         # Common headers and declarations
│   ├── ipv4.c             # Internet Layer - IPv4 implementation
│   ├── icmp.c             # Transport Layer - ICMP (ping)
│   ├── tcp.c              # Transport Layer - TCP protocol
│   ├── udp.c              # Transport Layer - UDP protocol
│   └── ethernet.c         # Link Layer - Ethernet helpers
├── Makefile               # Build system
└── README.md              # This documentation
```

### 🔧 Core Components

#### **1. Raw Socket Management (`main.c`)**
```c
// Creates low-level socket for direct packet injection
int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
```
- **Purpose**: Bypass kernel network stack for direct packet access
- **Challenge**: Requires root privileges and interface binding
- **Solution**: Uses `struct sockaddr_ll` for interface-specific sending

#### **2. Ethernet Layer (`ethernet.c`)**
```c
struct ethhdr {
    unsigned char h_dest[6];   // Destination MAC
    unsigned char h_source[6]; // Source MAC  
    unsigned short h_proto;    // EtherType
};
```
- **Responsibility**: Frame assembly and MAC addressing
- **Key Feature**: Constructs complete Ethernet II frames
- **Protocol Support**: IPv4 (0x0800), IPv6, ARP, and custom types

#### **3. Internet Layer (`ipv4.c`)**
```c
struct iphdr {
    uint8_t  version:4, ihl:4; // Version + Header Length
    uint8_t  tos;              // Type of Service
    uint16_t tot_len;          // Total Length
    uint16_t id;               // Identification
    // ... RFC 791 compliant fields
};
```
- **Implementation**: Full IPv4 header according to RFC 791
- **Features**: TTL, checksum calculation, protocol multiplexing
- **Checksum**: Custom implementation for header validation

#### **4. Transport Layer (`tcp.c`, `udp.c`, `icmp.c`)**
**TCP Features:**
- SYN, ACK, FIN, RST flag support
- Sequence number management
- Port-based multiplexing

**UDP Features:**
- Connectionless datagrams
- Lightweight header
- Checksum optional for IPv4

**ICMP Features:**
- Echo Request/Reply (ping)
- Identifier and sequence tracking
- Custom payload support

#### **5. Application Layer (`main.c` HTTP implementation)**
- HTTP/1.1 GET request generation
- Standard header fields
- Connection management

---

## 🔄 Complete Data Flow

### 📤 Packet Transmission Path

```
User Command: "./netforge eth0 ping 8.8.8.8"
    ↓
📱 APPLICATION LAYER
    ↓ Creates: "Ping to 8.8.8.8"
    ↓
🚚 TRANSPORT LAYER (ICMP)
    ↓ Adds: [ICMP Header] + Payload
    ↓
🌍 INTERNET LAYER (IPv4)  
    ↓ Adds: [IP Header] + [ICMP Packet]
    ↓
🔗 LINK LAYER (Ethernet)
    ↓ Adds: [Ethernet Header] + [IP Packet]
    ↓
📡 NETWORK INTERFACE
    ↓ Converts to electrical signals
    ↓
🌐 NETWORK CABLE/AIR
    ↓ Travels as physical signals
    ↓
📊 WIRESHARK
    ↓ Captures and decodes real packets!
```

### 🔍 Protocol Encapsulation

```
[ Ethernet Header ][ IP Header ][ TCP/UDP/ICMP Header ][ Payload ]
      14 bytes         20 bytes         var bytes       var bytes
      ↓               ↓               ↓               ↓
    MAC addresses  IP addresses    Ports/Flags    User data
    (Layer 2)      (Layer 3)      (Layer 4)      (Layer 5-7)
```

### 🎯 Real Packet Example (ICMP Ping)

```
ETHERNET FRAME:
  Destination: ff:ff:ff:ff:ff:ff (Broadcast)
  Source:      00:11:22:33:44:55 (Your MAC)
  Type:        0x0800 (IPv4)

IP PACKET:
  Version:     4
  Header Len:  20 bytes
  TTL:         64
  Protocol:    1 (ICMP)
  Source:      192.168.1.100
  Destination: 8.8.8.8

ICMP MESSAGE:
  Type:        8 (Echo Request)
  Code:        0
  Checksum:    [calculated]
  Data:        56 bytes of payload
```

---

## 🚀 Installation & Setup

### Prerequisites
- Linux operating system
- GCC compiler
- Root access (for raw sockets)
- Wireshark (for packet analysis)

### Quick Start
```bash
# 1. Clone and build
git clone <repository>
cd netforge
make

# 2. Enable raw socket capabilities
sudo setcap cap_net_raw+ep netforge

# 3. Find your network interface
ip link show

# 4. Start packet capture
sudo wireshark

# 5. Send test packets
./netforge eth0 ping 8.8.8.8
```

### Advanced Installation
```bash
# System-wide installation
make install

# Debug build
make debug

# Clean build
make clean
```

---

## 💻 Usage Guide

### Basic Commands
```bash
# Network discovery
./netforge eth0 info

# ICMP Ping (Layer 3)
./netforge eth0 ping 8.8.8.8

# TCP Connection Initiation (Layer 4)
./netforge eth0 tcp 192.168.1.1 80

# UDP Datagram (Layer 4)
./netforge eth0 udp 192.168.1.1 53

# HTTP Request (Layer 5-7)
./netforge eth0 http 192.168.1.1

# Raw Ethernet Frame (Layer 2)
./netforge eth0 raw

# Comprehensive Test
./netforge eth0 all 192.168.1.1
```

### Protocol-Specific Examples

#### 🔍 ICMP Ping
```bash
./netforge eth0 ping 8.8.8.8
```
**Creates:**
- Ethernet frame with broadcast MAC
- IP packet with TTL=64
- ICMP Echo Request with sequence number
- Visible in Wireshark as standard ping

#### 🔗 TCP SYN
```bash
./netforge eth0 tcp 192.168.1.1 443
```
**Creates:**
- TCP segment with SYN flag set
- Random source port + specified destination port
- Sequence number based on current time
- Initiates three-way handshake

#### 📦 UDP Datagram
```bash
./netforge eth0 udp 192.168.1.1 53
```
**Creates:**
- Connectionless UDP datagram
- Contains "Hello from NetForge" payload
- Common for DNS, DHCP, VoIP protocols

#### 🌐 HTTP GET
```bash
./netforge eth0 http 192.168.1.1
```
**Creates:**
- TCP segment with PSH+ACK flags
- Complete HTTP/1.1 GET request
- Standard headers (Host, User-Agent, Connection)

---

## 🔬 Technical Deep Dive

### 🎯 Raw Socket Programming

**Challenge:** Traditional sockets abstract away network details
**Solution:** Linux raw sockets provide direct packet access

```c
// Key system calls:
socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))  // Raw packet socket
ioctl(sock, SIOCGIFINDEX, &ifr)                // Get interface index  
ioctl(sock, SIOCGIFHWADDR, &ifr)               // Get MAC address
sendto(sock, packet, length, 0, &addr, sizeof(addr))  // Send raw packet
```

### 📊 Header Construction

#### Ethernet Frame Structure
```c
struct ethhdr {
    unsigned char  h_dest[ETH_ALEN];   // Destination MAC (6 bytes)
    unsigned char  h_source[ETH_ALEN]; // Source MAC (6 bytes)
    unsigned short h_proto;            // Protocol type (2 bytes)
};
```

#### IP Packet Structure
```c
struct iphdr {
    unsigned char  ihl:4, version:4;   // Version + Header Length
    unsigned char  tos;                // Type of Service
    unsigned short tot_len;            // Total Length
    unsigned short id;                 // Identification
    unsigned short frag_off;           // Fragment Offset
    unsigned char  ttl;                // Time to Live
    unsigned char  protocol;           // Protocol (TCP=6, UDP=17, ICMP=1)
    unsigned short check;              // Header Checksum
    unsigned int   saddr;              // Source Address
    unsigned int   daddr;              // Destination Address
};
```

### 🧮 Checksum Calculation

**Purpose:** Ensure data integrity across network hops
**Algorithm:** One's complement of one's complement sum

```c
unsigned short calculate_checksum(unsigned short *ptr, int nbytes) {
    register long sum;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    // Handle odd byte if necessary
    if (nbytes == 1) {
        // Special handling for last byte
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}
```

---

## 🎯 Educational Value

### 🎓 Learning Outcomes

**After studying NetForge, you'll understand:**

1. **Packet Encapsulation** - How headers wrap data at each layer
2. **Protocol Headers** - Exact field-by-field construction
3. **Network Stack Interaction** - How layers communicate
4. **Raw Socket Programming** - Low-level network access
5. **Protocol Specifications** - RFC-compliant implementations
6. **Error Detection** - Checksums and validation
7. **Network Analysis** - Using Wireshark for verification

### 🔍 Key Concepts Demonstrated

- **MAC Addressing** - Hardware-level communication
- **IP Routing** - Logical network addressing
- **Port Multiplexing** - Multiple services on one IP
- **Connection States** - TCP handshake process
- **Protocol Discrimination** - Ethernet type, IP protocol fields
- **Data Integrity** - Checksum verification

---

## 🛠️ Advanced Features

### 🔧 Customization Points

#### Protocol Extensions
```c
// Add new protocol types
#define ETH_P_CUSTOM 0x88B5

// Extend with new transport protocols
int create_custom_protocol(unsigned char *buffer, ...);
```

#### Header Modification
```c
// Custom IP options
ip->tos = 0x10;  // Differentiated Services

// Custom TCP flags
tcp->ece = 1;    // ECN-Echo capability
tcp->cwr = 1;    // Congestion Window Reduced
```

### 📈 Performance Considerations

- **Zero-copy operations** where possible
- **Batch packet sending** for high-throughput
- **Kernel bypass** techniques for latency-sensitive applications
- **Memory pool allocation** for packet buffers

---

## 🔍 Troubleshooting

### Common Issues

#### ❌ "SIOCGIFADDR failed: Cannot assign requested address"
**Cause:** Network interface has no IP address
**Solution:** 
```bash
sudo ip addr add 192.168.1.100/24 dev eth0
sudo ip link set eth0 up
```

#### ❌ "Operation not permitted"
**Cause:** Missing raw socket capabilities
**Solution:**
```bash
sudo setcap cap_net_raw+ep netforge
# OR run with sudo
sudo ./netforge eth0 ping 8.8.8.8
```

#### ❌ "No such device"
**Cause:** Wrong interface name
**Solution:**
```bash
ip link show  # Find correct interface name
./netforge wlan0 ping 8.8.8.8
```

### Wireshark Tips

- **Filter by MAC:** `eth.addr == 00:11:22:33:44:55`
- **Filter by IP:** `ip.addr == 192.168.1.100`
- **Follow TCP Stream:** Right-click → Follow → TCP Stream
- **Export packets:** File → Export Packet Dissections

---

## 🚀 Future Enhancements

### Planned Features
- [ ] **Packet Reception** - Receive and process incoming packets
- [ ] **ARP Protocol** - MAC address resolution
- [ ] **DNS Client** - Domain name resolution
- [ ] **DHCP Client** - Automatic IP configuration
- [ ] **IPv6 Support** - Modern protocol implementation
- [ ] **TLS/SSL** - Encrypted communication
- [ ] **Network Server** - Listen for incoming connections
- [ ] **Performance Metrics** - Latency and throughput measurement

### Research Directions
- **Kernel Module** - Even lower-level network access
- **DPDK Integration** - Userspace networking acceleration
- **Protocol Fuzzing** - Network security testing
- **Custom Protocols** - Experimental network designs

---

## 🤝 Contributing

NetForge welcomes contributions! Areas of particular interest:

- **New Protocol Implementations**
- **Performance Optimizations**
- **Additional Documentation**
- **Testing and Validation**
- **Cross-platform Support**

### Development Setup
```bash
git clone <repository>
cd netforge
make debug
gdb ./netforge
```

---

## 📚 Learning Resources

### RFC Documents
- RFC 791 - Internet Protocol (IPv4)
- RFC 793 - Transmission Control Protocol (TCP)
- RFC 768 - User Datagram Protocol (UDP)
- RFC 792 - Internet Control Message Protocol (ICMP)
- RFC 826 - Ethernet Address Resolution Protocol (ARP)

### Recommended Reading
- "TCP/IP Illustrated, Volume 1" by W. Richard Stevens
- "Understanding Linux Network Internals" by Christian Benvenuti
- "Linux Kernel Networking" by Rami Rosen

---

## 🎉 Conclusion

**NetForge represents the culmination of deep networking understanding translated into practical implementation.** From the initial curiosity about "how packets really work" to creating a tool that generates real, Wireshark-detectable network traffic, this project demonstrates the complete TCP/IP stack in action.

### Key Achievements
- ✅ **Real Network Packets** - Not simulations
- ✅ **Complete Protocol Stack** - All four TCP/IP layers
- ✅ **Educational Clarity** - Well-documented and explained
- ✅ **Professional Quality** - Robust error handling and features
- ✅ **Practical Utility** - Useful for testing and learning

### The Big Picture
NetForge bridges the gap between theoretical networking knowledge and practical implementation. By seeing your own packets travel through the network and being decoded by professional tools, you gain an intuitive understanding that reading alone cannot provide.

**This isn't just code - it's a deep dive into the fundamental technology that powers the internet.**

---
**NetForge - Forging the Future of Networking Education**  
*Developed by Yx0R* 🚀