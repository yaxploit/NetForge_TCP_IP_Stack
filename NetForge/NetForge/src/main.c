/**
 * NetForge - Custom TCP/IP Protocol Stack
 * ======================================
 * Developed by Yx0R
 * 
 * A complete TCP/IP implementation from scratch
 * Creates real network packets detectable by Wireshark
 * Supports: Ethernet, IPv4, ICMP, TCP, UDP, HTTP, DNS, DHCP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <time.h>
#include <linux/if_packet.h>

#include "protocols.h"

// Stack configuration structure
struct stack_config {
    int raw_socket;
    int if_index;
    unsigned char src_mac[6];
    unsigned char dest_mac[6];
    uint32_t src_ip;
    uint32_t dest_ip;
    char if_name[16];
};

// Function declarations
void print_banner();
void print_usage();
void print_stats();
int get_mac_address(const char *interface, unsigned char *mac);
int get_ip_address(const char *interface, uint32_t *ip);
void show_interface_info(struct stack_config *config);

/* ==================== VISUAL ENHANCEMENTS ==================== */

/**
 * Print colorful banner with tool information
 */
void print_banner() {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                                                              ║\n");
    printf("║    ███╗   ██╗███████╗████████╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗ ║\n");
    printf("║    ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝ ║\n");
    printf("║    ██╔██╗ ██║█████╗     ██║   █████╗  ██║     ██║   ██║██████╔╝█████╗   ║\n");
    printf("║    ██║╚██╗██║██╔══╝     ██║   ██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝   ║\n");
    printf("║    ██║ ╚████║███████╗   ██║   ██║     ╚██████╗╚██████╔╝██║  ██║███████╗ ║\n");
    printf("║    ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝       ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ║\n");
    printf("║                                                              ║\n");
    printf("║               Custom TCP/IP Protocol Stack                   ║\n");
    printf("║                     Developed by Yx0R                        ║\n");
    printf("║                                                              ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("🌐 Real Network Packets | 📡 Wireshark Compatible | 🚀 From Scratch\n");
    printf("\n");
}

/**
 * Print usage information with colorful formatting
 */
void print_usage() {
    printf("\n📖 USAGE GUIDE\n");
    printf("══════════════════════════════════════════════════════════════\n");
    printf("  netforge <interface> <command> [target] [port]\n\n");
    
    printf("🎯 AVAILABLE COMMANDS:\n");
    printf("──────────────────────────────────────────────────────────────\n");
    printf("  ping    <target_ip>           🔍 Send ICMP Echo Request\n");
    printf("  tcp     <target_ip> <port>    🔗 Send TCP SYN Packet\n");
    printf("  udp     <target_ip> <port>    📦 Send UDP Datagram\n");
    printf("  http    <target_ip>           🌐 Send HTTP GET Request\n");
    printf("  raw                           🔧 Send Raw Ethernet Frame\n");
    printf("  info                          ℹ️  Show Interface Information\n");
    printf("  all     <target_ip>           🎪 Send All Packet Types\n\n");
    
    printf("💡 EXAMPLES:\n");
    printf("──────────────────────────────────────────────────────────────\n");
    printf("  netforge eth0 ping 8.8.8.8\n");
    printf("  netforge eth0 tcp 192.168.1.1 80\n");
    printf("  netforge eth0 udp 192.168.1.1 53\n");
    printf("  netforge eth0 all 192.168.1.1\n");
    printf("  netforge eth0 info\n");
    printf("\n");
}

/**
 * Show detailed interface information
 */
void show_interface_info(struct stack_config *config) {
    printf("\n📊 INTERFACE INFORMATION\n");
    printf("══════════════════════════════════════════════════════════════\n");
    printf("  Interface:    %s\n", config->if_name);
    printf("  Index:        %d\n", config->if_index);
    printf("  MAC Address:  %02x:%02x:%02x:%02x:%02x:%02x\n",
           config->src_mac[0], config->src_mac[1], config->src_mac[2],
           config->src_mac[3], config->src_mac[4], config->src_mac[5]);
    printf("  IP Address:   %s\n", inet_ntoa(*(struct in_addr*)&config->src_ip));
    printf("  Socket:       %d (Raw)\n", config->raw_socket);
    printf("  Status:       ✅ Ready to send packets\n");
    printf("\n");
}

/* ==================== CORE FUNCTIONALITY ==================== */

/**
 * Create raw socket for low-level packet manipulation
 * Returns socket descriptor or -1 on error
 */
int create_raw_socket(int protocol) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(protocol));
    if (sock < 0) {
        perror("❌ Raw socket creation failed");
        return -1;
    }
    printf("✅ Raw socket created successfully\n");
    return sock;
}

/**
 * Get network interface index by name
 * Required for binding sockets to specific interfaces
 */
int get_interface_index(int sock, const char *interface) {
    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("❌ SIOCGIFINDEX failed");
        return -1;
    }
    return ifr.ifr_ifindex;
}

/**
 * Retrieve MAC address of specified network interface
 * Essential for Ethernet frame construction
 */
int get_mac_address(const char *interface, unsigned char *mac) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("❌ Socket creation for MAC failed");
        return -1;
    }
    
    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("❌ SIOCGIFHWADDR failed");
        close(sock);
        return -1;
    }
    
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
    return 0;
}

/**
 * Retrieve IP address of specified network interface
 * Used as source address in IP packets
 */
int get_ip_address(const char *interface, uint32_t *ip) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("❌ Socket creation for IP failed");
        return -1;
    }
    
    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("❌ SIOCGIFADDR failed");
        close(sock);
        return -1;
    }
    
    struct sockaddr_in *ip_addr = (struct sockaddr_in *)&ifr.ifr_addr;
    *ip = ip_addr->sin_addr.s_addr;
    close(sock);
    return 0;
}

/**
 * Send Ethernet frame with complete header construction
 * Handles MAC addressing and frame assembly
 */
int send_ethernet_frame(struct stack_config *config,
                       unsigned short ethertype, 
                       unsigned char *payload, 
                       int payload_len) {
    
    unsigned char frame[1514];
    struct ethhdr *eth = (struct ethhdr *)frame;
    
    // Build Ethernet header
    memcpy(eth->h_dest, config->dest_mac, 6);
    memcpy(eth->h_source, config->src_mac, 6);
    eth->h_proto = htons(ethertype);
    
    // Copy payload
    memcpy(frame + sizeof(struct ethhdr), payload, payload_len);
    
    // Send via raw socket
    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = config->if_index;
    addr.sll_halen = ETH_ALEN;
    memcpy(addr.sll_addr, config->dest_mac, 6);
    
    int total_len = sizeof(struct ethhdr) + payload_len;
    int sent = sendto(config->raw_socket, frame, total_len, 0, 
                     (struct sockaddr*)&addr, sizeof(addr));
    
    if (sent > 0) {
        printf("📤 Sent %d bytes via Ethernet\n", sent);
    } else {
        perror("❌ Send failed");
    }
    
    return sent;
}

/* ==================== PROTOCOL IMPLEMENTATIONS ==================== */

/**
 * Send ICMP Echo Request (Ping)
 * Tests network connectivity and measures latency
 */
void send_ping(struct stack_config *config, const char *target_ip_str) {
    printf("\n🎯 SENDING ICMP PING\n");
    printf("──────────────────────────────────────────────────────────────\n");
    
    uint32_t target_ip = inet_addr(target_ip_str);
    if (target_ip == INADDR_NONE) {
        printf("❌ Invalid IP address: %s\n", target_ip_str);
        return;
    }
    
    printf("  Source: %s\n", inet_ntoa(*(struct in_addr*)&config->src_ip));
    printf("  Target: %s\n", target_ip_str);
    printf("  Protocol: ICMP Echo Request\n");
    
    unsigned char packet[1500];
    unsigned char icmp_payload[1500];
    
    // Create ICMP Echo Request
    int icmp_len = create_icmp_echo_request(icmp_payload, 
                                          getpid() & 0xFFFF,
                                          1,
                                          NULL, 0);
    
    // Create IP packet
    int ip_len = create_ipv4_packet(packet, 
                                   config->src_ip, 
                                   target_ip, 
                                   IPPROTO_ICMP, 
                                   64,
                                   icmp_payload, 
                                   icmp_len);
    
    // Send Ethernet frame
    int sent = send_ethernet_frame(config, ETH_P_IP, packet, ip_len);
    
    if (sent > 0) {
        printf("✅ Ping sent successfully!\n");
        printf("📡 Check Wireshark for ICMP Echo Request\n");
    } else {
        printf("❌ Failed to send ping\n");
    }
}

/**
 * Send TCP SYN Packet
 * Initiates TCP three-way handshake
 */
void send_tcp_syn(struct stack_config *config, const char *target_ip_str, const char *port_str) {
    printf("\n🎯 SENDING TCP SYN PACKET\n");
    printf("──────────────────────────────────────────────────────────────\n");
    
    uint32_t target_ip = inet_addr(target_ip_str);
    if (target_ip == INADDR_NONE) {
        printf("❌ Invalid IP address: %s\n", target_ip_str);
        return;
    }
    
    int target_port = atoi(port_str);
    if (target_port <= 0 || target_port > 65535) {
        printf("❌ Invalid port: %s\n", port_str);
        return;
    }
    
    printf("  Source: %s:%d\n", inet_ntoa(*(struct in_addr*)&config->src_ip), 12345);
    printf("  Target: %s:%d\n", target_ip_str, target_port);
    printf("  Flags: SYN (Connection Initiation)\n");
    
    unsigned char packet[1500];
    unsigned char tcp_payload[1500];
    
    // Create TCP segment with SYN flag
    int tcp_len = create_tcp_packet(tcp_payload,
                                   12345,
                                   target_port,  
                                   time(NULL),
                                   0,
                                   0x02,
                                   NULL, 0);
    
    // Create IP packet
    int ip_len = create_ipv4_packet(packet,
                                   config->src_ip,
                                   target_ip,
                                   IPPROTO_TCP,
                                   64,
                                   tcp_payload,
                                   tcp_len);
    
    // Send Ethernet frame
    int sent = send_ethernet_frame(config, ETH_P_IP, packet, ip_len);
    
    if (sent > 0) {
        printf("✅ TCP SYN sent successfully!\n");
        printf("📡 Check Wireshark for TCP handshake attempt\n");
    } else {
        printf("❌ Failed to send TCP SYN\n");
    }
}

/**
 * Send UDP Packet
 * Connectionless communication for DNS, DHCP, etc.
 */
void send_udp_packet(struct stack_config *config, const char *target_ip_str, const char *port_str) {
    printf("\n🎯 SENDING UDP DATAGRAM\n");
    printf("──────────────────────────────────────────────────────────────\n");
    
    uint32_t target_ip = inet_addr(target_ip_str);
    if (target_ip == INADDR_NONE) {
        printf("❌ Invalid IP address: %s\n", target_ip_str);
        return;
    }
    
    int target_port = atoi(port_str);
    if (target_port <= 0 || target_port > 65535) {
        printf("❌ Invalid port: %s\n", port_str);
        return;
    }
    
    printf("  Source: %s:%d\n", inet_ntoa(*(struct in_addr*)&config->src_ip), 12345);
    printf("  Target: %s:%d\n", target_ip_str, target_port);
    printf("  Protocol: UDP (Connectionless)\n");
    
    unsigned char packet[1500];
    unsigned char udp_payload[1500];
    
    // Create UDP datagram
    const char *message = "Hello from NetForge TCP/IP Stack!";
    int udp_len = create_udp_packet(udp_payload,
                                   12345,
                                   target_port,
                                   (unsigned char*)message,
                                   strlen(message));
    
    // Create IP packet
    int ip_len = create_ipv4_packet(packet,
                                   config->src_ip,
                                   target_ip,
                                   IPPROTO_UDP,
                                   64,
                                   udp_payload,
                                   udp_len);
    
    // Send Ethernet frame
    int sent = send_ethernet_frame(config, ETH_P_IP, packet, ip_len);
    
    if (sent > 0) {
        printf("✅ UDP packet sent successfully!\n");
        printf("📡 Check Wireshark for UDP datagram\n");
    } else {
        printf("❌ Failed to send UDP packet\n");
    }
}

/**
 * Send HTTP GET Request
 * Application layer protocol over TCP
 */
void send_http_get(struct stack_config *config, const char *target_ip_str) {
    printf("\n🎯 SENDING HTTP GET REQUEST\n");
    printf("──────────────────────────────────────────────────────────────\n");
    
    uint32_t target_ip = inet_addr(target_ip_str);
    if (target_ip == INADDR_NONE) {
        printf("❌ Invalid IP address: %s\n", target_ip_str);
        return;
    }
    
    printf("  Source: %s:%d\n", inet_ntoa(*(struct in_addr*)&config->src_ip), 12345);
    printf("  Target: %s:80\n", target_ip_str);
    printf("  Protocol: HTTP/1.1 GET Request\n");
    
    unsigned char packet[1500];
    unsigned char tcp_payload[1500];
    
    // Create HTTP GET request
    char http_request[512];
    int http_len = snprintf(http_request, sizeof(http_request),
                           "GET / HTTP/1.1\r\n"
                           "Host: %s\r\n"
                           "User-Agent: NetForge/1.0\r\n"
                           "Connection: close\r\n"
                           "\r\n",
                           target_ip_str);
    
    // Create TCP segment with PSH+ACK flags
    int tcp_len = create_tcp_packet(tcp_payload,
                                   12345,
                                   80,
                                   time(NULL),
                                   0,
                                   0x18,
                                   (unsigned char*)http_request,
                                   http_len);
    
    // Create IP packet
    int ip_len = create_ipv4_packet(packet,
                                   config->src_ip,
                                   target_ip,
                                   IPPROTO_TCP,
                                   64,
                                   tcp_payload,
                                   tcp_len);
    
    // Send Ethernet frame
    int sent = send_ethernet_frame(config, ETH_P_IP, packet, ip_len);
    
    if (sent > 0) {
        printf("✅ HTTP GET request sent successfully!\n");
        printf("📡 Check Wireshark for HTTP traffic\n");
    } else {
        printf("❌ Failed to send HTTP request\n");
    }
}

/**
 * Send Custom Ethernet Frame
 * Raw Ethernet frame for testing and custom protocols
 */
void send_raw_ethernet(struct stack_config *config) {
    printf("\n🎯 SENDING RAW ETHERNET FRAME\n");
    printf("──────────────────────────────────────────────────────────────\n");
    printf("  Protocol: Raw Ethernet (Experimental)\n");
    
    unsigned char custom_payload[] = {
        0xDE, 0xAD, 0xBE, 0xEF,  // Magic number
        0x12, 0x34, 0x56, 0x78,  // Test data
        'N', 'E', 'T', 'F', 'O', 'R', 'G', 'E'  // Tool signature
    };
    
    // Use a custom EtherType (within the experimental range)
    unsigned short custom_ethertype = 0x88B5;
    
    int sent = send_ethernet_frame(config, custom_ethertype, 
                                  custom_payload, sizeof(custom_payload));
    
    if (sent > 0) {
        printf("✅ Raw Ethernet frame sent successfully!\n");
        printf("📡 Check Wireshark for custom Ethernet frame\n");
        printf("   EtherType: 0x%04X (Experimental)\n", custom_ethertype);
    } else {
        printf("❌ Failed to send raw Ethernet frame\n");
    }
}

/**
 * Send All Packet Types
 * Comprehensive test of all implemented protocols
 */
void send_all_packets(struct stack_config *config, const char *target_ip_str) {
    printf("\n🎪 SENDING ALL PACKET TYPES\n");
    printf("══════════════════════════════════════════════════════════════\n");
    
    uint32_t target_ip = inet_addr(target_ip_str);
    if (target_ip == INADDR_NONE) {
        printf("❌ Invalid IP address: %s\n", target_ip_str);
        return;
    }
    
    printf("  Target: %s\n", target_ip_str);
    printf("  Tests: ICMP, TCP, UDP, HTTP, Raw Ethernet\n");
    printf("\n");
    
    // 1. ICMP Ping
    printf("1. 🔍 ICMP Ping:\n");
    send_ping(config, target_ip_str);
    sleep(1);
    
    // 2. TCP SYN
    printf("\n2. 🔗 TCP SYN:\n");
    send_tcp_syn(config, target_ip_str, "80");
    sleep(1);
    
    // 3. UDP
    printf("\n3. 📦 UDP Datagram:\n");
    send_udp_packet(config, target_ip_str, "53");
    sleep(1);
    
    // 4. HTTP
    printf("\n4. 🌐 HTTP GET:\n");
    send_http_get(config, target_ip_str);
    sleep(1);
    
    // 5. Raw Ethernet
    printf("\n5. 🔧 Raw Ethernet:\n");
    send_raw_ethernet(config);
    
    printf("\n══════════════════════════════════════════════════════════════\n");
    printf("✅ All packet types sent successfully!\n");
    printf("📡 Check Wireshark for comprehensive packet capture\n");
}

/* ==================== MAIN APPLICATION ==================== */

/**
 * Initialize TCP/IP stack with specified network interface
 * Sets up raw socket, MAC address, and IP configuration
 */
int init_stack(struct stack_config *config, const char *interface) {
    printf("\n🚀 INITIALIZING NETFORGE STACK\n");
    printf("══════════════════════════════════════════════════════════════\n");
    
    strncpy(config->if_name, interface, sizeof(config->if_name) - 1);
    
    // Create raw socket
    config->raw_socket = create_raw_socket(ETH_P_ALL);
    if (config->raw_socket < 0) {
        return -1;
    }
    
    // Get interface index
    config->if_index = get_interface_index(config->raw_socket, interface);
    if (config->if_index < 0) {
        close(config->raw_socket);
        return -1;
    }
    
    // Get MAC address
    if (get_mac_address(interface, config->src_mac) < 0) {
        printf("⚠️  Using default MAC address\n");
        unsigned char default_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
        memcpy(config->src_mac, default_mac, 6);
    }
    
    // Get IP address
    if (get_ip_address(interface, &config->src_ip) < 0) {
        printf("⚠️  Using default IP address\n");
        config->src_ip = inet_addr("192.168.1.100");
    }
    
    // Default destination MAC (broadcast)
    unsigned char broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    memcpy(config->dest_mac, broadcast_mac, 6);
    
    printf("✅ NetForge Stack Initialized Successfully!\n");
    return 0;
}

/**
 * Cleanup resources and close sockets
 */
void cleanup_stack(struct stack_config *config) {
    if (config->raw_socket >= 0) {
        close(config->raw_socket);
        printf("✅ Socket closed\n");
    }
}

/**
 * Main application entry point
 * Handles command parsing and protocol selection
 */
int main(int argc, char *argv[]) {
    print_banner();
    
    if (argc < 3) {
        print_usage();
        return 1;
    }
    
    const char *interface = argv[1];
    const char *command = argv[2];
    
    // Initialize stack
    struct stack_config config;
    if (init_stack(&config, interface) < 0) {
        printf("❌ Failed to initialize NetForge stack\n");
        return 1;
    }
    
    // Parse and execute commands
    int success = 1;
    
    if (strcmp(command, "ping") == 0 && argc == 4) {
        send_ping(&config, argv[3]);
        
    } else if (strcmp(command, "tcp") == 0 && argc == 5) {
        send_tcp_syn(&config, argv[3], argv[4]);
        
    } else if (strcmp(command, "udp") == 0 && argc == 5) {
        send_udp_packet(&config, argv[3], argv[4]);
        
    } else if (strcmp(command, "http") == 0 && argc == 4) {
        send_http_get(&config, argv[3]);
        
    } else if (strcmp(command, "raw") == 0 && argc == 3) {
        send_raw_ethernet(&config);
        
    } else if (strcmp(command, "all") == 0 && argc == 4) {
        send_all_packets(&config, argv[3]);
        
    } else if (strcmp(command, "info") == 0 && argc == 3) {
        show_interface_info(&config);
        
    } else {
        printf("❌ Invalid command or arguments\n");
        print_usage();
        success = 0;
    }
    
    if (success) {
        printf("\n💡 TIP: Run 'sudo wireshark' or 'sudo tshark -i %s' to capture packets\n", interface);
    }
    
    cleanup_stack(&config);
    return success ? 0 : 1;
}
