/**
 * Custom TCP/IP Stack - Main Application
 * Complete implementation with multiple protocols
 * Creates real packets detectable by Wireshark
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

// Global configuration - defined HERE (not in protocols.h)
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
void print_usage();
void print_banner();
int get_mac_address(const char *interface, unsigned char *mac);
int get_ip_address(const char *interface, uint32_t *ip);

/**
 * Create raw socket for packet injection and reception
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
 * Get network interface index
 */
int get_interface_index(int sock, const char *interface) {
    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("❌ SIOCGIFINDEX failed");
        return -1;
    }
    printf("✅ Interface %s index: %d\n", interface, ifr.ifr_ifindex);
    return ifr.ifr_ifindex;
}

/**
 * Get MAC address of network interface
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
    
    printf("✅ MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return 0;
}

/**
 * Get IP address of network interface
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
    
    printf("✅ IP address: %s\n", inet_ntoa(ip_addr->sin_addr));
    return 0;
}

/**
 * Send raw Ethernet frame
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

/**
 * Send ICMP Ping (Echo Request)
 */
void send_ping(struct stack_config *config, uint32_t target_ip) {
    printf("\n🎯 Sending ICMP Ping...\n");
    printf("   From: %s\n", inet_ntoa(*(struct in_addr*)&config->src_ip));
    printf("   To:   %s\n", inet_ntoa(*(struct in_addr*)&target_ip));
    
    unsigned char packet[1500];
    unsigned char icmp_payload[1500];
    
    // Create ICMP Echo Request
    int icmp_len = create_icmp_echo_request(icmp_payload, 
                                          getpid() & 0xFFFF,  // Use PID as ID
                                          1,                  // Sequence number
                                          NULL, 0);           // No extra data
    
    // Create IP packet
    int ip_len = create_ipv4_packet(packet, 
                                   config->src_ip, 
                                   target_ip, 
                                   IPPROTO_ICMP, 
                                   64,                        // TTL
                                   icmp_payload, 
                                   icmp_len);
    
    // Send Ethernet frame
    int sent = send_ethernet_frame(config, ETH_P_IP, packet, ip_len);
    
    if (sent > 0) {
        printf("✅ Ping sent successfully!\n");
        printf("📡 Check Wireshark for ICMP Echo Request\n");
    } else {
        perror("❌ Failed to send ping");
    }
}

/**
 * Send TCP SYN Packet (Start connection)
 */
void send_tcp_syn(struct stack_config *config, uint32_t target_ip, uint16_t target_port) {
    printf("\n🎯 Sending TCP SYN...\n");
    printf("   From: %s:%d\n", inet_ntoa(*(struct in_addr*)&config->src_ip), 12345);
    printf("   To:   %s:%d\n", inet_ntoa(*(struct in_addr*)&target_ip), target_port);
    
    unsigned char packet[1500];
    unsigned char tcp_payload[1500];
    
    // Create TCP segment with SYN flag
    int tcp_len = create_tcp_packet(tcp_payload,
                                   12345,                    // Source port
                                   target_port,             // Destination port  
                                   time(NULL),              // Sequence number
                                   0,                       // ACK number
                                   0x02,                    // SYN flag
                                   NULL, 0);                // No payload for SYN
    
    // Create IP packet
    int ip_len = create_ipv4_packet(packet,
                                   config->src_ip,
                                   target_ip,
                                   IPPROTO_TCP,
                                   64,                      // TTL
                                   tcp_payload,
                                   tcp_len);
    
    // Send Ethernet frame
    int sent = send_ethernet_frame(config, ETH_P_IP, packet, ip_len);
    
    if (sent > 0) {
        printf("✅ TCP SYN sent successfully!\n");
        printf("📡 Check Wireshark for TCP handshake attempt\n");
    } else {
        perror("❌ Failed to send TCP SYN");
    }
}

/**
 * Send UDP Packet
 */
void send_udp_packet(struct stack_config *config, uint32_t target_ip, uint16_t target_port) {
    printf("\n🎯 Sending UDP Packet...\n");
    printf("   From: %s:%d\n", inet_ntoa(*(struct in_addr*)&config->src_ip), 12345);
    printf("   To:   %s:%d\n", inet_ntoa(*(struct in_addr*)&target_ip), target_port);
    
    unsigned char packet[1500];
    unsigned char udp_payload[1500];
    
    // Create UDP datagram
    const char *message = "Hello from Custom TCP/IP Stack!";
    int udp_len = create_udp_packet(udp_payload,
                                   12345,                    // Source port
                                   target_port,             // Destination port
                                   (unsigned char*)message, // Payload
                                   strlen(message));        // Payload length
    
    // Create IP packet
    int ip_len = create_ipv4_packet(packet,
                                   config->src_ip,
                                   target_ip,
                                   IPPROTO_UDP,
                                   64,                      // TTL
                                   udp_payload,
                                   udp_len);
    
    // Send Ethernet frame
    int sent = send_ethernet_frame(config, ETH_P_IP, packet, ip_len);
    
    if (sent > 0) {
        printf("✅ UDP packet sent successfully!\n");
        printf("📡 Check Wireshark for UDP datagram\n");
    } else {
        perror("❌ Failed to send UDP packet");
    }
}

/**
 * Send HTTP GET Request
 */
void send_http_get(struct stack_config *config, uint32_t target_ip, uint16_t target_port) {
    printf("\n🎯 Sending HTTP GET Request...\n");
    printf("   From: %s:%d\n", inet_ntoa(*(struct in_addr*)&config->src_ip), 12345);
    printf("   To:   %s:%d\n", inet_ntoa(*(struct in_addr*)&target_ip), target_port);
    
    unsigned char packet[1500];
    unsigned char tcp_payload[1500];
    
    // Create HTTP GET request
    char http_request[512];
    snprintf(http_request, sizeof(http_request),
             "GET / HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: Custom-TCPIP-Stack/1.0\r\n"
             "Connection: close\r\n"
             "\r\n",
             inet_ntoa(*(struct in_addr*)&target_ip));
    
    // Create TCP segment with PSH+ACK flags
    int tcp_len = create_tcp_packet(tcp_payload,
                                   12345,                    // Source port
                                   target_port,             // Destination port (HTTP)
                                   time(NULL),              // Sequence number
                                   0,                       // ACK number (no ACK for first packet)
                                   0x18,                    // PSH + ACK flags
                                   (unsigned char*)http_request, // HTTP payload
                                   strlen(http_request));   // Payload length
    
    // Create IP packet
    int ip_len = create_ipv4_packet(packet,
                                   config->src_ip,
                                   target_ip,
                                   IPPROTO_TCP,
                                   64,                      // TTL
                                   tcp_payload,
                                   tcp_len);
    
    // Send Ethernet frame
    int sent = send_ethernet_frame(config, ETH_P_IP, packet, ip_len);
    
    if (sent > 0) {
        printf("✅ HTTP GET request sent successfully!\n");
        printf("📡 Check Wireshark for HTTP traffic\n");
    } else {
        perror("❌ Failed to send HTTP request");
    }
}

/**
 * Send Custom Ethernet Frame (for testing)
 */
void send_raw_ethernet(struct stack_config *config) {
    printf("\n🎯 Sending Raw Ethernet Frame...\n");
    
    unsigned char custom_payload[] = {
        0xDE, 0xAD, 0xBE, 0xEF,  // Magic number
        0x12, 0x34, 0x56, 0x78   // Test data
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
        perror("❌ Failed to send raw Ethernet frame");
    }
}

/**
 * Initialize TCP/IP stack configuration
 */
int init_stack(struct stack_config *config, const char *interface) {
    printf("\n🚀 Initializing Custom TCP/IP Stack...\n");
    printf("========================================\n");
    
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
        // Default MAC for testing
        unsigned char default_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
        memcpy(config->src_mac, default_mac, 6);
    }
    
    // Get IP address
    if (get_ip_address(interface, &config->src_ip) < 0) {
        printf("⚠️  Using default IP address\n");
        config->src_ip = inet_addr("192.168.1.100");
    }
    
    // Default destination MAC (broadcast for testing)
    unsigned char broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    memcpy(config->dest_mac, broadcast_mac, 6);
    
    printf("✅ TCP/IP Stack Initialized Successfully!\n");
    return 0;
}

/**
 * Cleanup resources
 */
void cleanup_stack(struct stack_config *config) {
    if (config->raw_socket >= 0) {
        close(config->raw_socket);
        printf("✅ Socket closed\n");
    }
}

/**
 * Print usage information
 */
void print_usage() {
    printf("\n📖 Usage:\n");
    printf("  sudo ./mytcpip <interface> <command> [options]\n\n");
    printf("Commands:\n");
    printf("  ping <target_ip>         Send ICMP ping to target\n");
    printf("  tcp <target_ip> <port>   Send TCP SYN to target:port\n");
    printf("  udp <target_ip> <port>   Send UDP packet to target:port\n");
    printf("  http <target_ip>         Send HTTP GET to target:80\n");
    printf("  raw                      Send raw Ethernet frame\n");
    printf("  all <target_ip>          Send all packet types\n");
    printf("\nExamples:\n");
    printf("  sudo ./mytcpip eth0 ping 8.8.8.8\n");
    printf("  sudo ./mytcpip eth0 tcp 192.168.1.1 80\n");
    printf("  sudo ./mytcpip eth0 all 192.168.1.1\n");
}

/**
 * Print banner
 */
void print_banner() {
    printf("\n");
    printf("🌐 Custom TCP/IP Stack - Real Packet Generator\n");
    printf("==============================================\n");
    printf("Creates real network packets detectable by Wireshark\n");
    printf("Implements: Ethernet II, IPv4, ICMP, TCP, UDP, HTTP\n");
    printf("\n");
}

/**
 * Send all packet types (comprehensive test)
 */
void send_all_packets(struct stack_config *config, uint32_t target_ip) {
    printf("\n🎯 Sending All Packet Types...\n");
    printf("================================\n");
    
    // 1. ICMP Ping
    send_ping(config, target_ip);
    sleep(1);
    
    // 2. TCP SYN to common ports
    send_tcp_syn(config, target_ip, 80);   // HTTP
    sleep(1);
    send_tcp_syn(config, target_ip, 443);  // HTTPS
    sleep(1);
    
    // 3. UDP to common ports
    send_udp_packet(config, target_ip, 53);   // DNS
    sleep(1);
    send_udp_packet(config, target_ip, 123);  // NTP
    sleep(1);
    
    // 4. HTTP GET
    send_http_get(config, target_ip, 80);
    sleep(1);
    
    // 5. Raw Ethernet
    send_raw_ethernet(config);
    
    printf("\n✅ All packet types sent successfully!\n");
    printf("📡 Check Wireshark for comprehensive packet capture\n");
}

/**
 * Main application entry point
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
        printf("❌ Failed to initialize TCP/IP stack\n");
        return 1;
    }
    
    // Parse and execute command
    if (strcmp(command, "ping") == 0 && argc == 4) {
        uint32_t target_ip = inet_addr(argv[3]);
        send_ping(&config, target_ip);
        
    } else if (strcmp(command, "tcp") == 0 && argc == 5) {
        uint32_t target_ip = inet_addr(argv[3]);
        uint16_t target_port = atoi(argv[4]);
        send_tcp_syn(&config, target_ip, target_port);
        
    } else if (strcmp(command, "udp") == 0 && argc == 5) {
        uint32_t target_ip = inet_addr(argv[3]);
        uint16_t target_port = atoi(argv[4]);
        send_udp_packet(&config, target_ip, target_port);
        
    } else if (strcmp(command, "http") == 0 && argc == 4) {
        uint32_t target_ip = inet_addr(argv[3]);
        send_http_get(&config, target_ip, 80);
        
    } else if (strcmp(command, "raw") == 0) {
        send_raw_ethernet(&config);
        
    } else if (strcmp(command, "all") == 0 && argc == 4) {
        uint32_t target_ip = inet_addr(argv[3]);
        send_all_packets(&config, target_ip);
        
    } else {
        print_usage();
        cleanup_stack(&config);
        return 1;
    }
    
    printf("\n💡 Tip: Run 'sudo wireshark' or 'sudo tshark -i %s' to capture packets\n", interface);
    
    cleanup_stack(&config);
    return 0;
}
