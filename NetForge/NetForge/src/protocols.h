/**
 * NetForge - Custom TCP/IP Protocol Stack
 * Developed by Yx0R
 * 
 * protocols.h - Protocol definitions and function declarations
 * Complete TCP/IP stack implementation from Ethernet to Application layer
 */

#ifndef PROTOCOLS_H
#define PROTOCOLS_H

#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

// Forward declaration of stack configuration
struct stack_config;

/* ==================== ETHERNET LAYER FUNCTIONS ==================== */
/**
 * Send Ethernet frame with specified payload and EtherType
 * Handles MAC addressing and frame construction
 */
int send_ethernet_frame(struct stack_config *config, unsigned short ethertype, 
                       unsigned char *payload, int payload_len);

/* ==================== INTERNET LAYER FUNCTIONS ==================== */
/**
 * Calculate Internet checksum for IP/ICMP/TCP headers
 * Essential for packet validation and integrity
 */
unsigned short calculate_checksum(unsigned short *ptr, int nbytes);

/**
 * Create IPv4 packet with complete header fields
 * Handles TTL, protocol selection, and checksum calculation
 */
int create_ipv4_packet(unsigned char *buffer, uint32_t src_ip, uint32_t dest_ip,
                      uint8_t protocol, uint8_t ttl, unsigned char *payload, int payload_len);

/* ==================== TRANSPORT LAYER FUNCTIONS ==================== */
/**
 * Create ICMP Echo Request for network testing
 * Implements ping functionality with sequence tracking
 */
int create_icmp_echo_request(unsigned char *buffer, uint16_t id, uint16_t sequence,
                            unsigned char *data, int data_len);

/**
 * Create TCP segment with configurable flags and options
 * Supports SYN, ACK, FIN, RST, PSH, URG flags
 */
int create_tcp_packet(unsigned char *buffer, uint16_t src_port, uint16_t dest_port,
                     uint32_t seq_num, uint32_t ack_num, uint8_t flags,
                     unsigned char *payload, int payload_len);

/**
 * Create UDP datagram for connectionless communication
 * Lightweight protocol for DNS, DHCP, and real-time applications
 */
int create_udp_packet(unsigned char *buffer, uint16_t src_port, uint16_t dest_port,
                     unsigned char *payload, int payload_len);

/* ==================== APPLICATION LAYER FUNCTIONS ==================== */
/**
 * Create HTTP GET request for web communication
 * Implements HTTP/1.1 with standard headers
 */
int create_http_request(unsigned char *buffer, const char *host, const char *path);

/**
 * Create DNS query for domain name resolution
 * Supports A record lookups
 */
int create_dns_query(unsigned char *buffer, const char *domain_name);

/**
 * Create DHCP Discover for automatic IP configuration
 * Requests network parameters from DHCP server
 */
int create_dhcp_discover(unsigned char *buffer, unsigned char *client_mac);

#endif
