#ifndef PROTOCOLS_H
#define PROTOCOLS_H

#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

// Forward declaration (no struct definition here)
struct stack_config;

// Ethernet functions
int send_ethernet_frame(struct stack_config *config, unsigned short ethertype, 
                       unsigned char *payload, int payload_len);

// IPv4 functions
unsigned short calculate_checksum(unsigned short *ptr, int nbytes);
int create_ipv4_packet(unsigned char *buffer, uint32_t src_ip, uint32_t dest_ip,
                      uint8_t protocol, uint8_t ttl, unsigned char *payload, int payload_len);

// ICMP functions
int create_icmp_echo_request(unsigned char *buffer, uint16_t id, uint16_t sequence,
                            unsigned char *data, int data_len);

// TCP functions
int create_tcp_packet(unsigned char *buffer, uint16_t src_port, uint16_t dest_port,
                     uint32_t seq_num, uint32_t ack_num, uint8_t flags,
                     unsigned char *payload, int payload_len);

// UDP functions  
int create_udp_packet(unsigned char *buffer, uint16_t src_port, uint16_t dest_port,
                     unsigned char *payload, int payload_len);

#endif
