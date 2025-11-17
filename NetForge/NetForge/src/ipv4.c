/**
 * NetForge - IPv4 Protocol Implementation
 * Handles IP packet construction and checksum calculation
 */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "protocols.h"

/**
 * Calculate Internet checksum for protocol headers
 * Used by IP, ICMP, TCP, and UDP for data integrity
 */
unsigned short calculate_checksum(unsigned short *ptr, int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char*)&oddbyte) = *(unsigned char*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    
    return answer;
}

/**
 * Create complete IPv4 packet with header and payload
 * Implements RFC 791 Internet Protocol specification
 */
int create_ipv4_packet(unsigned char *buffer, 
                      uint32_t src_ip, uint32_t dest_ip,
                      uint8_t protocol, uint8_t ttl,
                      unsigned char *payload, int payload_len) {
    
    struct iphdr *ip = (struct iphdr *)buffer;
    
    // Fill IP header according to RFC 791
    ip->version = 4;                    // IPv4
    ip->ihl = 5;                        // Internet Header Length (5 * 4 = 20 bytes)
    ip->tos = 0;                        // Type of Service
    ip->tot_len = htons(sizeof(struct iphdr) + payload_len);
    ip->id = htons(54321);              // Identification
    ip->frag_off = 0;                   // Fragment offset
    ip->ttl = ttl;                      // Time To Live
    ip->protocol = protocol;            // Protocol (TCP=6, UDP=17, ICMP=1)
    ip->saddr = src_ip;                 // Source address
    ip->daddr = dest_ip;                // Destination address
    ip->check = 0;                      // Checksum (calculated below)
    
    // Calculate IP header checksum
    ip->check = calculate_checksum((unsigned short*)ip, sizeof(struct iphdr));
    
    // Copy payload after IP header
    if (payload && payload_len > 0) {
        memcpy(buffer + sizeof(struct iphdr), payload, payload_len);
    }
    
    return sizeof(struct iphdr) + payload_len;
}
