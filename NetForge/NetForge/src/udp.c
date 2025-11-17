/**
 * NetForge - UDP Protocol Implementation
 * Handles UDP datagram construction for connectionless communication
 */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "protocols.h"

// UDP header structure
struct udp_header {
    uint16_t source;    // Source port
    uint16_t dest;      // Destination port  
    uint16_t len;       // Length
    uint16_t check;     // Checksum
};

/**
 * Create UDP datagram with payload
 * Implements RFC 768 User Datagram Protocol
 */
int create_udp_packet(unsigned char *buffer,
                     uint16_t src_port, uint16_t dest_port,
                     unsigned char *payload, int payload_len) {
    
    struct udp_header *udp = (struct udp_header *)buffer;
    
    // Fill UDP header
    udp->source = htons(src_port);                    // Source port
    udp->dest = htons(dest_port);                     // Destination port
    udp->len = htons(sizeof(struct udp_header) + payload_len);  // Length
    udp->check = 0;                                   // Checksum (optional for IPv4)
    
    // Copy payload after UDP header
    if (payload && payload_len > 0) {
        memcpy(buffer + sizeof(struct udp_header), payload, payload_len);
    }
    
    return sizeof(struct udp_header) + payload_len;
}
