/**
 * NetForge - TCP Protocol Implementation
 * Handles TCP segment construction with configurable flags
 */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "protocols.h"

// TCP header structure
struct tcp_header {
    uint16_t source;      // Source port
    uint16_t dest;        // Destination port
    uint32_t seq;         // Sequence number
    uint32_t ack_seq;     // Acknowledgment number
    uint16_t res1:4,      // Reserved
             doff:4,      // Data offset
             fin:1,       // FIN flag
             syn:1,       // SYN flag  
             rst:1,       // RST flag
             psh:1,       // PSH flag
             ack:1,       // ACK flag
             urg:1,       // URG flag
             ece:1,       // ECN-Echo
             cwr:1;       // Congestion Window Reduced
    uint16_t window;      // Window size
    uint16_t check;       // Checksum
    uint16_t urg_ptr;     // Urgent pointer
};

/**
 * Create TCP segment with specified flags and options
 * Implements RFC 793 Transmission Control Protocol
 */
int create_tcp_packet(unsigned char *buffer,
                     uint16_t src_port, uint16_t dest_port,
                     uint32_t seq_num, uint32_t ack_num,
                     uint8_t flags, unsigned char *payload, int payload_len) {
    
    struct tcp_header *tcp = (struct tcp_header *)buffer;
    
    // Fill TCP header
    tcp->source = htons(src_port);        // Source port
    tcp->dest = htons(dest_port);         // Destination port
    tcp->seq = htonl(seq_num);            // Sequence number
    tcp->ack_seq = htonl(ack_num);        // Acknowledgment number
    tcp->doff = 5;                        // Data offset (5 * 4 = 20 bytes)
    tcp->window = htons(5840);            // Window size
    tcp->check = 0;                       // Checksum (0 for now)
    tcp->urg_ptr = 0;                     // Urgent pointer
    
    // Set TCP flags based on input
    tcp->fin = (flags & 0x01) ? 1 : 0;    // FIN - No more data from sender
    tcp->syn = (flags & 0x02) ? 1 : 0;    // SYN - Synchronize sequence numbers
    tcp->rst = (flags & 0x04) ? 1 : 0;    // RST - Reset connection
    tcp->psh = (flags & 0x08) ? 1 : 0;    // PSH - Push function
    tcp->ack = (flags & 0x10) ? 1 : 0;    // ACK - Acknowledgment field significant
    tcp->urg = (flags & 0x20) ? 1 : 0;    // URG - Urgent pointer field significant
    
    // Copy payload after TCP header
    if (payload && payload_len > 0) {
        memcpy(buffer + sizeof(struct tcp_header), payload, payload_len);
    }
    
    return sizeof(struct tcp_header) + payload_len;
}
