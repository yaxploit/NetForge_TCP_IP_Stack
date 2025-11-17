#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "protocols.h"

struct tcp_header {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

int create_tcp_packet(unsigned char *buffer,
                     uint16_t src_port, uint16_t dest_port,
                     uint32_t seq_num, uint32_t ack_num,
                     uint8_t flags, unsigned char *payload, int payload_len) {
    
    struct tcp_header *tcp = (struct tcp_header *)buffer;
    
    tcp->source = htons(src_port);
    tcp->dest = htons(dest_port);
    tcp->seq = htonl(seq_num);
    tcp->ack_seq = htonl(ack_num);
    tcp->doff = 5;  // Data offset: 5 * 4 = 20 bytes
    tcp->window = htons(5840);
    tcp->check = 0;
    tcp->urg_ptr = 0;
    
    // Set flags
    tcp->fin = (flags & 0x01) ? 1 : 0;
    tcp->syn = (flags & 0x02) ? 1 : 0;
    tcp->rst = (flags & 0x04) ? 1 : 0;
    tcp->psh = (flags & 0x08) ? 1 : 0;
    tcp->ack = (flags & 0x10) ? 1 : 0;
    tcp->urg = (flags & 0x20) ? 1 : 0;
    
    // Copy payload
    if (payload && payload_len > 0) {
        memcpy(buffer + sizeof(struct tcp_header), payload, payload_len);
    }
    
    return sizeof(struct tcp_header) + payload_len;
}
