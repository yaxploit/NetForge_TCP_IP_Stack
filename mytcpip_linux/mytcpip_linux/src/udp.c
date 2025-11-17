#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "protocols.h"

struct udp_header {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};

int create_udp_packet(unsigned char *buffer,
                     uint16_t src_port, uint16_t dest_port,
                     unsigned char *payload, int payload_len) {
    
    struct udp_header *udp = (struct udp_header *)buffer;
    
    udp->source = htons(src_port);
    udp->dest = htons(dest_port);
    udp->len = htons(sizeof(struct udp_header) + payload_len);
    udp->check = 0;  // Optional for IPv4
    
    // Copy payload
    if (payload && payload_len > 0) {
        memcpy(buffer + sizeof(struct udp_header), payload, payload_len);
    }
    
    return sizeof(struct udp_header) + payload_len;
}
