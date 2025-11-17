#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "protocols.h"

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

int create_ipv4_packet(unsigned char *buffer, 
                      uint32_t src_ip, uint32_t dest_ip,
                      uint8_t protocol, uint8_t ttl,
                      unsigned char *payload, int payload_len) {
    
    struct iphdr *ip = (struct iphdr *)buffer;
    
    // Fill IP header
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + payload_len);
    ip->id = htons(54321);
    ip->frag_off = 0;
    ip->ttl = ttl;
    ip->protocol = protocol;
    ip->saddr = src_ip;
    ip->daddr = dest_ip;
    ip->check = 0;
    
    // Calculate IP checksum
    ip->check = calculate_checksum((unsigned short*)ip, sizeof(struct iphdr));
    
    // Copy payload
    memcpy(buffer + sizeof(struct iphdr), payload, payload_len);
    
    return sizeof(struct iphdr) + payload_len;
}
