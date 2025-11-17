#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "protocols.h"

struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
};

int create_icmp_echo_request(unsigned char *buffer, 
                            uint16_t id, uint16_t sequence,
                            unsigned char *data, int data_len) {
    
    struct icmp_header *icmp = (struct icmp_header *)buffer;
    
    icmp->type = 8;  // Echo Request
    icmp->code = 0;
    icmp->checksum = 0;
    icmp->id = htons(id);
    icmp->sequence = htons(sequence);
    
    // Add some data
    if (data && data_len > 0) {
        memcpy(buffer + sizeof(struct icmp_header), data, data_len);
    } else {
        // Default ping data
        memset(buffer + sizeof(struct icmp_header), 'A', 56);
        data_len = 56;
    }
    
    // Calculate ICMP checksum
    icmp->checksum = calculate_checksum((unsigned short*)buffer, 
                                       sizeof(struct icmp_header) + data_len);
    
    return sizeof(struct icmp_header) + data_len;
}
