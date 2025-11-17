/**
 * NetForge - ICMP Protocol Implementation
 * Handles ICMP Echo Request (ping) functionality
 */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "protocols.h"

// ICMP header structure
struct icmp_header {
    uint8_t type;        // Message type (8=Echo Request, 0=Echo Reply)
    uint8_t code;        // Message code
    uint16_t checksum;   // Checksum
    uint16_t id;         // Identification
    uint16_t sequence;   // Sequence number
};

/**
 * Create ICMP Echo Request (ping) packet
 * Implements RFC 792 Internet Control Message Protocol
 */
int create_icmp_echo_request(unsigned char *buffer, 
                            uint16_t id, uint16_t sequence,
                            unsigned char *data, int data_len) {
    
    struct icmp_header *icmp = (struct icmp_header *)buffer;
    
    // Fill ICMP header
    icmp->type = 8;        // Echo Request
    icmp->code = 0;        // Code 0 for Echo Request
    icmp->checksum = 0;    // Initialize checksum to 0
    icmp->id = htons(id);  // Identification
    icmp->sequence = htons(sequence);  // Sequence number
    
    // Add payload data (optional)
    if (data && data_len > 0) {
        memcpy(buffer + sizeof(struct icmp_header), data, data_len);
    } else {
        // Default ping data (56 bytes as in standard ping)
        memset(buffer + sizeof(struct icmp_header), 0x41, 56); // 'A' characters
        data_len = 56;
    }
    
    // Calculate ICMP checksum including data
    icmp->checksum = calculate_checksum((unsigned short*)buffer, 
                                       sizeof(struct icmp_header) + data_len);
    
    return sizeof(struct icmp_header) + data_len;
}
