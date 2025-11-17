/**
 * NetForge - Ethernet Layer Implementation
 * Helper functions for Ethernet frame management
 */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "protocols.h"

/**
 * Ethernet helper functions
 * This file can be expanded with Ethernet-specific utilities
 */

// Ethernet protocol numbers
#define ETH_P_IP   0x0800  // Internet Protocol
#define ETH_P_ARP  0x0806  // Address Resolution Protocol
#define ETH_P_IPV6 0x86DD  // IPv6 Protocol

// Utility function to print MAC address
void print_mac_address(const char *label, unsigned char *mac) {
    printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           label, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
