/**
 * NetForge - HTTP Protocol Implementation
 * Handles HTTP request creation for web communication
 */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "protocols.h"

/**
 * Create HTTP GET request
 * Constructs complete HTTP/1.1 request with standard headers
 */
int create_http_request(unsigned char *buffer, const char *host, const char *path) {
    char http_header[1024];
    
    // Construct complete HTTP GET request
    int len = snprintf(http_header, sizeof(http_header),
                      "GET %s HTTP/1.1\r\n"
                      "Host: %s\r\n"
                      "User-Agent: NetForge/1.0\r\n"
                      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                      "Accept-Language: en-US,en;q=0.5\r\n"
                      "Accept-Encoding: gzip, deflate\r\n"
                      "Connection: close\r\n"
                      "\r\n",
                      path ? path : "/", host);
    
    // Copy to output buffer
    memcpy(buffer, http_header, len);
    return len;
}
