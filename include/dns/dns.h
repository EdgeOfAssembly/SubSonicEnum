#ifndef DNS_H
#define DNS_H

#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// DNS header structure (12 bytes, packed)
typedef struct __attribute__((packed)) {
    uint16_t id;      // Query ID
    uint16_t flags;   // Flags (QR, RD, etc.)
    uint16_t qdcount; // Question count
    uint16_t ancount; // Answer count
    uint16_t nscount; // Authority count
    uint16_t arcount; // Additional count
} dns_header_t;

// Create DNS A query packet
// Inputs: buffer (output), subdomain, target (e.g., "example", "com"), id, qtype (1 for A)
// Returns: length of query packet, or 0 on error
int create_dns_query(char* buffer, const char* subdomain, const char* target, uint16_t id, uint16_t qtype);

// Parse DNS response for A record
// Inputs: buffer (response), len (response length), record_data (output for IP), record_len (output for IP length)
// Returns: 1 if a valid A record is found, 0 otherwise
int parse_dns_response(const char* buffer, int len, char* record_data, int* record_len);

#ifdef __cplusplus
}
#endif

#endif // DNS_H