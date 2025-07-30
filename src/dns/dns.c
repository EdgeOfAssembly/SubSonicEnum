#include "dns/dns.h"
#include <stdio.h>
#include <arpa/inet.h>

// Create DNS A query packet
int create_dns_query(char* buffer, const char* subdomain, const char* target, uint16_t id, uint16_t qtype) {
    char fqdn[256];
    snprintf(fqdn, sizeof(fqdn), "%s.%s", subdomain, target);

    dns_header_t* header = (dns_header_t*)buffer;
    header->id = htons(id);
    header->flags = htons(0x0100); // Standard query, recursion desired
    header->qdcount = htons(1);
    header->ancount = 0;
    header->nscount = 0;
    header->arcount = 0;

    char* qname = buffer + sizeof(dns_header_t);
    int qname_len = 0;
    const char* p = fqdn;
    while (*p) {
        const char* dot = strchr(p, '.');
        int len = dot ? dot - p : strlen(p);
        if (len > 63 || qname_len + len + 1 > 255) {
            fprintf(stderr, "Invalid domain length: %s\n", p);
            return 0;
        }
        qname[qname_len++] = len;
        memcpy(qname + qname_len, p, len);
        qname_len += len;
        p += len + (dot ? 1 : 0);
        if (!dot) break;
    }
    qname[qname_len++] = 0;

    *(uint16_t*)(qname + qname_len) = htons(qtype); // QTYPE (A=1)
    qname_len += 2;
    *(uint16_t*)(qname + qname_len) = htons(1); // QCLASS (IN=1)
    qname_len += 2;

    return sizeof(dns_header_t) + qname_len;
}

// Parse DNS response for A record
int parse_dns_response(const char* buffer, int len, char* record_data, int* record_len) {
    if (len < sizeof(dns_header_t)) {
        fprintf(stderr, "Response too short: %d bytes\n", len);
        return 0;
    }

    dns_header_t* header = (dns_header_t*)buffer;
    uint16_t flags = ntohs(header->flags);
    if ((flags & 0x000F) == 3) { // NXDOMAIN (RCODE 3)
        return -1; // Indicate non-existent domain
    }
    if ((flags & 0x000F) != 0) {
        fprintf(stderr, "DNS response error, RCODE: %d\n", flags & 0x000F);
        return 0;
    }

    int pos = sizeof(dns_header_t);
#ifndef NDEBUG
    printf("Parsing response: QDCOUNT=%d, ANCOUNT=%d, NSCOUNT=%d, ARCOUNT=%d\n",
           ntohs(header->qdcount), ntohs(header->ancount), ntohs(header->nscount), ntohs(header->arcount));
#endif

    // Parse question section
    int qdcount = ntohs(header->qdcount);
    for (int i = 0; i < qdcount && pos < len; ++i) {
#ifndef NDEBUG
        printf("Parsing question %d at pos %d\n", i, pos);
#endif
        while (pos < len && buffer[pos] != 0) {
            if ((buffer[pos] & 0xC0) == 0xC0) {
                if (pos + 1 >= len) {
                    fprintf(stderr, "Invalid compressed name in question at pos %d\n", pos);
                    return 0;
                }
#ifndef NDEBUG
                printf("Found compressed name at pos %d: %02x %02x\n", pos, (unsigned char)buffer[pos], (unsigned char)buffer[pos+1]);
#endif
                pos += 2;
                break;
            }
#ifndef NDEBUG
            printf("Name segment length %d at pos %d\n", buffer[pos], pos);
#endif
            pos += buffer[pos] + 1;
        }
        pos += 1; // Skip null byte
        if (pos + 4 > len) {
            fprintf(stderr, "Invalid question section at pos %d\n", pos);
            return 0;
        }
        uint16_t qtype = ntohs(*(uint16_t*)(buffer + pos));
        uint16_t qclass = ntohs(*(uint16_t*)(buffer + pos + 2));
#ifndef NDEBUG
        printf("Question QTYPE=%d, QCLASS=%d at pos %d\n", qtype, qclass, pos);
#endif
        pos += 4; // Skip QTYPE, QCLASS
    }

    // Parse answer section
    int ancount = ntohs(header->ancount);
    if (ancount == 0) {
        return -1; // No A records, treat as NXDOMAIN
    }

    for (int i = 0; i < ancount && pos < len; ++i) {
#ifndef NDEBUG
        printf("Parsing answer %d at pos %d\n", i, pos);
#endif
        // Parse name
        int is_compressed = 0;
        while (pos < len && buffer[pos] != 0) {
            if ((buffer[pos] & 0xC0) == 0xC0) {
                if (pos + 1 >= len) {
                    fprintf(stderr, "Invalid compressed name in answer at pos %d\n", pos);
                    return 0;
                }
#ifndef NDEBUG
                printf("Found compressed name at pos %d: %02x %02x\n", pos, (unsigned char)buffer[pos], (unsigned char)buffer[pos+1]);
#endif
                is_compressed = 1;
                pos += 2;
                break;
            }
#ifndef NDEBUG
            printf("Name segment length %d at pos %d\n", buffer[pos], pos);
#endif
            pos += buffer[pos] + 1;
        }
        if (!is_compressed) pos += 1; // Skip null byte for non-compressed names
#ifndef NDEBUG
        printf("Name parsing ended at pos %d\n", pos);
#endif

        if (pos + 10 > len) {
            fprintf(stderr, "Invalid answer section, pos: %d, len: %d\n", pos, len);
            return 0;
        }
        uint16_t type = ntohs(*(uint16_t*)(buffer + pos));
        uint16_t class_ = ntohs(*(uint16_t*)(buffer + pos + 2));
        uint32_t ttl = ntohl(*(uint32_t*)(buffer + pos + 4));
        uint16_t rdlength = ntohs(*(uint16_t*)(buffer + pos + 8));
#ifndef NDEBUG
        printf("Answer TYPE=%d, CLASS=%d, TTL=%u, RDLENGTH=%d at pos %d\n", type, class_, ttl, rdlength, pos);
#endif

        if (pos + 10 + rdlength > len) {
            fprintf(stderr, "Invalid RDLENGTH, pos: %d, rdlength: %d, len: %d\n", pos + 10, rdlength, len);
            return 0;
        }
        if (type == 1) { // A record
            if (rdlength != 4) {
                fprintf(stderr, "Unexpected RDLENGTH %d for A record\n", rdlength);
                pos += 10 + rdlength;
                continue;
            }
            memcpy(record_data, buffer + pos + 10, rdlength);
            *record_len = rdlength;
#ifndef NDEBUG
            printf("Parsed A record, class %d, length %d, IP: %d.%d.%d.%d\n",
                   class_, rdlength,
                   (unsigned char)record_data[0], (unsigned char)record_data[1],
                   (unsigned char)record_data[2], (unsigned char)record_data[3]);
#endif
            return 1;
        }
        pos += 10 + rdlength;
    }

    return -1; // No valid A records
}
