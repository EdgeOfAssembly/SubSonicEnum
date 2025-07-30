#include "dns/dns.h"
#include "ui/progress_bar.h" // Include provided progress bar header
#include <cuda_runtime.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/socket.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <poll.h>

// Allowed characters for subdomains
__constant__ char d_allowed_chars[] = "abcdefghijklmnopqrstuvwxyz0123456789-";
const int num_chars = 37;
const int max_len = 5;
const int batch_size = 256; // Reduced to avoid rate limiting

// DNS resolvers
const char* resolvers[] = {"8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.4.4", "1.0.0.1", "1.0.0.2"};
const int num_resolvers = 6;
int active_resolvers[num_resolvers];
int num_active_resolvers = 0;

// Wildcard detection
char wildcard_response[512];
int wildcard_response_len = 0;
bool has_wildcard = false;

// Random delay range (milliseconds)
const int min_delay_ms = 200;
const int max_delay_ms = 1000;

// Buffer sizes
const int buffer_size = 262144;

// Global query ID counter
static uint16_t global_query_id = 0;

#define CUDA_CHECK(err) do { \
    if (err != cudaSuccess) { \
        fprintf(stderr, "CUDA Error: %s at %s:%d\n", cudaGetErrorString(err), __FILE__, __LINE__); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

#define SOCK_CHECK(err, msg) do { \
    if (err < 0) { \
        fprintf(stderr, "%s: %s\n", msg, strerror(errno)); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

// CUDA kernel to generate subdomains
__global__ void generate_subdomains(char* output_buffer, unsigned long long start_idx, int max_len, int num_chars) {
    unsigned long long idx = blockIdx.x * blockDim.x + threadIdx.x + start_idx;
    if (idx >= start_idx + batch_size) return;

    int len = 0;
    unsigned long long combo_idx = idx;
    unsigned long long total = 0;
    for (int i = 1; i <= max_len; ++i) {
        unsigned long long combos = 1ULL;
        for (int j = 0; j < i; ++j) combos *= num_chars;
        total += combos;
        if (idx < total) {
            len = i;
            combo_idx = idx - (total - combos);
            break;
        }
    }
    if (len == 0) return;

    char subdomain[64];
    for (int i = 0; i < len; ++i) {
        subdomain[i] = d_allowed_chars[combo_idx % num_chars];
        combo_idx /= num_chars;
    }
    subdomain[len] = '\0';

    if (subdomain[0] != '-' && (len == 1 || subdomain[len - 1] != '-')) {
        unsigned long long output_offset = (idx - start_idx) * 64;
        for (int i = 0; i <= len; ++i) {
            output_buffer[output_offset + i] = subdomain[i];
        }
    }
}

// Test resolver with blocking socket and poll
bool test_resolver(const char* ip, int sock) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid resolver IP: %s\n", ip);
        return false;
    }

    // Bind socket
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = 0;
    if (bind(sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        fprintf(stderr, "Bind failed for %s: %s\n", ip, strerror(errno));
        return false;
    }

    // Ensure blocking mode
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);

    char query[512];
    int query_len = create_dns_query(query, "example", "com", 0x1234, 1);
    if (query_len == 0) {
        fprintf(stderr, "Failed to create DNS query for %s\n", ip);
        return false;
    }

#ifndef NDEBUG
    // Log raw query
    printf("Raw query for %s: ", ip);
    for (int i = 0; i < query_len; ++i) {
        printf("%02x ", (unsigned char)query[i]);
    }
    printf("\n");
#endif

    const int max_retries = 3;
    for (int retry = 0; retry < max_retries; ++retry) {
        int sent = sendto(sock, query, query_len, 0, (struct sockaddr*)&addr, sizeof(addr));
        if (sent < 0) {
            fprintf(stderr, "sendto failed for %s (retry %d): %s\n", ip, retry, strerror(errno));
            continue;
        }

        struct pollfd pfd = {sock, POLLIN, 0};
        int timeout_ms = 10000; // 10s
        int polled = poll(&pfd, 1, timeout_ms);
        if (polled < 0) {
            fprintf(stderr, "poll failed for %s (retry %d): %s\n", ip, retry, strerror(errno));
            continue;
        }
        if (polled == 0) {
            fprintf(stderr, "poll timeout for %s (retry %d)\n", ip, retry);
            continue;
        }

        char response[512];
        int recvd = recvfrom(sock, response, sizeof(response), 0, NULL, NULL);
        if (recvd > 0) {
            char record_data[256];
            int record_len;
            int result = parse_dns_response(response, recvd, record_data, &record_len);
            if (result == 1) {
#ifndef NDEBUG
                printf("Successfully parsed DNS response for %s: %d bytes\n", ip, record_len);
#endif
                return true;
            } else if (result == -1) {
                fprintf(stderr, "NXDOMAIN for %s (retry %d)\n", ip, retry);
            } else {
                fprintf(stderr, "Failed to parse DNS response for %s, received %d bytes\n", ip, recvd);
#ifndef NDEBUG
                fprintf(stderr, "Raw response: ");
                for (int i = 0; i < recvd; ++i) fprintf(stderr, "%02x ", (unsigned char)response[i]);
                fprintf(stderr, "\n");
#endif
            }
        } else {
            fprintf(stderr, "recvfrom failed for %s (retry %d): %s\n", ip, retry, strerror(errno));
        }
        usleep(500000); // 500ms delay between retries
    }
    return false;
}

// Detect wildcard
void detect_wildcard(const char* target, int* socks, struct sockaddr_in* dns_servers, int num_servers) {
    srand(time(NULL));
    char random_subdomain[20];
    const char* allowed_chars = "abcdefghijklmnopqrstuvwxyz0123456789-";
    int attempts = 0;
    const int max_attempts = 10;

    while (attempts < max_attempts) {
        // Generate random subdomain
        for (int j = 0; j < 15; ++j) {
            random_subdomain[j] = allowed_chars[rand() % num_chars];
        }
        random_subdomain[15] = '\0';
#ifndef NDEBUG
        printf("Testing wildcard: %s.%s\n", random_subdomain, target);
#endif

        char query[512];
        int query_len = create_dns_query(query, random_subdomain, target, global_query_id++, 1);
        if (query_len == 0) {
            fprintf(stderr, "Failed to create wildcard query for %s\n", random_subdomain);
            attempts++;
            continue;
        }

        struct msghdr msg = {0};
        struct iovec iov = {query, (size_t)query_len};
        msg.msg_name = &dns_servers[attempts % num_servers];
        msg.msg_namelen = sizeof(struct sockaddr_in);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        int sent = sendmsg(socks[attempts % num_servers], &msg, 0);
        if (sent < 0) {
            fprintf(stderr, "Wildcard sendmsg failed for %s: %s\n", random_subdomain, strerror(errno));
            attempts++;
            continue;
        }

        char response[512];
        struct iovec response_iov = {response, sizeof(response)};
        struct msghdr response_msg = {0};
        response_msg.msg_name = &dns_servers[attempts % num_servers];
        response_msg.msg_namelen = sizeof(struct sockaddr_in);
        response_msg.msg_iov = &response_iov;
        response_msg.msg_iovlen = 1;

        // Use poll for blocking receive
        struct pollfd pfd = {socks[attempts % num_servers], POLLIN, 0};
        int timeout_ms = 2000; // 2s
        int polled = poll(&pfd, 1, timeout_ms);
        if (polled <= 0) {
            fprintf(stderr, "Wildcard poll %s for %s.%s\n", polled == 0 ? "timeout" : "failed", random_subdomain, target);
            attempts++;
            continue;
        }

        int recvd = recvmsg(socks[attempts % num_servers], &response_msg, 0);
        if (recvd > 0) {
            char record_data[256];
            int record_len;
            int result = parse_dns_response(response, recvd, record_data, &record_len);
            if (result == 1) {
                memcpy(wildcard_response, record_data, record_len);
                wildcard_response_len = record_len;
                has_wildcard = true;
                printf("Wildcard detected for *.%s with IP: %d.%d.%d.%d\n", target,
                       (unsigned char)record_data[0], (unsigned char)record_data[1],
                       (unsigned char)record_data[2], (unsigned char)record_data[3]);
                return;
            } else if (result == -1) {
                // NXDOMAIN is expected for non-wildcard domains
                attempts++;
            } else {
                fprintf(stderr, "Failed to parse wildcard response for %s.%s, received %d bytes\n", random_subdomain, target, recvd);
            }
        } else {
            fprintf(stderr, "Wildcard recvmsg failed for %s.%s: %s\n", random_subdomain, target, strerror(errno));
            attempts++;
        }
    }

    printf("No wildcard detected for *.%s after %d attempts\n", target, max_attempts);
}

// Match response ID to query ID
bool check_response_id(const char* response, int recvd, uint16_t query_id) {
    if (recvd < sizeof(dns_header_t)) return false;
    dns_header_t* header = (dns_header_t*)response;
    bool match = ntohs(header->id) == query_id;
#ifndef NDEBUG
    if (!match) {
        printf("ID mismatch: expected %u, got %u\n", query_id, ntohs(header->id));
    }
#endif
    return match;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <target_hostname>\n", argv[0]);
        return 1;
    }
    const char* target = argv[1];

    // Set process priority
    errno = 0;
    int nice_val = nice(-5);
    if (nice_val == -1 && errno != 0) {
        fprintf(stderr, "Warning: Failed to set nice value to -5 (%s)\n", strerror(errno));
    } else {
#ifndef NDEBUG
        printf("Set process nice value to %d\n", nice_val);
#endif
    }

    // Seed random number generator
    srand(time(NULL));

    // Initialize sockets
    int socks[num_resolvers];
    for (int i = 0; i < num_resolvers; ++i) {
        socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
        SOCK_CHECK(socks[i], "socket creation failed");
        int opt = 1;
        setsockopt(socks[i], SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        int mtu_opt = IP_PMTUDISC_DO;
        setsockopt(socks[i], IPPROTO_IP, IP_MTU_DISCOVER, &mtu_opt, sizeof(mtu_opt));
        setsockopt(socks[i], SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size));
        setsockopt(socks[i], SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size));
        // Ensure blocking mode
        int flags = fcntl(socks[i], F_GETFL, 0);
        fcntl(socks[i], F_SETFL, flags & ~O_NONBLOCK);
    }

    // Test resolvers
    for (int i = 0; i < num_resolvers; ++i) {
        if (test_resolver(resolvers[i], socks[i])) {
            active_resolvers[num_active_resolvers++] = i;
#ifndef NDEBUG
            printf("Resolver %s is active\n", resolvers[i]);
#endif
        } else {
#ifndef NDEBUG
            printf("Resolver %s is inactive\n", resolvers[i]);
#endif
            close(socks[i]);
            socks[i] = -1;
        }
    }
    if (num_active_resolvers == 0) {
        fprintf(stderr, "No active resolvers found\n");
        for (int i = 0; i < num_resolvers; ++i) {
            if (socks[i] >= 0) close(socks[i]);
        }
        return 1;
    }

    // Set up DNS server addresses
    struct sockaddr_in dns_servers[num_active_resolvers];
    for (int i = 0; i < num_active_resolvers; ++i) {
        memset(&dns_servers[i], 0, sizeof(dns_servers[i]));
        dns_servers[i].sin_family = AF_INET;
        dns_servers[i].sin_port = htons(53);
        inet_pton(AF_INET, resolvers[active_resolvers[i]], &dns_servers[i].sin_addr);
    }

    // Detect wildcard
    detect_wildcard(target, socks, dns_servers, num_active_resolvers);

    // Open output file
    FILE* output_file = fopen("valid_subdomains.txt", "w");
    if (!output_file) {
        fprintf(stderr, "Failed to open output file: %s\n", strerror(errno));
        for (int i = 0; i < num_resolvers; ++i) {
            if (socks[i] >= 0) close(socks[i]);
        }
        return 1;
    }

    // CUDA setup
    cudaStream_t stream;
    CUDA_CHECK(cudaStreamCreate(&stream));
    char* h_output_buffer = (char*)malloc(batch_size * 64 * sizeof(char));
    char* d_output_buffer;
    CUDA_CHECK(cudaMalloc(&d_output_buffer, batch_size * 64 * sizeof(char)));

    // DNS query buffers
    char query_buffers[batch_size][512];
    struct mmsghdr send_msgs[batch_size];
    struct mmsghdr recv_msgs[batch_size];
    struct iovec send_iovecs[batch_size];
    struct iovec recv_iovecs[batch_size];
    struct sockaddr_in addrs[batch_size];
    char response_buffers[batch_size][512];
    uint16_t query_ids[batch_size]; // Store query IDs
    int query_sockets[batch_size];   // Store socket index for each query
    char subdomains[batch_size][64]; // Store subdomains for matching
    int id_mismatches = 0;           // Track mismatches per batch
    int timeouts = 0;                // Track timeouts per batch

    // Main loop
    unsigned long long start_idx = 0;
    unsigned long long max_combinations = 0;
    for (int i = 1; i <= max_len; ++i) {
        max_combinations += (i == 1 ? 37 : 36 * 36 * (unsigned long long)pow(37, i-2));
    }
#ifndef NDEBUG
    printf("Total combinations to test: %llu\n", max_combinations);
#endif

    // Initialize progress bar
    char progress_message[128];
    snprintf(progress_message, sizeof(progress_message), "Querying %s.%s", "", target);
    progress_bar(progress_message, start_idx, max_combinations);

    while (start_idx < max_combinations) {
        // Update progress bar
        snprintf(progress_message, sizeof(progress_message), "Querying %s.%s", subdomains[0][0] ? subdomains[0] : "", target);
        progress_bar(progress_message, start_idx, max_combinations);

        // Generate subdomains
        int threads_per_block = 256;
        int blocks = (batch_size + threads_per_block - 1) / threads_per_block;
        generate_subdomains<<<blocks, threads_per_block, 0, stream>>>(d_output_buffer, start_idx, max_len, num_chars);
        CUDA_CHECK(cudaStreamSynchronize(stream));
        CUDA_CHECK(cudaMemcpyAsync(h_output_buffer, d_output_buffer, batch_size * 64 * sizeof(char), cudaMemcpyDeviceToHost, stream));
        CUDA_CHECK(cudaStreamSynchronize(stream));

        // Log generated subdomains
        int valid_subdomains = 0;
        for (int i = 0; i < batch_size; ++i) {
            char* subdomain = &h_output_buffer[i * 64];
            if (subdomain[0] != '\0' && strcmp(subdomain, "") != 0) {
#ifndef NDEBUG
                if (valid_subdomains < 5) { // Limit logging to first 5 for brevity
                    printf("Generated subdomain: %s.%s\n", subdomain, target);
                }
#endif
                valid_subdomains++;
            }
        }
#ifndef NDEBUG
        printf("Total valid subdomains in batch: %d\n", valid_subdomains);
#endif

        // Prepare DNS queries
        int valid_queries = 0;
        id_mismatches = 0;
        timeouts = 0;
        for (int i = 0; i < batch_size; ++i) {
            char* subdomain = &h_output_buffer[i * 64];
            if (subdomain[0] == '\0' || strcmp(subdomain, "") == 0) continue; // Skip empty subdomains

            query_ids[valid_queries] = global_query_id++; // Unique query ID
            query_sockets[valid_queries] = active_resolvers[valid_queries % num_active_resolvers]; // Assign resolver
            strncpy(subdomains[valid_queries], subdomain, 64); // Store subdomain
            int query_len = create_dns_query(query_buffers[valid_queries], subdomain, target, query_ids[valid_queries], 1);
            if (query_len == 0) continue;
            send_iovecs[valid_queries].iov_base = query_buffers[valid_queries];
            send_iovecs[valid_queries].iov_len = query_len;
            send_msgs[valid_queries].msg_hdr.msg_iov = &send_iovecs[valid_queries];
            send_msgs[valid_queries].msg_hdr.msg_iovlen = 1;
            send_msgs[valid_queries].msg_hdr.msg_name = &addrs[valid_queries];
            send_msgs[valid_queries].msg_hdr.msg_namelen = sizeof(addrs[valid_queries]);
            memcpy(&addrs[valid_queries], &dns_servers[valid_queries % num_active_resolvers], sizeof(struct sockaddr_in));
            // Prepare receive message
            recv_iovecs[valid_queries].iov_base = response_buffers[valid_queries];
            recv_iovecs[valid_queries].iov_len = sizeof(response_buffers[valid_queries]);
            recv_msgs[valid_queries].msg_hdr.msg_iov = &recv_iovecs[valid_queries];
            recv_msgs[valid_queries].msg_hdr.msg_iovlen = 1;
            recv_msgs[valid_queries].msg_hdr.msg_name = &addrs[valid_queries];
            recv_msgs[valid_queries].msg_hdr.msg_namelen = sizeof(addrs[valid_queries]);
            recv_msgs[valid_queries].msg_hdr.msg_control = NULL;
            recv_msgs[valid_queries].msg_hdr.msg_controllen = 0;
            valid_queries++;
        }
#ifndef NDEBUG
        printf("Prepared %d valid queries\n", valid_queries);
#endif

        // Send and receive queries synchronously
        int sent_queries = 0;
        int received_responses = 0;
        if (valid_queries > 0) {
            // Send queries
            for (int i = 0; i < valid_queries; i += num_active_resolvers) {
                int batch_size = (valid_queries - i < num_active_resolvers) ? valid_queries - i : num_active_resolvers;
                for (int j = 0; j < batch_size; ++j) {
                    int idx = i + j;
                    int sock_idx = query_sockets[idx];
                    int sent = sendmsg(socks[sock_idx], &send_msgs[idx].msg_hdr, 0);
                    if (sent < 0) {
                        fprintf(stderr, "sendmsg failed for query %d (%s.%s): %s\n",
                                idx, subdomains[idx], target, strerror(errno));
                        continue;
                    }
                    sent_queries++;
                }

                // Receive responses
                for (int attempt = 0; attempt < 3 && received_responses < sent_queries; ++attempt) {
                    for (int j = 0; j < batch_size; ++j) {
                        int idx = i + j;
                        int sock_idx = query_sockets[idx];
                        struct pollfd pfd = {socks[sock_idx], POLLIN, 0};
                        int timeout_ms = 15000; // 15s timeout
                        int polled = poll(&pfd, 1, timeout_ms);
                        if (polled <= 0) {
                            timeouts++;
#ifndef NDEBUG
                            printf("Poll %s for query %d (%s.%s)\n",
                                   polled == 0 ? "timeout" : "failed", idx, subdomains[idx], target);
#endif
                            continue;
                        }

                        int recvd = recvmsg(socks[sock_idx], &recv_msgs[idx].msg_hdr, 0);
                        if (recvd > 0) {
                            if (!check_response_id(response_buffers[idx], recvd, query_ids[idx])) {
                                id_mismatches++;
#ifndef NDEBUG
                                printf("Skipped response for %s.%s: ID mismatch\n", subdomains[idx], target);
#endif
                                continue;
                            }
                            char record_data[256];
                            int record_len;
                            int result = parse_dns_response(response_buffers[idx], recvd, record_data, &record_len);
                            if (result == 1) {
                                if (!has_wildcard || memcmp(record_data, wildcard_response, record_len) != 0) {
                                    if (subdomains[idx][0] != '\0') { // Ensure valid subdomain
                                        fprintf(output_file, "Valid subdomain: %s.%s\n", subdomains[idx], target);
                                        printf("Valid subdomain: %s.%s\n", subdomains[idx], target); // Removed leading \n
                                        fflush(stdout); // Ensure immediate display
                                    }
                                }
                                received_responses++;
                            } else if (result == -1) {
                                // NXDOMAIN or no A records: silently skip
                                received_responses++;
                            } else {
                                fprintf(stderr, "Malformed response for query %d (%s.%s), received %d bytes\n",
                                        idx, subdomains[idx], target, recvd);
                            }
                        } else {
                            fprintf(stderr, "recvmsg failed for query %d (%s.%s): %s\n",
                                    idx, subdomains[idx], target, strerror(errno));
                        }
                    }
                    if (received_responses < sent_queries && attempt < 2) {
#ifndef NDEBUG
                        printf("Retrying receive, attempt %d, %d responses of %d sent queries\n",
                               attempt + 1, received_responses, sent_queries);
#endif
                        usleep(500000); // 500ms delay before retry
                    }
                }
            }
        }
        printf("Sent %d queries, received %d responses, %d timeouts, %d ID mismatches\n",
               sent_queries, received_responses, timeouts, id_mismatches);
        fflush(stdout); // Ensure query stats are displayed immediately

        // Random delay
        int delay_ms = min_delay_ms + (rand() % (max_delay_ms - min_delay_ms + 1));
        struct timespec delay = {0, delay_ms * 1000000};
        nanosleep(&delay, NULL);

        start_idx += batch_size;
    }

    // Final progress bar update
    snprintf(progress_message, sizeof(progress_message), "Completed");
    progress_bar(progress_message, max_combinations, max_combinations);

    // Cleanup
    free(h_output_buffer);
    CUDA_CHECK(cudaFree(d_output_buffer));
    CUDA_CHECK(cudaStreamDestroy(stream));
    for (int i = 0; i < num_resolvers; ++i) {
        if (socks[i] >= 0) close(socks[i]);
    }
    fclose(output_file);
    return 0;
}
