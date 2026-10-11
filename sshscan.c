/*
 * sshscan.c - fast, multithreaded SSH host finder for your LAN (macOS/Linux)
 *
 * Build:  cc -O2 -pthread -o sshscan sshscan.c
 *
 * Usage:  ./sshscan [-c CIDR] [-m match] [-f fingerprint] [-p port] [-t timeout_ms] [-j threads]
 *
 *   -c  subnet to scan, e.g. 192.168.1.0/24  (default: auto-detect from your interface)
 *   -m  only show hosts whose IP, hostname or SSH banner contains this text
 *       (case-insensitive), e.g. -m raspberry, -m ubuntu, -m 192.168.1.4
 *   -f  only show the host whose SSH host key fingerprint matches, e.g.
 *       -f SHA256:abc123...   (also accepts MD5:aa:bb:... legacy fingerprints)
 *       Uses ssh-keyscan + ssh-keygen, which ship with macOS.
 *   -p  port (default 22)
 *   -t  per-stage timeout in ms (default 600)
 *   -j  worker threads (default 128)
 *
 * How it's fast: a pool of threads pulls IPs from a shared atomic counter, and each
 * one does a non-blocking connect() with poll() timeouts, so a /24 finishes in about
 * one timeout period instead of 254 * timeout.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <time.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

static uint32_t g_first;            /* first host (host byte order) */
static uint32_t g_count;            /* number of hosts to scan */
static atomic_uint g_next;          /* next index to claim */
static atomic_uint g_found;
static int g_port = 22;
static int g_timeout_ms = 600;
static const char *g_match = NULL;
static const char *g_fp = NULL;     /* host key fingerprint to match */
static pthread_mutex_t g_print = PTHREAD_MUTEX_INITIALIZER;

/* wait for fd to become ready; returns >0 ready, 0 timeout, <0 error */
static int wait_fd(int fd, short events, int ms) {
    struct pollfd p = { .fd = fd, .events = events };
    int r;
    do { r = poll(&p, 1, ms); } while (r < 0 && errno == EINTR);
    return r;
}

/* Fetch the host's keys and compare their fingerprints to g_fp. */
static int fp_matches(const char *ip) {
    char cmd[256], line[512];
    const char *hash = strncasecmp(g_fp, "MD5:", 4) == 0 ? "-E md5 " : "";
    snprintf(cmd, sizeof(cmd),
             "ssh-keyscan -T 3 -p %d %s 2>/dev/null | ssh-keygen %s-lf - 2>/dev/null",
             g_port, ip, hash);
    FILE *f = popen(cmd, "r");
    if (!f) return 0;
    int ok = 0;
    while (fgets(line, sizeof(line), f))
        if (strstr(line, g_fp)) { ok = 1; break; }   /* fingerprints are case-sensitive */
    pclose(f);
    return ok;
}

static void probe(uint32_t host) {
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)g_port);
    sa.sin_addr.s_addr = htonl(host);
#ifdef __APPLE__
    sa.sin_len = sizeof(sa);
#endif

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return;
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

    int rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    if (rc < 0 && errno != EINPROGRESS) { close(fd); return; }

    if (rc < 0) {
        if (wait_fd(fd, POLLOUT, g_timeout_ms) <= 0) { close(fd); return; }
        int err = 0; socklen_t len = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
            close(fd); return;          /* refused / unreachable */
        }
    }

    /* port is open: grab the SSH banner (servers speak first) */
    char banner[256] = "";
    if (wait_fd(fd, POLLIN, g_timeout_ms) > 0) {
        ssize_t n = recv(fd, banner, sizeof(banner) - 1, 0);
        if (n > 0) {
            banner[n] = '\0';
            banner[strcspn(banner, "\r\n")] = '\0';
        }
    }
    close(fd);

    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sa.sin_addr, ip, sizeof(ip));

    char name[NI_MAXHOST] = "";
    if (getnameinfo((struct sockaddr *)&sa, sizeof(sa), name, sizeof(name),
                    NULL, 0, NI_NAMEREQD) != 0)
        strcpy(name, "-");

    if (g_match && !strcasestr(ip, g_match) && !strcasestr(name, g_match) &&
        !strcasestr(banner, g_match))
        return;

    if (g_fp && !fp_matches(ip)) return;

    atomic_fetch_add(&g_found, 1);
    pthread_mutex_lock(&g_print);
    printf("%-15s  %-30s  %s%s\n", ip, name, banner[0] ? banner : "(no banner)",
           g_fp ? "  [fingerprint match]" : "");
    fflush(stdout);
    pthread_mutex_unlock(&g_print);
}

static void *worker(void *arg) {
    (void)arg;
    for (;;) {
        uint32_t i = atomic_fetch_add(&g_next, 1);
        if (i >= g_count) break;
        probe(g_first + i);
    }
    return NULL;
}

/* Parse "a.b.c.d/nn" into the host range. */
static int parse_cidr(const char *cidr) {
    char buf[64];
    strncpy(buf, cidr, sizeof(buf) - 1); buf[sizeof(buf) - 1] = '\0';
    char *slash = strchr(buf, '/');
    if (!slash) return -1;
    *slash = '\0';
    int prefix = atoi(slash + 1);
    struct in_addr a;
    if (inet_pton(AF_INET, buf, &a) != 1 || prefix < 8 || prefix > 32) return -1;

    uint32_t mask = prefix == 0 ? 0 : 0xFFFFFFFFu << (32 - prefix);
    uint32_t net = ntohl(a.s_addr) & mask;
    uint32_t bcast = net | ~mask;
    if (prefix >= 31) { g_first = net; g_count = bcast - net + 1; }
    else              { g_first = net + 1; g_count = bcast - net - 1; }
    return 0;
}

/* Find the first active, non-loopback IPv4 interface and derive its subnet. */
static int autodetect(char *out, size_t outlen) {
    struct ifaddrs *ifa, *p;
    if (getifaddrs(&ifa) < 0) return -1;
    int found = -1;
    for (p = ifa; p; p = p->ifa_next) {
        if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
        if (!(p->ifa_flags & IFF_UP) || (p->ifa_flags & IFF_LOOPBACK)) continue;
        if (!p->ifa_netmask) continue;
        struct in_addr ip = ((struct sockaddr_in *)p->ifa_addr)->sin_addr;
        struct in_addr mk = ((struct sockaddr_in *)p->ifa_netmask)->sin_addr;
        uint32_t m = ntohl(mk.s_addr);
        if ((ntohl(ip.s_addr) >> 16) == 0xA9FE) continue;   /* skip 169.254.x.x */
        int prefix = __builtin_popcount(m);
        char s[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip, s, sizeof(s));
        snprintf(out, outlen, "%s/%d", s, prefix);
        fprintf(stderr, "Auto-detected %s on interface %s\n", out, p->ifa_name);
        found = 0;
        if (strcmp(p->ifa_name, "en0") == 0) break;          /* prefer Wi-Fi/Ethernet on a Mac */
    }
    freeifaddrs(ifa);
    return found;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [-c CIDR] [-m match] [-f fingerprint] [-p port] [-t timeout_ms] [-j threads]\n"
        "  e.g. %s -m raspberry\n", prog, prog);
    exit(1);
}

int main(int argc, char **argv) {
    const char *cidr = NULL;
    int threads = 128, opt;
    char detected[64];

    while ((opt = getopt(argc, argv, "c:m:f:p:t:j:h")) != -1) {
        switch (opt) {
            case 'c': cidr = optarg; break;
            case 'm': g_match = optarg; break;
            case 'f': g_fp = optarg; break;
            case 'p': g_port = atoi(optarg); break;
            case 't': g_timeout_ms = atoi(optarg); break;
            case 'j': threads = atoi(optarg); break;
            default: usage(argv[0]);
        }
    }

    if (!cidr) {
        if (autodetect(detected, sizeof(detected)) != 0) {
            fprintf(stderr, "Could not detect network; pass one with -c 192.168.1.0/24\n");
            return 1;
        }
        cidr = detected;
    }
    if (parse_cidr(cidr) != 0) {
        fprintf(stderr, "Bad CIDR '%s' (prefix must be 8-32)\n", cidr);
        return 1;
    }
    if (threads < 1) threads = 1;
    if ((uint32_t)threads > g_count) threads = (int)g_count;

    fprintf(stderr, "Scanning %u hosts on port %d with %d threads...\n",
            g_count, g_port, threads);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    pthread_t *tid = malloc(sizeof(pthread_t) * threads);
    for (int i = 0; i < threads; i++) pthread_create(&tid[i], NULL, worker, NULL);
    for (int i = 0; i < threads; i++) pthread_join(tid[i], NULL);
    free(tid);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double secs = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    fprintf(stderr, "Done: %u host(s) found in %.2fs\n", atomic_load(&g_found), secs);
    return 0;
}
