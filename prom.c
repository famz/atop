
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <regex.h>
#include <glib.h>
#include "atop.h"
#include "ifprop.h"
#include "photoproc.h"
#include "photosyst.h"
#include "cgroups.h"
#include "showgeneric.h"
#include "showlinux.h"
#include "prom.h"


#define BUFFER_SIZE 4096

/* protected by prom_mutex */
static gchar* prom_metrics = NULL;

static pthread_mutex_t prom_mutex = PTHREAD_MUTEX_INITIALIZER;

static void prom_write(int fd, const char *buf, size_t len)
{
    int r;

    do {
        r = write(fd, buf, len);
        if (r > 0) {
            buf += r;
            len -= r;
        }
    } while (len > 0 && (r > 0 || (r == -1 && (errno == EINTR || errno == EAGAIN))));
}

static
void handle_client(int client_socket) {
    char buffer[BUFFER_SIZE];
    int bytes_read = read(client_socket, buffer, BUFFER_SIZE - 1);
    
    if (bytes_read < 0) {
        perror("read");
        close(client_socket);
        return;
    }

    buffer[bytes_read] = '\0';

    // Simple check to see if the request is for /metrics
    if (strncmp(buffer, "GET /metrics", 12) == 0) {
        const char *response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Connection: close\r\n"
            "\r\n";

        prom_write(client_socket, response, strlen(response));
        if (pthread_mutex_lock(&prom_mutex)) {
            abort();
        }
        if (prom_metrics) {
            prom_write(client_socket, prom_metrics, strlen(prom_metrics));
        }
        if (pthread_mutex_unlock(&prom_mutex)) {
            abort();
        }
    } else {
        const char *not_found_response =
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/plain\r\n"
            "Connection: close\r\n"
            "\r\n"
            "Not Found\n";

        prom_write(client_socket, not_found_response, strlen(not_found_response));
    }

    close(client_socket);
}

static
void *prom_server_thread(void *p) {
    int sock_fd = (uintptr_t)p;

    while (1) {
        int client_socket;
        struct sockaddr_in client_address;
        socklen_t client_addr_len = sizeof(client_address);
        client_socket = accept(sock_fd, (struct sockaddr *)&client_address, &client_addr_len);

        if (client_socket < 0) {
            perror("accept");
            continue;
        }

        handle_client(client_socket);
    }

    return NULL;
}

int prom_serve_start(const char *addr, int port)
{
    int sock_fd;
    pthread_t thread_id;
    struct sockaddr_in sock_addr;
    int optval = 1;

    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, addr, &sock_addr.sin_addr) <= 0) {
        perror("inet_pton");
        return 1;
    }

    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        perror("socket");
        return 1;
    }

    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("ERROR setting socket option SO_REUSEADDR");
        goto err;
    }

    if (bind(sock_fd, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) < 0) {
        perror("bind");
        goto err;
    }

    if (listen(sock_fd, 10) < 0) {
        perror("listen");
        goto err;
    }

    printf("HTTP server is listening on port %d\n", port);

    if (pthread_create(&thread_id, NULL, prom_server_thread, (void *)sock_fd) != 0) {
        perror("pthread_create");
        goto err;
    }
    return 0;
err:
    close(sock_fd);
    return 1;
}

char prom_sample(time_t curtime, int numsecs, struct devtstat *devtstat, struct sstat *sstat, struct cgchainer *devchain, int ncgroups, int npids, int nexit, unsigned int noverflow, char flag)
{
    char *p, *q;
    int i;
    const int buf_size = 1 << 20;

    p = g_malloc0(buf_size);
    q = p;
    for (i = 0; q - p < buf_size && i < sstat->cpu.nrcpu; i++) {

        struct percpu *cpu = &sstat->cpu.cpu[i];
        count_t alltics =
            cpu->stime +
            cpu->utime +
            cpu->ntime +
            cpu->itime +
            cpu->wtime +
            cpu->Itime +
            cpu->Stime +
            cpu->steal;
        int r = snprintf(q, buf_size - (q - p),
            "cpu_system{cpu=\"%d\"} %.1f\n"
            "cpu_user{cpu=\"%d\"} %.1f\n"
            "cpu_idle{cpu=\"%d\"} %.1f\n"
            "cpu_iowait{cpu=\"%d\"} %.1f\n"
            "cpu_softirq{cpu=\"%d\"} %.1f\n"
            "cpu_guest{cpu=\"%d\"} %.1f\n",
            i, (float)cpu->stime * 100 / (float)alltics,
            i, (float)cpu->utime * 100 / (float)alltics,
            i, (float)cpu->itime * 100 / (float)alltics,
            i, (float)cpu->wtime * 100 / (float)alltics,
            i, (float)cpu->Stime * 100 / (float)alltics,
            i, (float)cpu->guest * 100 / (float)alltics
            );
        q += r;
    }
    if (pthread_mutex_lock(&prom_mutex)) {
        abort();
    }
    g_free(prom_metrics);
    prom_metrics = p;
    if (pthread_mutex_unlock(&prom_mutex)) {
        abort();
    }
}
