/*
 * t11_heap_glibc234.c
 * glibc 2.34+ heap exploitation test target.
 *
 * Compile:
 *   gcc -o ../bins/t11_heap_glibc234 t11_heap_glibc234.c \
 *       -fno-stack-protector -no-pie -w
 *
 * Vulnerability:
 *   Three heap operations exposed via a simple protocol:
 *     'A' <size> <data>  → malloc(size) + copy data (possible overflow)
 *     'F' <idx>          → free chunk at index
 *     'R' <idx>          → read chunk at index (UAF after free)
 *     'W' <idx> <data>   → write to chunk at index (UAF write / double-free)
 *
 * Techniques targeted (glibc 2.34+, no __malloc_hook / __free_hook):
 *   - tcache key bypass (zero out key field → double-free)
 *   - House of Botcake (tcache + unsorted bin consolidation)
 *   - _IO_FILE FSOP (overwrite _IO_list_all or _IO_wfile_jumps)
 *   - House of Tangerine (aligned chunk abuse)
 *
 * Protocol (binary, newline-terminated):
 *   Client sends: <CMD> <SIZE>\n<DATA>
 *   Server responds: OK\n or ERR\n
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#define MAX_CHUNKS 16
#define MAX_SIZE   512

static void *chunks[MAX_CHUNKS] = {0};
static size_t sizes[MAX_CHUNKS] = {0};

/* Trigger: called when heap state is exploited */
void win(void) {
    write(1, "HEAP_PWNED\n", 11);
}

void handle(int fd) {
    char cmd;
    int  idx;
    size_t sz;
    char data[MAX_SIZE + 16];

    while (1) {
        /* Read command */
        if (read(fd, &cmd, 1) != 1) break;

        switch (cmd) {
        case 'A': {   /* Allocate */
            if (read(fd, &idx, sizeof(int)) != sizeof(int)) goto done;
            if (read(fd, &sz,  sizeof(size_t)) != sizeof(size_t)) goto done;
            if (idx < 0 || idx >= MAX_CHUNKS) { write(fd,"ERR\n",4); break; }
            chunks[idx] = malloc(sz);
            sizes[idx]  = sz;
            if (read(fd, data, sz + 32) < 0) goto done;   /* VULN: sz+32 > sz */
            memcpy(chunks[idx], data, sz + 32);            /* VULN: heap overflow */
            write(fd, "OK\n", 3);
            break;
        }
        case 'F': {   /* Free */
            if (read(fd, &idx, sizeof(int)) != sizeof(int)) goto done;
            if (idx < 0 || idx >= MAX_CHUNKS) { write(fd,"ERR\n",4); break; }
            free(chunks[idx]);   /* note: chunk ptr NOT zeroed → UAF */
            write(fd, "OK\n", 3);
            break;
        }
        case 'R': {   /* Read / leak */
            if (read(fd, &idx, sizeof(int)) != sizeof(int)) goto done;
            if (idx < 0 || idx >= MAX_CHUNKS || !chunks[idx]) {
                write(fd,"ERR\n",4); break;
            }
            write(fd, chunks[idx], sizes[idx]);   /* VULN: UAF read */
            break;
        }
        case 'W': {   /* Write */
            if (read(fd, &idx, sizeof(int)) != sizeof(int)) goto done;
            if (idx < 0 || idx >= MAX_CHUNKS || !chunks[idx]) {
                write(fd,"ERR\n",4); break;
            }
            if (read(fd, chunks[idx], MAX_SIZE) < 0) goto done;  /* VULN: UAF write */
            write(fd, "OK\n", 3);
            break;
        }
        case 'Q': goto done;
        default:  write(fd, "ERR\n", 4); break;
        }
    }
done:;
}

int main(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1, c;
    struct sockaddr_in a = {0};
    a.sin_family      = AF_INET;
    a.sin_port        = htons(14451);
    a.sin_addr.s_addr = INADDR_ANY;

    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    bind(s, (struct sockaddr *)&a, sizeof(a));
    listen(s, 1);

    while ((c = accept(s, NULL, NULL)) != -1) {
        handle(c);
        close(c);
    }
    close(s);
    return 0;
}
